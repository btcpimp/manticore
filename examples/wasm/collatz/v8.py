import argparse
import os

# from manticore.core.manticore import ManticoreBase
from manticore.native import Manticore as ManticoreBase
from manticore.native.cpu.abstractcpu import ConcretizeRegister
from manticore.native.cpu.cpufactory import CpuFactory
from manticore.native.memory import SMemory64, InvalidSymbolicMemoryAccess, InvalidMemoryAccess
from manticore.core.smtlib import ConstraintSet, issymbolic
from manticore.core.smtlib.expression import BitVecVariable
from manticore.native.state import State
from manticore.utils.log import ContextFilter
from manticore.platforms.linux import SLinux
from manticore.core.plugin import Plugin
import glob
import struct
import logging
import progressbar
from functools import reduce

logger = logging.getLogger("manticore.v8")
logger.addFilter(ContextFilter())

# As far as I know, there's no way to get access to the state object from SymbolicDereferenceMemory.read.
# This global is an ugly, but functional solution.
last_pc = None


def make_hex_string(data):
    if type(data) is int or type(data) is float:
        return hex(data)
    return str(data)


class SymbolicDereferenceSLinux(SLinux):
    """ Modifies the stock SLinux platform to use the custom memory model """

    def _mk_proc(self, arch):
        mem = SymbolicDereferenceMemory(self.constraints)
        return CpuFactory.get_cpu(mem, arch)


def make_initial_state(program_path):
    platform = SymbolicDereferenceSLinux(program_path, argv=[], envp=[], symbolic_files=None)
    return State(ConstraintSet(), platform)


class SymbolicDereferenceMemory(SMemory64):
    """
    On a high-level, modifies the SMemory implementation to return a new symbol in cases where we:
        * try to read from uninitialized memory
        * try to read from a symbolic memory address that can't be concretized

    Memory Read Workflow:

    If we're reading from a symbolic address:
        Try to concretize it:
            Read from the concrete addresses as normal
        If we can't concretize it:
            If we haven't seen it before:
                return a new symbol  #TODO: Say we write a 4-byte int then try to read the last byte. What happens then?
            If we *have* seen it before:
                return the symbol we returned last time

    If we're reading from a concrete address:
        If there's something there:
            return it
        If it hasn't been initialized:
            return a new symbol
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.symbol_store = {}
        self.write_backing_store = {}

        self.symbolic_read_locs = []
        self.uninit_read_locs = []

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __reduce__(self):
        _superclass, data = super().__reduce__()
        return (
            self.__class__,
            data,
            {
                "symbol_store": self.symbol_store,
                "write_backing_store": self.write_backing_store,
                "symbolic_read_locs": self.symbolic_read_locs,
                "uninit_read_locs": self.uninit_read_locs,
            },
        )

    def emplace(self, target, value):
        """ Put new symbols in the symbol store if there isn't already something there """
        if target not in self.symbol_store or (
            target in self.symbol_store and len(value) not in self.symbol_store[target]
        ):
            self.symbol_store.setdefault(target, {})[len(value)] = value

    def read(self, address, size, force=False):
        try:
            # Attempt to concretize and do normal concrete read
            r = super().read(address, size, force=force)
            # TODO: Is there a better way than this to check for uninitialized memory?
            if (
                address not in self.write_backing_store
                and reduce(lambda acc, x: acc and (x == b"\x00"), (k for k in r))
                and address in self.symbol_store
            ):  # will_read_mem doesn't fire for code apparently
                logger.warning(
                    f"Concretized read from uninitialized memory at {make_hex_string(address)} ({size})"
                )
                if last_pc is not None:
                    self.uninit_read_locs.append(last_pc)

                return self.symbol_store[address][
                    size
                ]  # We read from uninitialized memory (probably)

            return r
        except InvalidSymbolicMemoryAccess:
            # We couldn't concretize, so we'll return whatever's in the symbol store for this address
            logger.warning(
                f"Couldn't concretize address given by {make_hex_string(address)} ({size}) before reading"
            )
            if last_pc is not None:
                self.symbolic_read_locs.append(last_pc)

            return self.symbol_store[address][size]

    def write(self, address, value, force=False):
        self.write_backing_store.setdefault(address, {})[len(value)] = value
        super().write(address, value, force=force)


class V8AnalyzerPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.mem_map = {}
        self.init_read_locs = []

    def will_start_run_callback(self, state, *_args):
        logging.getLogger("manticore.v8").setLevel(logging.DEBUG)

        # Symbolicate all the registers, sans stack and base pointers, to model how we don't know anything about the state
        for reg in [
            "RAX",
            "RCX",
            "RDX",
            "RBX",
            "RSI",
            "RDI",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "R13",  # 'RSP', 'RBP',
            "R14",
            "R15",
            "YMM0",
            "YMM1",
            "YMM2",
            "YMM3",
            "YMM4",
            "YMM5",
            "YMM6",
            "YMM7",
            "YMM8",
            "YMM9",
            "YMM10",
            "YMM11",
            "YMM12",
            "YMM13",
            "YMM14",
            "YMM15",
            "CS",
            "DS",
            "ES",
            "SS",
            "FS",
            "GS",
        ]:
            setattr(state.cpu, reg, state.new_symbolic_value(state.cpu.regfile._table[reg].size))

        # Add in constant registers that we've observed in Binja-disassembled JIT instructions
        # state.cpu.R8 = 0x00000000000130a8
        # state.cpu.R9 = 0x0
        # state.cpu.R12 = 0xffffffffffffffff
        # state.cpu.RFLAGS = 0x0000000000000246
        # state.cpu.CS = 0x000000000000002b
        # state.cpu.FS = 0x0
        # state.cpu.GS = 0x0

        # Set up the stack in an arbitrary location
        stack_size = 0x21000
        state.cpu.RBP = state.cpu.STACK - stack_size // 2
        state.cpu.RSP = state.cpu.RBP - 8

        maps = set()
        self.read_mem_from_disk()
        print("Copying to Manticore Memory")
        for base in progressbar.progressbar(self.mem_map):
            if not state.mem.access_ok(base, "w"):
                new_base = (base >> 20) << 20
                if new_base not in maps:
                    state.cpu.memory.mmap(new_base, 2 ** 20, "rwx")
                    maps.add(new_base)

            try:
                state.mem.write(base, self.mem_map[base], force=True)
            except InvalidMemoryAccess:
                logger.error("Could not write heap object to memory!")
                raise

    def will_execute_instruction_callback(self, state, pc, insn):
        global last_pc
        last_pc = state.cpu.instruction.address
        # Concretize CMOV results so we get two forks instead of a symbolic memory deref down the line
        if "cmov" in insn.mnemonic and issymbolic(state.cpu.ZF):
            raise ConcretizeRegister(
                state.cpu, "ZF", "Concretizing ZF: " + str(state.cpu.ZF), policy="ALL"
            )

        # Print binja commands displaying the reads in any states that reached a return statement
        if insn.mnemonic == "ret":
            logger.debug(f"Reached return instruction at {hex(pc)}")
            self.dump_read_info(
                set(state.cpu.memory.uninit_read_locs), set(state.cpu.memory.symbolic_read_locs)
            )
            state.abandon()

        # Abandon call's rather than waiting for them to cause memory violations
        if insn.mnemonic in ["call"]:
            logger.debug(f"Abandoning state: {insn.mnemonic} occurred at {hex(pc)}")
            state.abandon()

    def will_read_memory_callback(self, state, where, size):
        # Hacky way of getting access to the state object from the memory. Results in more symbols than we need, but at
        # least they work
        state.cpu.memory.emplace(where, state.new_symbolic_buffer(size // 8))

    # Records successful reads from memory
    def did_read_memory_callback(self, state, where, value, size):
        if not issymbolic(value):
            self.init_read_locs.append(state.cpu.instruction.address)

    def dump_read_info(self, uninit_read_locs, symbolic_read_locs):
        gen_binja_commands(self.init_read_locs, "Green")
        gen_binja_commands(uninit_read_locs, "Red")
        gen_binja_commands(symbolic_read_locs, "Orange")

    def read_mem_from_disk(self):
        print("Reading memory from disk")
        for dmp in progressbar.progressbar(glob.glob("memory/*.dmp")):
            with open(dmp, "rb") as dumpfile:
                address = struct.unpack("Q", dumpfile.read(8))[0]
                size = struct.unpack("Q", dumpfile.read(8))[0]
                mem = bytes(dumpfile.read(size))
                description = bytes(dumpfile.read()).decode("utf-8")

                logger.log(1, "Read {}, ({} bytes)".format(description, size))

                self.mem_map[address] = mem


# Print out Binja commands to highlight the instructions that read memory
def gen_binja_commands(regs, colorname):
    print(
        f"for r in {set(regs)}:\n\tcurrent_function.set_auto_instr_highlight(r, HighlightStandardColor.{colorname}HighlightColor)\n"
    )


def disp_args(state):
    print("RIP:", hex(state.cpu.instruction.address))
    print("\tRBP:", hex(state.cpu.RBP) if type(state.cpu.RBP) is int else state.cpu.RBP)
    print("\tRSP:", hex(state.cpu.RSP) if type(state.cpu.RSP) is int else state.cpu.RSP)
    print("\tRAX (ARG0):", hex(state.cpu.RAX) if type(state.cpu.RAX) is int else state.cpu.RAX)
    print("\tRBX (ARG1):", hex(state.cpu.RBX) if type(state.cpu.RBX) is int else state.cpu.RBX)


def do_analysis(filename, verbosity):
    m = ManticoreBase(make_initial_state(filename))  # , pure_symbolic=True)
    m.verbosity(verbosity)

    # Specific to add.js
    # m.add_hook(0x1fafded9852a, disp_args)
    # m.add_hook(0x1fafded98536, disp_args)

    m.register_plugin(V8AnalyzerPlugin())
    m.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a binary with a fully symbolic initial register state"
    )
    parser.add_argument("file", help="ELF Binary to run")
    parser.add_argument("--verbose", "-v", action="count", help="Output verbosity")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        logger.debug(f"Error: Invalid file path: {args.file}")

    do_analysis(args.file, 0 if not type(args.verbose) is int else args.verbose)
