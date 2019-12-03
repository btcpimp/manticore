from manticore.wasm import ManticoreWASM
from manticore.core.smtlib.visitors import (
    pretty_print,
    get_depth,
    arithmetic_simplify,
    constant_folder,
    count_nodes,
)
from manticore.core.plugin import Plugin
from manticore.native import Manticore
from manticore.utils.log import set_verbosity
from manticore.core.smtlib.solver import Z3Solver
from manticore.core.smtlib.constraints import ConstraintSet
from manticore.core.smtlib import Operators

solver = Z3Solver.instance()


class CaptureForkConstraints(Plugin):
    def will_fork_state_callback(self, state, fork_on, *args):
        # print(pretty_print(state.stack.peek(), depth=min(x, 4)))
        with self.locked_context("fork_constraints", list) as ctx:
            val = ctx.append(state.stack.peek())
            # ctx.append(state.locals[1])


def getchar(constraints, _addr):
    res = constraints.new_bitvec(32, "getchar_res")
    constraints.add(res == (2 ** 3))
    return [res]


set_verbosity(2)
m = ManticoreWASM("collatz.wasm", env={"getchar": getchar})
wasm_plugin = CaptureForkConstraints()
m.register_plugin(wasm_plugin)
m.invoke("main")
m.run()

wasm_fork_expressions = wasm_plugin.context.get("fork_constraints")
wasm_final = arithmetic_simplify(constant_folder(wasm_fork_expressions[-1]))
# depth = get_depth(wasm_final)
# count = count_nodes(wasm_final)
# print(pretty_print(wasm_final, depth=min(24, depth)))
# print()
# print(depth, "::", count)
wasm_constraints = next(m.all_states)._constraints


class NativeCaptureForkConstraints(Plugin):
    def will_fork_state_callback(self, state, fork_on, *args):
        with self.locked_context("fork_constraints", list) as ctx:
            ctx.append(fork_on)
            # ctx.append(state.cpu.RBX)


m2 = Manticore("collatz.elf")
native_plugin = NativeCaptureForkConstraints()
m2.register_plugin(native_plugin)


@m2.hook(0x00010A0)
def hook(state):
    sym = state.new_symbolic_value(32)
    rsi = state.new_symbolic_value(64)
    state.constrain(sym == (2 ** 3))
    state.cpu.EAX = sym
    state.cpu.RSI = rsi


@m2.hook(0x00010C0)
def hook2(state):
    state.cpu.PC = 0x00010D0


# set_verbosity(3)
m2.run()


native_fork_expressions = native_plugin.context.get("fork_constraints")
native_final = arithmetic_simplify(constant_folder(native_fork_expressions[-1]))
# depth = get_depth(native_final)
# count = count_nodes(native_final)
# print(pretty_print(native_final, depth=min(24, depth)))
# print()
# print(depth, "::", count)
native_constraints = next(m2.all_states)._constraints

merged = ConstraintSet.merge(wasm_constraints, native_constraints)

native_final = native_final == 4331
wasm_final = wasm_final == 0
print(count_nodes(native_final), count_nodes(wasm_final))
print("Native:", solver.get_all_values(merged, native_final))
print("WASM:", solver.get_all_values(merged, wasm_final))
eq = wasm_final == native_final
print("Can be equal:", solver.can_be_true(merged, eq))
print("Must be equal:", solver.must_be_true(merged, eq))
