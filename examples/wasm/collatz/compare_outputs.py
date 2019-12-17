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

from networkx.drawing.nx_agraph import write_dot
from manticore.utils.graphing import graph_expression_tree

from manticore.utils.config import get_group

core = get_group("core")
core.mprocessing = core.mprocessing.single

solver = Z3Solver.instance()

wasm_constraint = None
native_constraint = None


class CaptureForkConstraints(Plugin):
    def will_fork_state_callback(self, state, fork_on, *args):
        # print(pretty_print(state.stack.peek(), depth=min(x, 4)))
        with self.locked_context("fork_constraints", list) as ctx:
            val = ctx.append(state.stack.peek())
            # ctx.append(state.locals[1])


def getchar(constraints, _addr):
    global wasm_constraint
    wasm_constraint = constraints.new_bitvec(32, "getchar_res")
    # res = constraints.new_bitvec(32, "getchar_res")
    constraints.add(wasm_constraint == (2 ** 3))
    return [wasm_constraint]


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
wasm_constraint_set = next(m.all_states)._constraints


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
    global native_constraint
    native_constraint = state.new_symbolic_value(32)
    rsi = state.new_symbolic_value(64)
    state.constrain(native_constraint == (2 ** 3))
    state.cpu.EAX = native_constraint
    state.cpu.RSI = rsi


@m2.hook(0x00010C0)
def hook2(state):
    state.cpu.PC = 0x00010D0


# set_verbosity(3)
m2.run()


native_fork_expressions = native_plugin.context.get("fork_constraints")
native_final = arithmetic_simplify(constant_folder(native_fork_expressions[-1]))
native_constraint_set = next(m2.all_states)._constraints


# Merge constraints
merged = ConstraintSet.merge(wasm_constraint_set, native_constraint_set)
print(wasm_constraint, native_constraint)
merged.add(wasm_constraint == native_constraint)

# Set constraints equal to the same code path
native_final = native_final == 0x10EB
wasm_final = wasm_final == 0

# Evaluate equivalence
eq = wasm_final == native_final
print("Can be equal:", solver.can_be_true(merged, eq))
print("Must be equal:", solver.must_be_true(merged, eq))

# Generate graphs
native_graph = graph_expression_tree(native_final, native_constraint_set)
wasm_graph = graph_expression_tree(wasm_final, wasm_constraint_set)
write_dot(native_graph, "native.dot")
write_dot(wasm_graph, "wasm.dot")
