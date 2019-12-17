import networkx as nx
from ..core.smtlib import Visitor, Expression, ConstraintSet
import typing

from ..core.smtlib.solver import Z3Solver

solver = Z3Solver.instance()


class Grapher(Visitor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.G = nx.DiGraph()
        self.cs = None
        self._last_node = None

    def set_constraints(self, cs):
        self.cs = cs

    def make_node(self, expr: Expression):
        return str(expr)

    def visit_Expression(self, expression):
        stringified = self.make_node(expression)
        self.G.add_node(stringified)
        return stringified

    def visit_Operation(self, expression, *operands):
        parent = self.visit_Expression(expression)
        for op in operands:
            self.G.add_edge(parent, op)
        return parent

    def visit_BitVecConstant(self, bvc):
        stringified = self.make_node(bvc)

        pos_val = solver.get_all_values(self.cs, bvc, 3)
        if len(pos_val) == 1:
            stringified = f"{stringified} ({hex(pos_val[0])})"
            self.G.add_node(stringified, label=hex(pos_val[0]))
        else:
            self.G.add_node(stringified)
        return stringified

    def visit_BitVecVariable(self, expression):
        stringified = self.make_node(expression)
        self.G.add_node(stringified, color="green")
        return stringified


def graph_expression_tree(
    exp: Expression, constraints: typing.Optional[ConstraintSet] = None
) -> nx.DiGraph:
    visitor = Grapher()
    if constraints is not None:
        visitor.set_constraints(constraints)
    visitor.visit(exp)
    return visitor.G.reverse()
