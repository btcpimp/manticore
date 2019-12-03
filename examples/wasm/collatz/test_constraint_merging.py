from manticore.core.smtlib.solver import Z3Solver
from manticore.core.smtlib.constraints import ConstraintSet

solver = Z3Solver.instance()

cs1 = ConstraintSet()
cs2 = ConstraintSet()

b1 = cs1.new_bitvec(32, name="cs1_bitvec")
b2 = cs2.new_bitvec(32, name="cs2_bitvec")

cs1.add(b1 > 10)
cs2.add(b2 < 10)

print(solver.can_be_true(cs1, b1 == b2))
print(solver.can_be_true(cs2, b1 == b2))

merged = ConstraintSet.merge(cs1, cs2)

print("==CS1==")
print(cs1.to_string())

print("==CS2==")
print(cs2.to_string())

print("==Merged==")
print(merged.to_string())

print(solver.can_be_true(merged, b1 == b2))
