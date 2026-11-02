"""False-positive control for the three checks verify_xref.py applies to a proposed pair.

Random 1.0/3.0 function pairs are scored the same way a proposed pair is. The rate at which they
pass estimates how much of each check's agreement is coincidence.

The caller check is measured on the pool of functions that have at least two mapped callers,
because that is the population it can say anything about. The string check is measured on pairs
whose 1.0 side actually names a string, since a body without one can never pass.
"""
import random
import sys

sys.path.insert(0, r"C:\Users\Pc\Desktop\wibeProjects\sa-coop\tools\port")
from consolidate import Model  # noqa: E402
import verify_xref as VX  # noqa: E402


def main():
    model = Model()
    tables = VX.anchor_table(model)
    maps = VX.call_graphs(model)
    fwd_c, rev_c = tables[0], tables[2]
    rev10, rev30 = maps[0][1], maps[1][1]

    pool10 = [f for f in model.f10 if len([g for g in rev10.get(f, ()) if g in fwd_c]) >= 2]
    pool30 = [v for v in model.f30 if len([g for g in rev30.get(v, ()) if g in rev_c]) >= 2]
    print(f"caller pool: {len(pool10)} 1.0 / {len(pool30)} 3.0 functions with >= 2 mapped callers")

    random.seed(20261102)

    trials = 5000
    hits = sum(bool(VX.callers_pass(VX.caller_score(tables, maps, random.choice(pool10),
                                                    random.choice(pool30))))
               for _ in range(trials))
    print(f"callers: {hits}/{trials} random pairs pass ({hits / trials:.4%})")

    every10, every30 = sorted(model.f10), sorted(model.f30)
    trials = 3000
    hits_ref = hits_str = str_trials = 0
    for _ in range(trials):
        f = random.choice(every10)
        v = random.choice(every30)
        size = int(model.f10[f]["size"])
        hits_ref += bool(VX.passes(VX.score_pair(model, tables, f, size, v)))
        names = VX.string_sets(model, 10, f, size)
        if not names:
            continue
        str_trials += 1
        other = VX.string_sets(model, 30, v, int(model.f30[v]["size"]))
        hits_str += bool(VX.strings_pass((sum(1 for x in names if x in other), len(names))))
    print(f"references: {hits_ref}/{trials} random pairs pass ({hits_ref / trials:.4%})")
    print(f"strings: {hits_str}/{str_trials} pairs with a named string "
          f"({hits_str / max(str_trials, 1):.4%})")


if __name__ == "__main__":
    main()
