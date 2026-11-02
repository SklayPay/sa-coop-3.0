"""False-positive control for the anchored-caller check in verify_xref.py.

Random 1.0/3.0 function pairs, both of which already have at least two mapped callers, are scored
the same way a proposed pair is. The rate at which they pass estimates how much of the check's
agreement is coincidence.
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
    print(f"pool: {len(pool10)} 1.0 functions, {len(pool30)} 3.0 functions with >= 2 mapped callers")

    random.seed(20261102)
    trials = 5000
    for label, score in (("callers", VX.caller_score), ("references", None)):
        hits = 0
        for _ in range(trials):
            f = random.choice(pool10)
            v = random.choice(pool30)
            if score is not None:
                ok = VX.callers_pass(score(tables, maps, f, v))
            else:
                size = int(model.f10[f]["size"])
                ok = VX.passes(VX.score_pair(model, tables, f, size, v))
            hits += bool(ok)
        print(f"{label}: {hits}/{trials} random pairs pass ({hits / trials:.4%})")


if __name__ == "__main__":
    main()
