"""Sanity check the confirmed pairs by body size.

Recompiling the same function changes its size - the compilers differ, helpers get inlined or
pulled out - but not by an order of magnitude. A pair whose two bodies differ wildly is worth a
look: either the compiler really did restructure the code, or the pair is wrong, which is the
failure the whole pipeline exists to avoid.

This is not a confirmation signal: two different functions can happen to be the same size. It is
a check that a confirmed pair has no obvious reason to be doubted, and it runs over every
confirmed row at once, which the reference checks (they look at candidates one at a time) do not.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/audit_sizes.py
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consolidate as C  # noqa: E402
from consolidate import Model  # noqa: E402

LO, HI = 0.4, 2.5


def size10(model, r):
    """Size of the 1.0 body, and whether it is comparable at all.

    Ghidra's size is used when it described the function, except for the entries it calls thunks:
    this 1.0 release wraps some function entries in a SecuROM stub, so Ghidra sees a six byte
    `nop; jmp` and gives it size 6 while the real body sits right after it. Comparing that with
    the 3.0 body says nothing.
    """
    f10 = int(r["function10"], 16) if r["function10"] else int(r["v10"], 16)
    body, chain = C.body_of(model, f10)
    if chain:
        return C.body_size(model, 10, body), True
    entry = model.f10.get(f10)
    if entry and str(entry["name"]).startswith("thunk_"):
        return 0, False
    if entry:
        return int(entry["size"]), True
    return C.body_size(model, 10, body), True


def size30(model, va):
    """Size of a 3.0 body: Ghidra's size when it described the function, else the disassembler."""
    if va in model.f30:
        return int(model.f30[va]["size"])
    return C.body_size(model, 30, va)


def main():
    model = Model()
    rows = [r for r in csv.DictReader(open(C.ROOT / "docs/port/mapping.csv", encoding="utf-8-sig"))
            if r["state"] == "confirmed" and r["kind"] == "func" and r["v30"]]
    print(f"confirmed function rows: {len(rows)}")

    out = []
    skipped_thunk = skipped_small = 0
    for r in rows:
        v30 = int(r["function30"] or r["v30"], 16)
        s10, comparable = size10(model, r)
        s30 = size30(model, v30)
        if not comparable:
            skipped_thunk += 1
            continue
        if s10 <= 0 or s30 <= 0:
            skipped_small += 1
            continue
        out.append((s30 / s10, r["v10"], r["v30"], s10, s30, r["sources"]))
    out.sort()

    print(f"\nratio {HI}x - 1.0x:")
    for ratio, v10, v30, s10, s30, src in out[:6]:
        print(f"  {v10} -> {v30}  {s10:5d} -> {s30:5d}  ratio {ratio:5.2f}  {src}")
    print(f"ratio 1.0x - {LO}x:")
    for ratio, v10, v30, s10, s30, src in out[-6:]:
        print(f"  {v10} -> {v30}  {s10:5d} -> {s30:5d}  ratio {ratio:5.2f}  {src}")

    # A small function can legitimately change size by a large ratio without meaning anything, so
    # the flag also needs the difference to be worth a look.
    bad = [x for x in out if not (LO <= x[0] <= HI) and abs(x[4] - x[3]) > 48]
    print(f"\ncompared {len(out)}, skipped {skipped_thunk} wrapped entries and "
          f"{skipped_small} without a size")
    print(f"within {LO}x-{HI}x (or too small to matter): {len(out) - len(bad)}/{len(out)}")
    if bad:
        print("outside:")
        for ratio, v10, v30, s10, s30, src in bad:
            print(f"  {v10} -> {v30}  {s10} -> {s30}  ratio {ratio:.2f}  {src}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
