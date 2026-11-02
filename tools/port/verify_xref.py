"""Independent cross-verification of candidate 1.0 -> 3.0 function pairs.

A candidate pair is scored by the references its two functions make: every callee and every
global that the 1.0 function touches and that is already confirmed in `mapping.csv` must appear
as the mapped counterpart in the 3.0 function. The two builds come from different compilers, so
agreement on the *referenced identities* cannot come from instruction layout, register
allocation or stack offsets - it is evidence that the two bodies really are the same function.

The check is deliberately conservative:

  * it needs at least three anchored callees (agreement >= 0.7) or three anchored globals
    (agreement >= 0.6), otherwise it says nothing;
  * it refuses a pair when another Version Tracking proposal for the same 1.0 function scores
    just as well, because the signal cannot tell the two apart.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/verify_xref.py
"""
import bisect
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consolidate as C  # noqa: E402
from consolidate import Model, addr10, is_data30, is_code10  # noqa: E402

from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MAPPING = ROOT / "docs/port/mapping.csv"
VT_MATCHES = C.TMP / "vt_matches.csv"
OUT = ROOT / "docs/port/xref_verified.csv"

CODE_AGREEMENT = 0.7   # anchored callees that must resolve to the mapped counterpart
CODE_MIN = 3
DATA_AGREEMENT = 0.6   # anchored globals that must resolve to the mapped counterpart
DATA_MIN = 3


def anchor_table(model):
    """Confirmed rows that do not already rest on this check, split into lookup tables.

    Rows confirmed through `xref_verified.csv` (or the delta-neighbourhood pass) are left out:
    using them as anchors would let the file vouch for itself and the check would drift.
    """
    fwd_c, fwd_d, rev_c, val_d = {}, {}, {}, set()
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if r["state"] != "confirmed" or not r["v30"]:
            continue
        if "xref-ver" in r["sources"] or "delta-nb" in r["sources"]:
            continue
        v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
        if r["kind"] == "func":
            fwd_c[v10] = v30
            rev_c[v30] = v10
        elif r["kind"] == "data":
            fwd_d[v10] = v30
            val_d.add(v30)
    return fwd_c, fwd_d, rev_c, val_d


def reference_sets(model, which, start):
    """(call targets, global targets) of a function body."""
    f = model.f10[start] if which == 10 else model.f30[start]
    code, data = set(), set()
    for _, _, insn in model.insns(which, start, int(f["size"])):
        for op in insn.operands:
            if op.type == X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if insn.mnemonic in ("call", "jmp"):
                    if 0x401000 <= v < 0xD3C000:
                        code.add(v)
                elif C.is_data10(v) if which == 10 else is_data30(v):
                    data.add(v)
            elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp:
                v = op.mem.disp & 0xFFFFFFFF
                if C.is_data10(v) if which == 10 else is_data30(v):
                    data.add(v)
    return code, data


def score(model, tables, f10, v30):
    """(callee hit, callee total, global hit, global total) for a candidate pair."""
    fwd_c, fwd_d, rev_c, val_d = tables
    if f10 not in model.f10 or v30 not in model.f30:
        return None
    c10, d10 = reference_sets(model, 10, f10)
    c30, d30 = reference_sets(model, 30, v30)
    want_c = {fwd_c[x] for x in c10 if x in fwd_c}
    have_c = {x for x in c30 if x in rev_c}
    want_d = {fwd_d[x] for x in d10 if x in fwd_d}
    have_d = {x for x in d30 if x in val_d}
    return (len(want_c & have_c), len(want_c), len(want_d & have_d), len(want_d))


def passes(s):
    """True when the pair carries enough anchored agreement to be evidence."""
    if s is None:
        return False
    hc, nc, hd, nd = s
    return (nc >= CODE_MIN and hc / nc >= CODE_AGREEMENT) or \
           (nd >= DATA_MIN and hd / nd >= DATA_AGREEMENT)


def vt_proposals():
    sets = defaultdict(list)
    if not VT_MATCHES.exists():
        return sets
    for r in csv.DictReader(open(VT_MATCHES, encoding="utf-8-sig")):
        if r["type"] == "Function":
            sets[int(r["src"], 16)].append(int(r["dst"], 16))
    return sets


def candidates(model, proposals):
    """[(row, f10, v30)] for every inventory row that names a function, whatever its state.

    Already confirmed rows are scored as well, so the emitted file is the full set of pairs the
    check supports and can be regenerated from scratch instead of only holding the newest ones.
    """
    out = []
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if r["kind"] not in ("func", "code"):
            continue
        f10 = int(r["function10"], 16) if r["function10"] else None
        v30 = int(r["function30"], 16) if r["function30"] else None
        if not f10:
            continue
        if not v30:
            # A missing row has no candidate yet; Version Tracking may still offer one.
            alts = [d for d in proposals.get(f10, []) if d in model.f30]
            if not alts:
                continue
            v30 = alts[0]
        out.append((r, f10, v30))
    return out


def main():
    model = Model()
    tables = anchor_table(model)
    print(f"anchors: {len(tables[0])} functions, {len(tables[1])} globals")
    proposals = vt_proposals()
    rows = candidates(model, proposals)
    print(f"candidates to score: {len(rows)}")

    C.SET_SEEDS = dict(tables[0])
    good, ambiguous = [], []
    for r, f10, v30 in rows:
        s = score(model, tables, f10, v30)
        if not passes(s):
            continue
        alts = [d for d in proposals.get(f10, []) if d != v30 and d in model.f30]
        same = [d for d in alts if passes(score(model, tables, f10, d))]
        if same:
            ambiguous.append((r, f10, v30, same))
            continue
        good.append((r, f10, v30, s))

    print(f"verified: {len(good)}   rejected as ambiguous: {len(ambiguous)}")
    for r, f10, v30, same in ambiguous:
        print(f"  ambiguous {r['v10']} {f10:#x}: {v30:#x} ties with "
              f"{', '.join(hex(x) for x in same)}")

    # The evidence attaches to the function pair, so every row inside that function benefits
    # from it. Rows that verified the pair are listed for the audit trail.
    merged = {}
    for r, f10, v30, s in good:
        entry = merged.setdefault((f10, v30), {"rows": [], "s": s})
        entry["rows"].append(int(r["v10"], 16))
        # keep the strongest agreement seen for the pair
        if (s[1], s[0], s[3], s[2]) > (entry["s"][1], entry["s"][0], entry["s"][3], entry["s"][2]):
            entry["s"] = s

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v30", "callees", "callees_hit", "globals", "globals_hit",
                    "rows", "evidence"])
        for (f10, v30), e in sorted(merged.items()):
            s = e["s"]
            ev = f"anchored callees {s[0]}/{s[1]}, globals {s[2]}/{s[3]}"
            w.writerow([f"0x{f10:08X}", f"0x{v30:08X}", s[1], s[0], s[3], s[2],
                        " ".join(f"0x{x:08X}" for x in sorted(e["rows"])), ev])
    print(f"written {OUT}: {len(merged)} verified function pairs")


if __name__ == "__main__":
    main()