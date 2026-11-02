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
import pickle
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consolidate as C  # noqa: E402
from consolidate import Model, addr10, is_data30, is_code10  # noqa: E402

from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MAPPING = ROOT / "docs/port/mapping.csv"
SHAPE_CANDIDATES = ROOT / "docs/port/missing_candidates.csv"
VT_MATCHES = C.TMP / "vt_matches.csv"
OUT = ROOT / "docs/port/xref_verified.csv"

CODE_AGREEMENT = 0.7   # anchored callees that must resolve to the mapped counterpart
CODE_MIN = 3
DATA_AGREEMENT = 0.6   # anchored globals that must resolve to the mapped counterpart
DATA_MIN = 3
CALLER_AGREEMENT = 0.5  # anchored callers that must call the candidate

# Sources that are this check's own output. A row whose evidence consists *only* of these is not
# usable as an anchor, otherwise the file would vouch for itself. A row that also carries an
# independent source (even a data row translated through the aligned function, `xref`) still
# counts, which keeps the anchor pool from shrinking on every run.
DERIVED_SOURCES = ("xref-ver", "delta-nb")


def anchor_table(model):
    """Confirmed rows that do not already rest on this check, split into lookup tables.

    A row confirmed by Version Tracking *and* by this check still counts as an anchor: the
    Version Tracking proposal is evidence that does not come from here. Dropping every row that
    mentions this check made the anchor pool shrink with each run and take earlier pairs with it.
    """
    fwd_c, fwd_d, rev_c, val_d = {}, {}, {}, set()
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if r["state"] != "confirmed" or not r["v30"]:
            continue
        if all(s in DERIVED_SOURCES for s in r["sources"].split("+")):
            continue
        v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
        if r["kind"] == "func":
            fwd_c[v10] = v30
            rev_c[v30] = v10
        elif r["kind"] == "data":
            fwd_d[v10] = v30
            val_d.add(v30)
    add_exact_pairs(model, fwd_c, rev_c)
    return fwd_c, fwd_d, rev_c, val_d


def add_exact_pairs(model, fwd_c, rev_c):
    """Add the function pairs Version Tracking reports as an exact match.

    The rows above are the inventory, 507 addresses the mod uses. Everything else in the image is
    an unknown, which leaves these two axes with 142 anchors to work with, and a function whose
    callees are not among them cannot be checked at all. Version Tracking's exact sets cover the
    whole image and state that the two bodies are the same code - the one kind of evidence the
    mapping accepts on its own (`ghidra-exact`) - so they are usable as anchors even though the mod
    never mentions those functions. A pair that contradicts a confirmed row is refused and
    reported, since one of the two is then wrong.
    """
    conflicts = 0
    for v10, v30 in C.ghidra_exact().items():
        if v10 not in model.f10 or v30 not in model.f30:
            continue
        if fwd_c.setdefault(v10, v30) != v30 or rev_c.setdefault(v30, v10) != v10:
            conflicts += 1
    print(f"exact-match anchors added, {conflicts} contradicting a confirmed pair")


def reference_sets_at(model, which, start, size):
    """(call targets, global targets) of a body of a known size."""
    code, data = set(), set()
    for _, _, insn in model.insns(which, start, max(size, 16)):
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


def reference_sets(model, which, start):
    """(call targets, global targets) of a described function body."""
    f = model.f10[start] if which == 10 else model.f30[start]
    return reference_sets_at(model, which, start, int(f["size"]))


def score_pair(model, tables, ref10, refsize, v30):
    """(callee hit, callee total, global hit, global total) for a candidate pair.

    The 1.0 side is given as a body rather than a function start, because a HOODLUM trampoline
    is only a jump and an address Ghidra left out of its function list has no size to read.
    """
    fwd_c, fwd_d, rev_c, val_d = tables
    if v30 not in model.f30:
        return None
    c10, d10 = reference_sets_at(model, 10, ref10, refsize)
    c30, d30 = reference_sets(model, 30, v30)
    want_c = {fwd_c[x] for x in c10 if x in fwd_c}
    have_c = {x for x in c30 if x in rev_c}
    want_d = {fwd_d[x] for x in d10 if x in fwd_d}
    have_d = {x for x in d30 if x in val_d}
    return (len(want_c & have_c), len(want_c), len(want_d & have_d), len(want_d))


def printable_at(model, which, va, n=40):
    """The NUL-terminated printable string at an address, or None.

    The length floor keeps single characters and stray literals out; a NUL inside the window is
    required, otherwise the bytes are a table or code, not text.
    """
    pe = model.p10 if which == 10 else model.p30
    b = pe.read(va, n)
    if not b:
        return None
    out = bytearray()
    for ch in b:
        if ch == 0:
            break
        if not (0x20 <= ch < 0x7F):
            return None
        out.append(ch)
    return bytes(out) if len(out) >= 6 else None


def string_sets(model, which, start, size):
    """Printable strings a body refers to, content -> the address holding them.

    A string literal is the one piece of a function that survives recompilation byte for byte, so
    agreement on it does not come from anything this tool has already mapped. That makes it the
    only signal available to a body that calls nothing mapped and touches no mapped global.
    """
    _, data = reference_sets_at(model, which, start, size)
    out = {}
    for a in sorted(data):
        s = printable_at(model, which, a)
        if s is not None and s not in out:
            out[s] = a
    return out


def strings_pass(s):
    """(hit, total) of the string literals both bodies name. Every one of them must match."""
    hit, total = s
    return total >= 1 and hit == total


def score(model, tables, f10, v30):
    """score_pair for a described 1.0 function; None when it is not one."""
    if f10 not in model.f10:
        return None
    return score_pair(model, tables, f10, int(model.f10[f10]["size"]), v30)


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


def shape_proposals():
    """Candidates and 1.0 bodies proposed by match_missing.py for functions no matcher saw.

    Returns ({v10: [v30, ...]}, {v10: body}) where the body is the real code the candidate was
    matched against: for a HOODLUM trampoline that is the target of its jump, which is where the
    instructions that matter live.
    """
    props, bodies = defaultdict(list), {}
    if not SHAPE_CANDIDATES.exists():
        return props, bodies
    for r in csv.DictReader(open(SHAPE_CANDIDATES, encoding="utf-8-sig")):
        v10 = int(r["v10"], 16)
        props[v10].append(int(r["v30"], 16))
        bodies[v10] = int(r["v10_body"], 16)
    return props, bodies


def call_graphs(model):
    """({function start: call targets}, {call target: callers}) for both builds.

    Walked from the described functions only, which is what makes the caller check meaningful:
    both sides are measured the same way. The walk covers every function in the image, so it is
    cached on disk.
    """
    cache = C.TMP / "call_graphs.pkl"
    if cache.exists():
        with open(cache, "rb") as fp:
            return pickle.load(fp)
    out = []
    for which in (10, 30):
        funcs = model.f10 if which == 10 else model.f30
        fwd, rev = {}, defaultdict(set)
        for va, f in funcs.items():
            targets = set()
            for _, _, insn in model.insns(which, va, int(f["size"])):
                if insn.mnemonic == "call" and insn.operands:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM:
                        targets.add(op.imm & 0xFFFFFFFF)
            fwd[va] = targets
            for t in targets:
                rev[t].add(va)
        out.append((fwd, dict(rev)))
    with open(cache, "wb") as fp:
        pickle.dump(out, fp, protocol=4)
    return out


def caller_score(tables, maps, f10, v30):
    """(hit, anchored, violations) for the callers of a candidate pair.

    The reference check asks whether the 3.0 body calls the mapped counterparts of what the
    1.0 body calls. This asks the same from the other end: every 1.0 function that calls the
    target and already has a confirmed counterpart must call the candidate in 3.0. A virtual
    method has no callers of its own, but the method that calls it still pins it down.
    """
    fwd_c, _, rev_c, _ = tables
    rev10, rev30 = maps[0][1], maps[1][1]
    want = {fwd_c[g] for g in rev10.get(f10, ()) if g in fwd_c}
    if not want:
        return (0, 0, 0)
    have = {g for g in rev30.get(v30, ()) if g in rev_c}
    return (len(want & have), len(want), len(want - have))


def callers_pass(s):
    hit, total, miss = s
    return total >= 2 and hit >= 2 and hit > miss and hit / total >= CALLER_AGREEMENT


def candidates(model, vt, shape, bodies):
    """[(row, entry, ref, refsize, v30, alts)] for every inventory row that names a function.

    Already confirmed rows are scored as well, so the emitted file is the full set of pairs the
    check supports and can be regenerated from scratch instead of only holding the newest ones.

    `entry` is the address the mod calls and the callers point at, `ref`/`refsize` the body whose
    references are compared. They differ for a HOODLUM trampoline: the entry is the jump, the body
    is where its target lives.
    """
    out = []
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if r["kind"] not in ("func", "code") and r["state"] != "missing":
            continue
        rowv = int(r["v10"], 16)
        f10 = int(r["function10"], 16) if r["function10"] else None
        v30 = int(r["function30"], 16) if r["function30"] else None
        if f10:
            entry = f10
            ref, refsize = f10, int(model.f10[f10]["size"])
            alts = [d for d in vt.get(f10, []) if d in model.f30]
            if rowv in bodies:
                # A trampoline, or a start Ghidra described with a stub body: the matcher keyed
                # it by the body it jumps to, so compare that body's references instead.
                ref = bodies[rowv]
                refsize = C.body_size(model, 10, ref)
                alts = list(dict.fromkeys(alts + shape.get(rowv, [])))
        else:
            if rowv not in shape:
                continue
            entry = rowv
            ref = bodies[rowv]
            refsize = C.body_size(model, 10, ref)
            alts = list(shape[rowv])
        if not v30:
            if not alts:
                continue
            v30 = alts[0]
        out.append((r, entry, ref, refsize, v30, alts))
    return out


def main():
    model = Model()
    tables = anchor_table(model)
    print(f"anchors: {len(tables[0])} functions, {len(tables[1])} globals")
    vt = vt_proposals()
    shape, bodies = shape_proposals()
    rows = candidates(model, vt, shape, bodies)
    print(f"candidates to score: {len(rows)}")

    C.SET_SEEDS = dict(tables[0])
    maps = call_graphs(model)
    good, ambiguous = [], []

    def string_score(names10, d):
        """(shared, total) string literals of the two bodies."""
        if not names10:
            return 0, 0
        names30 = string_sets(model, 30, d, int(model.f30[d]["size"]))
        return sum(1 for x in names10 if x in names30), len(names10)

    for r, entry, ref, refsize, v30, alts in rows:
        s = score_pair(model, tables, ref, refsize, v30)
        cs = caller_score(tables, maps, entry, v30)
        names10 = string_sets(model, 10, ref, refsize)
        ss = string_score(names10, v30)
        ok_ref = passes(s)
        ok_caller = callers_pass(cs)
        ok_str = strings_pass(ss)
        if not (ok_ref or ok_caller or ok_str):
            continue
        same = [d for d in alts
                if d != v30 and d in model.f30
                and (passes(score_pair(model, tables, ref, refsize, d))
                     or callers_pass(caller_score(tables, maps, entry, d))
                     or strings_pass(string_score(names10, d)))]
        if same:
            ambiguous.append((r, entry, v30, same))
            continue
        good.append((r, entry, v30, s, cs, ss, ok_ref, ok_caller, ok_str))

    print(f"verified: {len(good)}   rejected as ambiguous: {len(ambiguous)}")
    for r, entry, v30, same in ambiguous:
        print(f"  ambiguous {r['v10']} {entry:#x}: {v30:#x} ties with "
              f"{', '.join(hex(x) for x in same)}")

    # The evidence attaches to the function pair, so every row inside that function benefits
    # from it. Rows that verified the pair are listed for the audit trail.
    merged = {}
    for r, entry, v30, s, cs, ss, ok_ref, ok_caller, ok_str in good:
        e = merged.setdefault((entry, v30), {"rows": [], "s": s, "cs": cs, "ss": ss,
                                             "ref": ok_ref, "caller": ok_caller,
                                             "str": ok_str})
        e["rows"].append(int(r["v10"], 16))
        # keep the strongest agreement seen for the pair
        if (s[1], s[0], s[3], s[2]) > (e["s"][1], e["s"][0], e["s"][3], e["s"][2]):
            e["s"] = s
        if cs > e["cs"]:
            e["cs"] = cs
        if ss[1] > e["ss"][1]:
            e["ss"] = ss

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v30", "callees", "callees_hit", "globals", "globals_hit",
                    "callers", "callers_hit", "rows", "evidence"])
        for (entry, v30), e in sorted(merged.items()):
            s, cs, ss = e["s"], e["cs"], e["ss"]
            parts = []
            if e["ref"]:
                parts.append(f"anchored callees {s[0]}/{s[1]}, globals {s[2]}/{s[3]}")
            if e["caller"]:
                parts.append(f"anchored callers {cs[0]}/{cs[1]}")
            if e["str"]:
                parts.append(f"string literals {ss[0]}/{ss[1]}")
            w.writerow([f"0x{entry:08X}", f"0x{v30:08X}", s[1], s[0], s[3], s[2],
                        cs[1], cs[0],
                        " ".join(f"0x{x:08X}" for x in sorted(e["rows"])),
                        "; ".join(parts)])
    print(f"written {OUT}: {len(merged)} verified function pairs")


if __name__ == "__main__":
    main()