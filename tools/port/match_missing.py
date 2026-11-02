"""Match the 1.0 addresses no other matcher covered.

Two families dominate the leftovers:

  * 1.0 function starts that Ghidra did not describe as functions (it either left them out of
    its function list or merged them into the previous body) - many of them are virtual methods
    that the game only ever reaches through a vtable, so no caller leads to them;
  * HOODLUM trampolines: a five byte `jmp` to the real body in the section the crack appended,
    which the inventory then calls through.

Both are invisible to match_functions.py, which walks Ghidra's function list and needs the
target to sit inside a described function. This tool takes the real body, ranks 3.0 functions by
normalised instruction similarity, and then lets verify_xref's anchored-reference check decide.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/match_missing.py
"""
import bisect
import csv
import difflib
import json
import pickle
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, addr10, is_code10, body_of, body_end, body_size, \
    plausible_entry  # noqa: E402
import match_functions as MF  # noqa: E402
import verify_xref as VX  # noqa: E402

from capstone import CS_ARCH_X86, CS_MODE_32, Cs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MAPPING = ROOT / "docs/port/mapping.csv"
OUT = ROOT / "docs/port/missing_candidates.csv"
INDEX_CACHE = VX.C.TMP / "missing_index30.pkl"


def body_tokens(model, which, start, size=None):
    """Normalised instruction tokens of a body, with the size Ghidra gave when it has it."""
    if size is None:
        size = body_size(model, which, start)
    return [t for _, t, _ in model.insns(which, start, max(size, 16))]


def build_index(model):
    """Tokens of every 3.0 function plus a three-gram index, cached because the scan is slow."""
    if INDEX_CACHE.exists():
        with open(INDEX_CACHE, "rb") as fp:
            data = pickle.load(fp)
        if isinstance(data, tuple) and len(data) == 2:
            return data
    out = {}
    for va in model.starts30:
        t = body_tokens(model, 30, va)
        if len(t) >= 4:
            out[va] = t
    grams = defaultdict(set)
    for va, t in out.items():
        for j in range(min(32, len(t) - 2)):
            grams[tuple(t[j:j + 3])].add(va)
    grams = dict(grams)
    with open(INDEX_CACHE, "wb") as fp:
        pickle.dump((out, grams), fp, protocol=4)
    return out, grams


def rank(target_tokens, index, grams, top=12):
    """Rank 3.0 functions by token similarity, with a cheap three-gram prefilter."""
    cands = set()
    for j in range(min(32, len(target_tokens) - 2)):
        cands |= grams.get(tuple(target_tokens[j:j + 3]), set())
    out = []
    for va in cands:
        t = index[va]
        sm = difflib.SequenceMatcher(None, target_tokens[:96], t[:96], autojunk=False)
        ratio = sm.ratio()
        lr = min(len(target_tokens), len(t)) / max(len(target_tokens), len(t))
        out.append((0.85 * ratio + 0.15 * lr, ratio, lr, va))
    out.sort(reverse=True)
    return out[:top]


def main():
    model = Model()
    tables = VX.anchor_table(model)
    print(f"anchors: {len(tables[0])} functions, {len(tables[1])} globals")

    rows = [r for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig"))
            if r["state"] == "missing"]
    print(f"missing rows: {len(rows)}")

    index, grams = build_index(model)
    print(f"3.0 functions indexed: {len(index)}")

    results = []
    for r in rows:
        v10 = int(r["v10"], 16)
        if not is_code10(v10):
            continue
        if r["function10"] and int(r["function10"], 16) != v10:
            # owned by a described function: this is a site inside it, handled elsewhere
            continue
        if not plausible_entry(model, v10):
            # a redirect site or a patch byte, not the start of a function
            continue
        body, chain = body_of(model, v10)
        tokens = body_tokens(model, 10, body)
        if len(tokens) < 4:
            print(f"{r['v10']} body 0x{body:08X}: only {len(tokens)} instructions")
            continue
        ranked = rank(tokens, index, grams)
        if not ranked:
            print(f"{r['v10']} body 0x{body:08X}: no candidate")
            continue
        scored = []
        size10 = body_size(model, 10, body)
        for score, ratio, lr, va in ranked[:6]:
            s = VX.score_pair(model, tables, body, size10, va)
            scored.append((score, ratio, lr, va, s, VX.passes(s)))
        best = scored[0]
        verified = [x for x in scored if x[5]]
        print(f"\n{r['v10']} body 0x{body:08X} ({len(tokens)} insns, "
              f"{'trampoline' if chain else 'direct'})")
        for score, ratio, lr, va, s, ok in scored:
            anch = f"callees {s[0]}/{s[1]} globals {s[2]}/{s[3]}" if s else "-"
            print(f"    -> 0x{va:08X} score={score:.3f} ratio={ratio:.3f} lr={lr:.2f} "
                  f"{'VERIFIED' if ok else '        '} {anch}")
        results.append((r, body, chain, scored, verified))

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v10_body", "trampoline", "v30", "score", "ratio", "lenratio",
                    "callees", "callees_hit", "globals", "globals_hit", "verified"])
        for r, body, chain, scored, verified in results:
            for score, ratio, lr, va, s, ok in scored:
                w.writerow([r["v10"], f"0x{body:08X}", "yes" if chain else "no",
                            f"0x{va:08X}", f"{score:.4f}", f"{ratio:.4f}", f"{lr:.4f}",
                            s[1] if s else "", s[0] if s else "",
                            s[3] if s else "", s[2] if s else "",
                            "yes" if ok else "no"])
    print(f"\nwritten {OUT}")
    print(f"targets: {len(results)}, with a verified candidate: "
          f"{sum(1 for _, _, _, _, v in results if v)}")

if __name__ == "__main__":
    main()