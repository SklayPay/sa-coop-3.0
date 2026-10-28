"""Build the 1.0 -> 3.0 address table from several independent matchers.

Inputs (all produced by the other tools in this folder):
  function_matches.csv   instruction-sequence matcher (tools/port/match_functions.py)
  feature_matches.csv    string/import matcher        (tools/port/match_features.py)
  vt_matches.csv         Ghidra Version Tracking     (tools/port/VtExport.java)
  silentpatch_triples.csv public SilentPatch addresses

Outputs:
  docs/port/mapping.csv  every inventory address, its 3.0 address and the evidence
  docs/port/mapping_high.csv the subset that is safe to add to Addresses.cpp without review

Conflict handling is deliberate: when two tools propose different 3.0 addresses for the same 1.0
address, the row is marked "conflict" and is not used. A wrong address is worse than a missing one.
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
INVENTORY = ROOT / "docs/port/addresses.csv"
TMP = Path(r"C:\Users\Pc\AppData\Local\Temp")
OUT = ROOT / "docs/port/mapping.csv"
OUT_HIGH = ROOT / "docs/port/mapping_high.csv"

KNOWN = {
    0x4D3990: 0x4DE2F0,
    0x563280: 0x57D370,
    0x5A82C0: 0x5BDFE0,
    0x601110: 0x620E70,
    0x6190A0: 0x63AB90,
    0x734A40: 0x7671B0,
    0x743C60: 0x77D940,
    0x7F0990: 0x82A950,
}


def load_function_csv(path, addr_field, score_field=None, min_score=0.0, extra=None):
    out = {}
    if not Path(path).exists():
        return out
    for r in csv.DictReader(open(path, encoding="utf-8-sig")):
        v = int(r[addr_field], 16)
        if score_field and float(r[score_field]) < min_score:
            continue
        out[v] = r
    return out


def main():
    inv = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    inv_by = {int(r["Address"], 16): r for r in inv}

    # --- evidence sources -------------------------------------------------
    exact = load_function_csv(TMP / "function_matches.csv", "v10", "score", 0.90)
    exact = {v: r for v, r in exact.items() if r["v30"]}

    features = load_function_csv(TMP / "feature_matches.csv", "v10", "sim", 0.8)
    features = {v: r for v, r in features.items() if r["v30"]}

    vt = defaultdict(list)
    for r in csv.DictReader(open(TMP / "vt_matches.csv", encoding="utf-8-sig")):
        if r["type"] != "Function":
            continue
        vt[int(r["src"], 16)].append(r)

    evidence = defaultdict(list)  # v10 -> [(source, v30, quality)]
    for v10, r in exact.items():
        evidence[v10].append(("insns", int(r["v30"], 16), float(r["score"])))
    for v10, r in features.items():
        evidence[v10].append(("features", int(r["v30"], 16), float(r["sim"])))
    for v10, rs in vt.items():
        # prefer the exact sets; reference sets are useful but weaker
        rs = sorted(rs, key=lambda x: -float(x["confidence"]))
        best = rs[0]
        evidence[v10].append(("ghidra", int(best["dst"], 16), float(best["similarity"])))
    for v10, v30 in KNOWN.items():
        evidence[v10].append(("known", v30, 1.0))

    # --- conflict resolution ---------------------------------------------
    rows = []
    for v10 in sorted(inv_by):
        r = inv_by[v10]
        votes = evidence.get(v10, [])
        if not votes:
            rows.append({"v10": f"0x{v10:08X}", "v30": "", "state": "missing",
                         "sources": "", "name": "", "refs": r["Refs"], "first": r["First"]})
            continue
        by_target = defaultdict(list)
        for src, v30, q in votes:
            by_target[v30].append((src, q))
        targets = sorted(by_target, key=lambda t: (-len(by_target[t]), -max(q for _, q in by_target[t])))
        best = targets[0]
        others = [t for t in targets[1:]]
        srcs = by_target[best]
        if others:
            state = "conflict"
        elif len(srcs) >= 2 or srcs[0][0] == "known":
            state = "confirmed"
        else:
            state = "single"
        rows.append({
            "v10": f"0x{v10:08X}",
            "v30": f"0x{best:08X}",
            "state": state,
            "sources": "+".join(sorted(s for s, _ in srcs)),
            "name": r["Entry"],
            "refs": r["Refs"],
            "first": r["First"],
        })

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    high = [r for r in rows if r["state"] == "confirmed"]
    with open(OUT_HIGH, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(high)

    print("state counts:")
    for k, n in Counter(r["state"] for r in rows).most_common():
        print(f"  {k}: {n}")
    print(f"written: {OUT} ({len(rows)}), {OUT_HIGH} ({len(high)})")


if __name__ == "__main__":
    main()
