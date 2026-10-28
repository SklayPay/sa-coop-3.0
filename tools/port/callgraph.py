"""Score function pairs by their direct call and data-reference fingerprints.

The instruction matcher is weak on large functions where the compiler inlined code
differently. The call graph is much more stable: if a 1.0 function calls ten functions whose
3.0 counterparts are already known, the 3.0 function with the same ten callees is almost
certainly its counterpart.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/callgraph.py
"""
import bisect
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, addr10, build_seeds, ghirda_functions, is_data10  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
MAPPING = ROOT / "docs/port/mapping.csv"
INVENTORY = ROOT / "docs/port/addresses.csv"
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\callgraph_scores.csv")


def direct_target(insn):
    if insn.mnemonic == "call" and insn.operands:
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            return op.imm & 0xFFFFFFFF
    return 0


def data_target(insn):
    if insn.mnemonic in ("call", "jmp"):
        return 0
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            v = op.mem.disp & 0xFFFFFFFF
            if is_data10(v):
                return v
        elif op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if is_data10(v):
                return v
    return 0


def main():
    model = Model()
    ghidra = ghirda_functions()
    seeds, sources = build_seeds(model, ghidra)
    print(f"seeds: {len(seeds)}")

    data_map = {}
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if not r["v30"] or r["kind"] != "data":
            continue
        data_map[int(r["v10"], 16)] = int(r["v30"], 16)
    print(f"data map: {len(data_map)}")

    inv = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    code = [int(r["Address"], 16) for r in inv if 0x401000 <= int(r["Address"], 16) < 0x12FB000]

    def fingerprint(which, va, size):
        calls = set()
        datas = set()
        for a, _, insn in model.insns(which, va, size):
            c = direct_target(insn)
            if c:
                calls.add(c)
            d = data_target(insn)
            if d:
                datas.add(d)
        return calls, datas

    starts10 = sorted(model.f10)

    def owner10(va):
        k = bisect.bisect_right(starts10, va) - 1
        if k < 0:
            return None
        f = model.f10[starts10[k]]
        return f if va < int(f["addr"], 16) + int(f["size"]) else None

    # Functions we still need, keyed by owner start (0 for addresses with no owner).
    need = set()
    for v in code:
        f = owner10(v)
        a = addr10(f) if f else 0
        if a not in seeds:
            need.add(a)

    print(f"missing functions: {len(need)}")

    # 3.0 call/data fingerprints for every function.
    f30 = {}
    for a, f in model.f30.items():
        calls, datas = fingerprint(30, a, int(f["size"]))
        f30[a] = (calls, datas, int(f["size"]))
    print(f"3.0 fingerprints: {len(f30)}")

    # Inverted index: expected 3.0 call target -> 1.0 functions that call it.
    expected = defaultdict(Counter)  # v10 -> Counter(3.0 address -> weight)
    for v10, f in model.f10.items():
        if v10 not in need:
            continue
        calls, datas = fingerprint(10, v10, int(f["size"]))
        for c in calls:
            m = seeds.get(c)
            if m:
                expected[v10][("c", m)] += 1
        for d in datas:
            m = data_map.get(d)
            if m:
                expected[v10][("d", m)] += 1

    # Score every 3.0 function against every missing 1.0 function via inverted index.
    inv_call = defaultdict(list)
    inv_data = defaultdict(list)
    for v10, cnt in expected.items():
        for (kind, target), w in cnt.items():
            (inv_call if kind == "c" else inv_data)[target].append((v10, w))

    scores = defaultdict(Counter)
    for a30, (calls, datas, size30) in f30.items():
        for c in calls:
            for v10, w in inv_call.get(c, ()):
                scores[v10][a30] += w
        for d in datas:
            for v10, w in inv_data.get(d, ()):
                scores[v10][a30] += 2 * w

    # Token scores from the Ghidra-boundary matcher.
    tok = {}
    for r in csv.DictReader(open(r"C:\Users\Pc\AppData\Local\Temp\function_matches_ghidra.csv", encoding="utf-8-sig")):
        if r["v30"]:
            tok[int(r["v10"], 16)] = (int(r["v30"], 16), float(r["score"]))

    rows = []
    for v10, cnt in sorted(scores.items(), key=lambda kv: -max(kv[1].values() or [0])):
        if v10 not in need:
            continue
        top = cnt.most_common(5)
        if not top:
            continue
        best, best_score = top[0]
        second = top[1][1] if len(top) > 1 else 0
        tv, ts = tok.get(v10, (0, 0.0))
        calls, datas = fingerprint(10, v10, int(model.f10[v10]["size"]))
        rows.append({
            "v10": f"0x{v10:08X}",
            "v30": f"0x{best:08X}",
            "matches": best_score,
            "second": second,
            "token": f"{ts:.3f}" if tv else "",
            "token_v30": f"0x{tv:08X}" if tv else "",
            "calls": len(calls),
            "datas": len(datas),
            "size10": int(model.f10[v10]["size"]),
            "size30": int(model.f30.get(best, {}).get("size", 0)),
            "first": next((r["First"] for r in inv if owner10(int(r["Address"], 16)) is not None
                           and addr10(owner10(int(r["Address"], 16))) == v10), ""),
        })

    rows.sort(key=lambda r: -(r["matches"] + float(r["token"] or 0)))
    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"written: {OUT} ({len(rows)})")
    for r in rows[:40]:
        print(f"{r['v10']} -> {r['v30']} m={r['matches']} second={r['second']} "
              f"tok={r['token']} tok30={r['token_v30']} size {r['size10']}/{r['size30']} {r['first']}")


if __name__ == "__main__":
    main()
