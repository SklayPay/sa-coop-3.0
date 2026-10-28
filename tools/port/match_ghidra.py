"""Function matcher using Ghidra function boundaries (instead of radare2).

Radare2 merges some HOODLUM functions into enormous blobs, which makes whole-function
comparison useless. Ghidra's analysis gives one entry per real function, including the
HOODLUM trampoline targets in the second .text section.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/match_ghidra.py
"""
import argparse
import csv
import difflib
import json
import sys
from collections import defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match_functions import EXE10, EXE30, Pe, is_game_address, token  # noqa: E402

TMP = Path(r"C:\Users\Pc\AppData\Local\Temp")
FUNCS10 = TMP / "ghidra_funcs10.csv"
FUNCS30 = TMP / "ghidra_funcs30.csv"
INVENTORY = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop\docs\port\addresses.csv")
OUT = TMP / "function_matches_ghidra.csv"

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


def load_funcs(path):
    out = {}
    for r in csv.DictReader(open(path, encoding="utf-8-sig")):
        a = int(r["addr"], 16)
        out[a] = {"addr": a, "size": int(r["size"]), "name": r["name"]}
    return out


def seq(pe, md, func, limit=160):
    va = int(func["addr"])
    size = int(func["size"])
    code = pe.read(va, min(max(size, 16), 4096))
    out = []
    for insn in md.disasm(code, va):
        t = token(insn)
        if t:
            out.append(t)
        if len(out) >= limit:
            break
    return out


def thunk_target(pe, md, func):
    """If the function is a 5-byte HOODLUM trampoline, return its target."""
    code = pe.read(int(func["addr"]), 8)
    ins = list(md.disasm(code, int(func["addr"])))
    if ins and ins[0].mnemonic == "jmp" and ins[0].operands:
        op = ins[0].operands[0]
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if is_game_address(v):
                return v
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    f10, f30 = load_funcs(FUNCS10), load_funcs(FUNCS30)
    p10, p30 = Pe(EXE10), Pe(EXE30)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    print(f"functions: 1.0 {len(f10)}, 3.0 {len(f30)}")

    print("disassembling 3.0...", flush=True)
    s30 = {}
    for i, f in enumerate(f30.values()):
        t = seq(p30, md, f)
        if len(t) >= 3:
            s30[int(f["addr"])] = t
        if i % 3000 == 0:
            print(f"  {i}/{len(f30)}", flush=True)

    print("building index...", flush=True)
    index = defaultdict(set)
    for va, t in s30.items():
        for j in range(min(24, len(t) - 2)):
            index[tuple(t[j:j + 3])].add(va)

    starts10 = sorted(f10)
    import bisect

    def owner(va):
        k = bisect.bisect_right(starts10, va) - 1
        if k < 0:
            return None
        f = f10[starts10[k]]
        return f if va < f["addr"] + f["size"] else None

    rows = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    results = []
    for n, r in enumerate(rows):
        v10 = int(r["Address"], 16)
        if not (0x401000 <= v10 < 0x857000):
            continue
        f = owner(v10)
        if not f:
            continue
        # If the owner is a HOODLUM trampoline, match the real body it jumps to.
        match_func = f
        thunk = thunk_target(p10, md, f)
        if thunk and thunk in f10 and f["size"] <= 8:
            match_func = f10[thunk]
        t10 = seq(p10, md, match_func)
        if len(t10) < 3:
            continue
        candidates = set()
        for j in range(min(24, len(t10) - 2)):
            candidates |= index.get(tuple(t10[j:j + 3]), set())
        best = []
        for va30 in candidates:
            b = s30[va30]
            sm = difflib.SequenceMatcher(None, t10[:120], b[:120], autojunk=False)
            ratio = sm.ratio()
            lr = min(len(t10), len(b)) / max(len(t10), len(b))
            score = 0.85 * ratio + 0.15 * lr
            best.append((score, ratio, lr, va30))
        best.sort(reverse=True)
        if best:
            score, ratio, lr, va30 = best[0]
            second = best[1][0] if len(best) > 1 else 0.0
        else:
            score = ratio = lr = second = 0.0
            va30 = 0
        results.append({
            "v10": f"0x{v10:08X}",
            "v30": f"0x{va30:08X}" if va30 else "",
            "score": f"{score:.4f}",
            "ratio": f"{ratio:.4f}",
            "lenratio": f"{lr:.4f}",
            "second": f"{second:.4f}",
            "func10": f"0x{int(f['addr']):08X}",
            "match10": f"0x{int(match_func['addr']):08X}",
            "func30": f"0x{va30:08X}" if va30 else "",
            "thunk": "yes" if match_func is not f else "",
            "refs": r["Refs"],
            "first": r["First"],
        })
        if v10 in KNOWN:
            want = KNOWN[v10]
            ok = "OK" if va30 == want else f"want {want:08X}"
            print(f"KNOWN {v10:08X} -> {va30:08X} {ok} score={score:.3f}", flush=True)
        if n % 50 == 0:
            print(f"  {n}/{len(rows)}", flush=True)

    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(results[0]))
        w.writeheader()
        w.writerows(results)
    print(f"written: {args.out} ({len(results)} rows)")


if __name__ == "__main__":
    main()
