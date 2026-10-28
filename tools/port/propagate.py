"""Propagate 1.0 -> 3.0 function/data mappings through matched functions.

Start from the high-confidence matches produced by match_functions.py. For every pair, align the
two instruction sequences and compare each aligned instruction:

* a direct call/jump gives a vote for its target function;
* an absolute memory operand gives a vote for the referenced global.

New functions with enough votes are added to the seed set and the process repeats. This is how the
remaining 3.0 addresses are recovered without guessing.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/propagate.py
"""
import csv
import difflib
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match_functions import Pe, token  # noqa: E402

EXE10 = Path(r"C:\Users\Pc\AppData\Local\Temp\gta_sa_analysis.exe")
EXE30 = Path(r"C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe")
FUNCS10 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs10_analysis.json")
FUNCS30 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs30.json")
MATCHES = Path(r"C:\Users\Pc\AppData\Local\Temp\function_matches.csv")
OUT_FUNCS = Path(r"C:\Users\Pc\AppData\Local\Temp\propagated_functions.csv")
OUT_DATA = Path(r"C:\Users\Pc\AppData\Local\Temp\propagated_data.csv")

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


def is_game(v):
    v &= 0xFFFFFFFF
    return 0x401000 <= v < 0xD3C000


def disasm(pe, md, va, size):
    out = []
    for insn in md.disasm(pe.read(va, min(max(size, 16), 4096)), va):
        t = token(insn)
        if t:
            out.append((insn, t))
    return out


def direct_target(insn):
    if insn.mnemonic in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
        v = insn.operands[0].imm & 0xFFFFFFFF
        if is_game(v):
            return v
    return 0


def absolute_operand(insn):
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp:
            v = op.mem.disp & 0xFFFFFFFF
            if is_game(v):
                return v
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if is_game(v):
                return v
    return 0


def align_and_vote(a10, a30, f10, f30, md, p10, p30, fvotes, dvotes):
    i10 = disasm(p10, md, int(f10["addr"]), int(f10["size"]))
    i30 = disasm(p30, md, int(f30["addr"]), int(f30["size"]))
    if len(i10) < 3 or len(i30) < 3:
        return
    sm = difflib.SequenceMatcher(None, [t for _, t in i10], [t for _, t in i30], autojunk=False)
    for blk in sm.get_matching_blocks():
        for k in range(blk.size):
            x, y = i10[blk.a + k][0], i30[blk.b + k][0]
            t10, t30 = direct_target(x), direct_target(y)
            if t10 and t30:
                fvotes[(t10, t30)] += 1
            # a global access: both sides must reference some absolute address
            if x.operands and y.operands:
                d10, d30 = absolute_operand(x), absolute_operand(y)
                if d10 and d30:
                    dvotes[(d10, d30)] += 1


def main():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    p10, p30 = Pe(EXE10), Pe(EXE30)
    f10 = {int(f["addr"]): f for f in json.load(open(FUNCS10, encoding="utf-8-sig"))}
    f30 = {int(f["addr"]): f for f in json.load(open(FUNCS30, encoding="utf-8-sig"))}

    matches = list(csv.DictReader(open(MATCHES, encoding="utf-8-sig")))
    seeds = {}
    for m in matches:
        if not m["v30"]:
            continue
        score = float(m["score"])
        margin = score - float(m["second"])
        a10, a30 = int(m["v10"], 16), int(m["v30"], 16)
        if a10 == int(m["func10"], 16) and a30 == int(m["func30"], 16):
            if score >= 0.95 and margin >= 0.15:
                seeds[a10] = a30
    for a10, a30 in KNOWN.items():
        seeds[a10] = a30
    print(f"seeds: {len(seeds)}")

    all_f = dict(seeds)
    fvotes = Counter()
    dvotes = Counter()
    rounds = 0
    while True:
        rounds += 1
        fvotes.clear()
        dvotes.clear()
        for a10, a30 in all_f.items():
            if a10 not in f10 or a30 not in f30:
                continue
            align_and_vote(a10, a30, f10[a10], f30[a30], md, p10, p30, fvotes, dvotes)
        added = 0
        for (t10, t30), n in fvotes.most_common():
            if t10 in all_f:
                continue
            if t10 not in f10 or t30 not in f30:
                continue
            # a single vote is weak, but two different callers agreeing is strong
            if n >= 2:
                all_f[t10] = t30
                added += 1
        print(f"round {rounds}: {len(all_f)} functions (+{added}), "
              f"{sum(1 for v in fvotes.values() if v)} votes, {len(dvotes)} data votes")
        if added == 0:
            break

    with open(OUT_FUNCS, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v30", "seed", "votes"])
        for a10, a30 in sorted(all_f.items()):
            w.writerow([f"0x{a10:08X}", f"0x{a30:08X}",
                        "yes" if a10 in seeds else "no", fvotes.get((a10, a30), 0)])
    with open(OUT_DATA, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v30", "votes"])
        for (a10, a30), n in dvotes.most_common():
            w.writerow([f"0x{a10:08X}", f"0x{a30:08X}", n])
    print(f"written: {OUT_FUNCS} ({len(all_f)}), {OUT_DATA} ({len(dvotes)})")


if __name__ == "__main__":
    main()
