"""Propagate function mappings through direct calls, using Ghidra function boundaries.

The seed set comes from consolidate.build_seeds (Ghidra Version Tracking, the instruction
matcher and the string/import matcher). Every matched function pair is aligned instruction by
instruction; a direct call in a matched block gives a vote for the callee pair. Callees with at
least two independent votes are added and the process repeats.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/propagate_ghidra.py
"""
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, addr10, align, build_seeds, ghirda_functions  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
INVENTORY = ROOT / "docs/port/addresses.csv"
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\propagated_ghidra.csv")


def direct_target(insn):
    if insn.mnemonic in ("call", "jmp") and insn.operands:
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if 0x401000 <= v < 0x857000:
                return v
    return 0


def main():
    model = Model()
    ghidra = ghirda_functions()
    seeds, sources = build_seeds(model, ghidra, include_propagated=False)
    print(f"seed functions: {len(seeds)}")

    all_f = dict(seeds)
    rounds = 0
    while True:
        rounds += 1
        votes = Counter()
        for v10, v30 in all_f.items():
            if v10 not in model.f10 or v30 not in model.f30:
                continue
            t10, t30, blocks = align(model, model.f10[v10], v30)
            for blk in blocks:
                for k in range(blk.size):
                    c10 = direct_target(t10[blk.a + k][2])
                    c30 = direct_target(t30[blk.b + k][2])
                    if c10 and c30 and c10 != v10 and c30 != v30:
                        if c10 in model.f10 and c30 in model.f30:
                            votes[(c10, c30)] += 1
        added = 0
        for (c10, c30), n in votes.most_common():
            if c10 in all_f or c10 in model.f10 and c10 in seeds:
                continue
            if c10 not in model.f10 or c30 not in model.f30:
                continue
            if all_f.get(c10, c30) != c30:
                continue
            if n >= 2:
                all_f[c10] = c30
                added += 1
        print(f"round {rounds}: {len(all_f)} (+{added}), {len(votes)} candidate pairs")
        if added == 0:
            break

    known = {0x4D3990: 0x4DE2F0, 0x563280: 0x57D370, 0x5A82C0: 0x5BDFE0,
             0x601110: 0x620E70, 0x6190A0: 0x63AB90, 0x734A40: 0x7671B0,
             0x743C60: 0x77D940, 0x7F0990: 0x82A950}
    for a, b in known.items():
        print(f"known {a:08X} -> {all_f.get(a, 0):08X} want {b:08X}")

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["v10", "v30", "seed"])
        for a, b in sorted(all_f.items()):
            w.writerow([f"0x{a:08X}", f"0x{b:08X}", "yes" if a in seeds else "no"])

    # coverage of the client inventory
    inv = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    covered = 0
    total = 0
    for r in inv:
        v = int(r["Address"], 16)
        if not (0x401000 <= v < 0x857000):
            continue
        total += 1
        f = model.owner10(v)
        if f and addr10(f) in all_f:
            covered += 1
    print(f"code inventory covered by function: {covered}/{total}")


if __name__ == "__main__":
    main()
