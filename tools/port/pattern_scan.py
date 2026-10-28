"""Find functions in 3.0 by a masked byte signature taken from 1.0.

Whole-function instruction matching fails when one inlined block changed, even though the
prologue/epilogue of a function is byte-for-byte identical. This tool takes the first
instructions of each unmatched 1.0 function, replaces every relocatable value (call target,
absolute data address, internal branch displacement) with a wildcard and searches the 3.0
.text section. A hit must land on a Ghidra function start.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/pattern_scan.py
"""
import bisect
import csv
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, addr10, build_seeds, ghirda_functions  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
INVENTORY = ROOT / "docs/port/addresses.csv"
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\pattern_scan.csv")


def mask_pattern(md, pe, va, size, max_insns=30):
    """Return (pattern_regex, instruction_count, byte_length) for the start of a function."""
    code = pe.read(va, min(max(size, 16), 512))
    pieces = []
    used = 0
    count = 0
    for insn in md.disasm(code, va):
        if used + len(insn.bytes) > 96 or count >= max_insns:
            break
        raw = bytearray(insn.bytes)
        mask = bytearray(len(raw))
        # Relocatable operands: absolute immediates and absolute memory displacements.
        for op in insn.operands:
            values = []
            if op.type == X86_OP_IMM:
                values.append(op.imm & 0xFFFFFFFF)
            elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                values.append(op.mem.disp & 0xFFFFFFFF)
            for v in values:
                needle = struct.pack("<I", v)
                pos = raw.find(needle)
                if pos >= 0:
                    for i in range(pos, pos + 4):
                        mask[i] = 1
        # Relative branches/calls: displacement bytes are not the absolute target.
        if insn.mnemonic in ("call", "jmp") or insn.group(CS_GRP_JUMP):
            op = insn.operands[0] if insn.operands else None
            if op is not None and op.type == X86_OP_IMM:
                target = op.imm & 0xFFFFFFFF
                disp = (target - (insn.address + len(raw))) & 0xFFFFFFFF
                needle = struct.pack("<I", disp)
                pos = raw.find(needle)
                if pos < 0 and insn.mnemonic in ("jmp", "call") and len(raw) == 2:
                    disp8 = (target - (insn.address + 2)) & 0xFF
                    pos = raw.find(bytes([disp8]))
                if pos >= 0:
                    for i in range(pos, len(raw)):
                        mask[i] = 1
        for b, m in zip(raw, mask):
            pieces.append(b"." if m else re.escape(bytes([b])))
        used += len(raw)
        count += 1
        if insn.mnemonic in ("ret", "jmp") and count > 4:
            break
    if not pieces:
        return None, 0, 0
    return re.compile(b"".join(pieces), re.S), count, used


def main():
    model = Model()
    ghidra = ghirda_functions()
    seeds, sources = build_seeds(model, ghidra, include_propagated=True)
    print(f"seeds: {len(seeds)}")

    starts30 = sorted(model.f30)
    text30 = b"".join(data for name, start, end, data in model.p30.sections if name == ".text")
    text30_base = next(start for name, start, end, data in model.p30.sections if name == ".text")

    inv = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    starts10 = sorted(model.f10)

    def owner10(va):
        k = bisect.bisect_right(starts10, va) - 1
        if k < 0:
            return None
        f = model.f10[starts10[k]]
        return f if va < addr10(f) + int(f["size"]) else None

    def body_of(f):
        va = addr10(f)
        ins = list(model.md.disasm(model.p10.read(va, 8), va))
        if ins and ins[0].mnemonic == "jmp" and ins[0].operands:
            op = ins[0].operands[0]
            if op.type == X86_OP_IMM:
                t = op.imm & 0xFFFFFFFF
                if t in model.f10:
                    return model.f10[t]
        return f

    need = set()
    for r in inv:
        v = int(r["Address"], 16)
        f = owner10(v)
        a = addr10(f) if f else 0
        if a not in seeds:
            need.add(a)

    # Only functions that are still unmapped.
    rows = []
    for a in sorted(need):
        if a == 0 or a not in model.f10:
            continue
        f = body_of(model.f10[a])
        pat, count, length = mask_pattern(model.md, model.p10, addr10(f), int(f["size"]))
        if not pat or count < 4:
            continue
        hits = []
        for m in pat.finditer(text30):
            va = text30_base + m.start()
            # Prefer exact function starts; if the hit is inside a function, take its owner.
            k = bisect.bisect_right(starts30, va) - 1
            if k < 0:
                continue
            fa = starts30[k]
            if va == fa:
                hits.append(fa)
            # else leave mid-function hits out: they are usually a different function's tail.
        hits = sorted(set(hits))
        rows.append({
            "v10": f"0x{a:08X}",
            "body10": f"0x{addr10(f):08X}",
            "v30": f"0x{hits[0]:08X}" if len(hits) == 1 else "",
            "hits": len(hits),
            "candidates": " ".join(f"0x{x:08X}" for x in hits[:8]),
            "insns": count,
            "bytes": length,
            "thunk": "yes" if f is not model.f10[a] else "",
            "first": next((r["First"] for r in inv if owner10(int(r["Address"], 16)) is not None
                           and addr10(owner10(int(r["Address"], 16))) == a), ""),
        })

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"written: {OUT} ({len(rows)})")
    for r in rows:
        if r["v30"]:
            print(f"{r['v10']} -> {r['v30']} insns={r['insns']} bytes={r['bytes']} {r['first']}")
        elif r["hits"]:
            print(f"{r['v10']} ambiguous hits={r['hits']}: {r['candidates']} {r['first']}")


if __name__ == "__main__":
    main()
