"""Map a single missing address by matching its local instruction pattern.

Whole-function matching needs a function boundary and a good instruction score. For the last
dozen addresses that is too strict: a small function that Ghidra never split, a call inside an
inlined block, or a patch in the middle of a function all have a distinctive local instruction
sequence even when the surrounding function differs.

The pattern is taken around the address, every absolute operand and every relative branch
displacement is masked, and the hit must be unique in 3.0 and land on an instruction boundary.
A function start must land on a Ghidra function start.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/local_scan.py
"""
import bisect
import csv
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, addr10, is_code10  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
MAPPING = ROOT / "docs/port/mapping.csv"
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\local_scan.csv")


def mask(insn):
    raw = bytearray(insn.bytes)
    m = bytearray(len(raw))
    for op in insn.operands:
        values = []
        if op.type == X86_OP_IMM:
            values.append(op.imm & 0xFFFFFFFF)
        elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            values.append(op.mem.disp & 0xFFFFFFFF)
        for v in values:
            pos = raw.find(struct.pack("<I", v))
            if pos >= 0:
                m[pos:pos + 4] = b"\x01" * 4
    if insn.group(CS_GRP_JUMP) or insn.mnemonic == "call":
        op = insn.operands[0] if insn.operands else None
        if op is not None and op.type == X86_OP_IMM:
            target = op.imm & 0xFFFFFFFF
            for width, calc in ((4, 4), (1, 1)):
                disp = (target - (insn.address + len(raw))) & ((1 << (8 * width)) - 1)
                pos = raw.find(disp.to_bytes(width, "little"))
                if pos >= 0:
                    m[pos:pos + width] = b"\x01" * width
                    break
    return raw, m


def build_pattern(md, pe, start, limit=16, min_insns=5):
    code = pe.read(start, 384)
    pieces = []
    count = 0
    for insn in md.disasm(code, start):
        raw, m = mask(insn)
        for b, f in zip(raw, m):
            pieces.append(b"." if f else re.escape(bytes([b])))
        count += 1
        if insn.mnemonic == "ret" and count >= min_insns:
            break
        if count >= limit:
            break
    if count < min_insns:
        return None, 0
    return re.compile(b"".join(pieces), re.S), count


def main():
    model = Model()
    inv = list(csv.DictReader(open(MAPPING, encoding="utf-8-sig")))
    todo = [r for r in inv if not r["v30"] and is_code10(int(r["v10"], 16))]
    print(f"missing code: {len(todo)}")

    starts10 = sorted(model.f10)
    starts30 = sorted(model.f30)
    text30 = b"".join(d for n, s, e, d in model.p30.sections if n == ".text")
    base30 = next(s for n, s, e, d in model.p30.sections if n == ".text")

    def owner10(va):
        k = bisect.bisect_right(starts10, va) - 1
        if k < 0:
            return None
        f = model.f10[starts10[k]]
        return f if va < addr10(f) + int(f["size"]) else None

    def owner30(va):
        k = bisect.bisect_right(starts30, va) - 1
        if k < 0:
            return None
        return starts30[k]

    def insn_start30(va):
        f = owner30(va)
        if f is None:
            return False
        code = model.p30.read(f, 256)
        for insn in model.md.disasm(code, f):
            if insn.address == va:
                return True
            if insn.address > va:
                return False
        return False

    rows = []
    for r in todo:
        v10 = int(r["v10"], 16)
        f = owner10(v10)
        at_start = f is not None and addr10(f) == v10
        # For an address Ghidra has no function for, start there anyway.
        start = v10 if not f else (addr10(f) if at_start else v10 - 8)
        pat, count = build_pattern(model.md, model.p10, start)
        if not pat:
            continue
        hits = []
        for m in pat.finditer(text30):
            va = base30 + m.start()
            if not insn_start30(va):
                continue
            if at_start or f is None:
                if owner30(va) != va:
                    continue
            hits.append(va)
            if len(hits) > 4:
                break
        hits = sorted(set(hits))
        rows.append({
            "v10": f"0x{v10:08X}",
            "v30": f"0x{hits[0]:08X}" if len(hits) == 1 else "",
            "hits": len(hits),
            "candidates": " ".join(f"0x{x:08X}" for x in hits[:5]),
            "insns": count,
            "at_start": "yes" if (at_start or f is None) else "no",
            "first": r["first"],
        })

    if rows:
        with open(OUT, "w", newline="", encoding="utf-8") as fp:
            w = csv.DictWriter(fp, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"written {OUT} ({len(rows)})")
    for r in rows:
        if r["v30"]:
            print(f"OK   {r['v10']} -> {r['v30']} insns={r['insns']} start={r['at_start']} {r['first']}")
        else:
            print(f"???  {r['v10']} hits={r['hits']} {r['candidates']} start={r['at_start']} {r['first']}")


if __name__ == "__main__":
    main()
