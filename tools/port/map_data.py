"""Translate the data addresses used by the client from 1.0 to 3.0 via code cross-references.

A global in the 1.0 client is referenced by absolute 32-bit addresses in .text. If the referring
function is matched to 3.0, the same instruction in 3.0 contains the 3.0 address of that global.
This script reports, for each data target, every cross-reference and the candidate 3.0 address.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/map_data.py
"""
import csv
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match_functions import Pe, seq, token  # noqa: E402

EXE10 = Path(r"C:\Users\Pc\AppData\Local\Temp\gta_sa_analysis.exe")
EXE30 = Path(r"C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe")
FUNCS10 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs10_analysis.json")
FUNCS30 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs30.json")
MATCHES = Path(r"C:\Users\Pc\AppData\Local\Temp\function_matches.csv")
INVENTORY = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop\docs\port\addresses.csv")
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\data_matches.csv")


def iter_insns(pe, md, start, size):
    code = pe.read(start, size)
    for insn in md.disasm(code, start):
        yield insn


def main():
    p10, p30 = Pe(EXE10), Pe(EXE30)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    f10 = {int(f["addr"]): f for f in json.load(open(FUNCS10, encoding="utf-8-sig"))}
    starts10 = sorted(f10)

    matches = {r["v10"]: r for r in csv.DictReader(open(MATCHES, encoding="utf-8-sig"))}
    rows = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))

    # index of every 4-byte literal in 1.0 .text
    text = p10.read(0x401000, 0x456000)
    refs = defaultdict(list)
    for va in range(0x401000, 0x857000 - 4):
        off = va - 0x401000
        if off + 4 > len(text):
            break
        v = struct.unpack_from("<I", text, off)[0]
        if 0x401000 <= v < 0xC98000:
            refs[v].append(va)
    print(f"1.0 text literals: {sum(len(v) for v in refs.values())}, unique {len(refs)}")

    data_rows = [r for r in rows if not (0x401000 <= int(r["Address"], 16) < 0x857000)]
    print(f"data/other targets: {len(data_rows)}")

    out_rows = []
    for r in data_rows:
        target = int(r["Address"], 16)
        sites = refs.get(target, [])
        votes = Counter()
        details = []
        for site in sites:
            f = owner(starts10, f10, site)
            if not f:
                continue
            m = matches.get(f"0x{int(f['addr']):08X}")
            if not m or not m["v30"] or float(m["score"]) < 0.75:
                continue
            v30func = int(m["v30"], 16)
            mapped = translate_inside(p10, p30, md, f, v30func, site)
            if not mapped:
                continue
            value = mapped
            if 0x401000 <= value < 0xD3C000:
                votes[value] += 1
                details.append(f"{site:08X}->{value:08X}")
        best = ""
        if votes:
            best = f"0x{votes.most_common(1)[0][0]:08X}"
        out_rows.append({
            "v10": f"0x{target:08X}",
            "v30": best,
            "votes": votes.most_common(1)[0][1] if votes else 0,
            "refs": len(sites),
            "details": ";".join(details[:6]),
            "refs_client": r["Refs"],
            "first": r["First"],
        })

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(out_rows[0]))
        w.writeheader()
        w.writerows(out_rows)
    print(f"with votes: {sum(1 for r in out_rows if r['v30'])} / {len(out_rows)}")
    print(f"written: {OUT}")


def owner(starts, by_start, va):
    import bisect
    k = bisect.bisect_right(starts, va) - 1
    if k < 0:
        return None
    f = by_start[starts[k]]
    return f if va < int(f["addr"]) + int(f["size"]) else None


def translate_inside(p10, p30, md, f10, v30func, site):
    """Find the instruction at `site` in the 1.0 function and return the 3.0 global it references,
    or 0. The functions are compared by normalized token sequence; a unique target is required."""
    import difflib
    start10 = int(f10["addr"])
    ins10 = []
    for insn in md.disasm(p10.read(start10, min(int(f10["size"]), 2048)), start10):
        t = token(insn)
        if t:
            ins10.append((insn.address, t))
    idx10 = next((i for i, (a, _) in enumerate(ins10) if a == site), None)
    if idx10 is None:
        return 0
    ins30 = []
    for insn in md.disasm(p30.read(v30func, 2048), v30func):
        t = token(insn)
        if t:
            ins30.append((insn.address, t, insn))
    a = [t for _, t in ins10]
    b = [t for _, t, _ in ins30]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for blk in sm.get_matching_blocks():
        if blk.a <= idx10 < blk.a + blk.size:
            insn = ins30[blk.b + (idx10 - blk.a)][2]
            return referenced_address(insn)
    return 0


def referenced_address(insn):
    for op in insn.operands:
        if op.type in (X86_OP_IMM, X86_OP_MEM):
            v = (op.imm if op.type == X86_OP_IMM else op.mem.disp) & 0xFFFFFFFF
            if 0x401000 <= v < 0xD3C000:
                return v
    return 0


if __name__ == "__main__":
    main()
