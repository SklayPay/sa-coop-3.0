"""Match 1.0 US functions to 3.0 functions using radare2 function boundaries.

This is a port helper, not part of the mod. It reads two radare2 `aflj` exports and writes
function-level candidates to CSV; the addresses are then verified manually and copied into
src/client/shared/game/version/Addresses.cpp.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/match_functions.py
"""
import argparse
import csv
import difflib
import json
from collections import defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

EXE10 = Path(r"C:\Users\Pc\AppData\Local\Temp\gta_sa_analysis.exe")
EXE30 = Path(r"C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe")
FUNCS10 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs10_analysis.json")
FUNCS30 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs30.json")
INVENTORY = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop\docs\port\addresses.csv")
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\function_matches.csv")

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


class Pe:
    def __init__(self, path):
        pe = pefile.PE(str(path), fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\0").decode(errors="replace")
            start = self.base + s.VirtualAddress
            size = max(s.Misc_VirtualSize, s.SizeOfRawData)
            self.sections.append((name, start, start + size, pe.get_data(s.VirtualAddress, size)))

    def read(self, va, size):
        for _, start, end, data in self.sections:
            if start <= va < end:
                return data[va - start:va - start + size]
        return b""

    def section(self, va):
        for name, start, end, _ in self.sections:
            if start <= va < end:
                return name
        return None


def is_game_address(v):
    v &= 0xFFFFFFFF
    return 0x401000 <= v < 0xC98000 or 0x1556000 <= v < 0x1577000


def token(insn):
    mn = insn.mnemonic
    if mn.startswith("."):
        return None
    if insn.group(CS_GRP_CALL):
        return "call"
    if insn.group(CS_GRP_JUMP):
        return mn  # jmp, je, jne, ...
    parts = []
    for op in insn.operands:
        if op.type == X86_OP_REG:
            parts.append(insn.reg_name(op.reg))
        elif op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            parts.append("ADDR" if is_game_address(v) else f"{v:#x}")
        elif op.type == X86_OP_MEM:
            base = insn.reg_name(op.mem.base) if op.mem.base else ""
            idx = insn.reg_name(op.mem.index) if op.mem.index else ""
            disp = op.mem.disp
            if base and idx:
                s = f"[{base}+{idx}*{op.mem.scale}"
            elif base:
                s = f"[{base}"
            elif idx:
                s = f"[{idx}*{op.mem.scale}"
            else:
                s = "["
            if disp:
                s += "+ADDR" if (is_game_address(disp) or abs(disp) > 0x1000) else f"{disp:+#x}"
            s += "]"
            parts.append(s)
        else:
            parts.append("?")
    return mn + " " + ",".join(parts)


def seq(pe, md, func, limit=140):
    va = int(func["addr"])
    size = int(func["size"])
    code = pe.read(va, min(max(size, 16), 2048))
    out = []
    for insn in md.disasm(code, va):
        t = token(insn)
        if t:
            out.append(t)
        if len(out) >= limit:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    f10 = json.load(open(FUNCS10, encoding="utf-8-sig"))
    f30 = json.load(open(FUNCS30, encoding="utf-8-sig"))
    p10, p30 = Pe(EXE10), Pe(EXE30)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    print(f"functions: 1.0 {len(f10)}, 3.0 {len(f30)}")
    print("disassembling 3.0...", flush=True)
    s30 = {}
    starts30 = []
    for i, f in enumerate(f30):
        t = seq(p30, md, f)
        if len(t) >= 4:
            s30[int(f["addr"])] = t
            starts30.append(int(f["addr"]))
        if i % 2000 == 0:
            print(f"  {i}/{len(f30)}", flush=True)

    print("building index...", flush=True)
    index = defaultdict(set)
    for va, t in s30.items():
        for j in range(min(32, len(t) - 2)):
            index[tuple(t[j:j + 3])].add(va)

    print("disassembling 1.0 targets...", flush=True)
    rows = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    by_start = {int(f["addr"]): f for f in f10}
    starts10 = sorted(by_start)

    # map a target address to the function that contains it
    def owner(va):
        lo, hi = 0, len(starts10) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if starts10[mid] <= va:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if best is None:
            return None
        f = by_start[starts10[best]]
        return f if va < int(f["addr"]) + int(f["size"]) else None

    results = []
    hits = 0
    for n, r in enumerate(rows):
        v10 = int(r["Address"], 16)
        if p10.section(v10) != ".text" or not (0x401000 <= v10 < 0x857000):
            continue
        f = owner(v10)
        if not f:
            continue
        t10 = seq(p10, md, f)
        if len(t10) < 4:
            continue
        candidates = set()
        for j in range(min(32, len(t10) - 2)):
            candidates |= index.get(tuple(t10[j:j + 3]), set())
        best = []
        for va30 in candidates:
            b = s30[va30]
            sm = difflib.SequenceMatcher(None, t10[:96], b[:96], autojunk=False)
            ratio = sm.ratio()
            # length similarity is a useful tie breaker for tiny functions
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
            "func30": f"0x{va30:08X}" if va30 else "",
            "refs": r["Refs"],
            "first": r["First"],
        })
        if v10 in KNOWN:
            ok = "OK" if va30 == KNOWN[v10] else f"WRONG (want {KNOWN[v10]:08X})"
            print(f"KNOWN {v10:08X} -> {va30:08X} {ok} score={score:.3f}", flush=True)
            hits += 1
        if n % 50 == 0:
            print(f"  {n}/{len(rows)}", flush=True)

    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(results[0]))
        w.writeheader()
        w.writerows(results)
    print(f"known checked: {hits}/{len(KNOWN)}")
    print(f"written: {args.out}")


if __name__ == "__main__":
    main()
