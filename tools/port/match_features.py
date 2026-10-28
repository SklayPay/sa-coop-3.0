"""Match functions by the strings and imported functions they reference.

Function bodies are rewritten between 1.0 and 3.0, but the strings and Win32/DirectX imports they
use usually stay the same. For every function we collect the set of string literals and import
names it refers to, then look for a 3.0 function with the same set. This recovers functions that
the instruction-level matcher cannot align.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/match_features.py
"""
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match_functions import Pe  # noqa: E402

EXE10 = Path(r"C:\Users\Pc\AppData\Local\Temp\gta_sa_analysis.exe")
EXE30 = Path(r"C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe")
FUNCS10 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs10_analysis.json")
FUNCS30 = Path(r"C:\Users\Pc\AppData\Local\Temp\funcs30.json")
INVENTORY = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop\docs\port\addresses.csv")
OUT = Path(r"C:\Users\Pc\AppData\Local\Temp\feature_matches.csv")

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


class Features:
    def __init__(self, path):
        self.pe = Pe(path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.imports = {}
        self.strings = {}
        self._load_imports(path)
        self._load_strings()

    def _load_imports(self, path):
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode(errors="replace").upper()
            for imp in entry.imports:
                if imp.name:
                    self.imports[imp.address] = dll + "!" + imp.name.decode(errors="replace")

    def _load_strings(self):
        for name, start, end, data in self.pe.sections:
            if name not in (".rdata", ".data"):
                continue
            for m in PRINTABLE.finditer(data):
                if m.start() < 2:
                    continue
                self.strings[start + m.start()] = m.group().decode(errors="replace")

    def features(self, func):
        va = int(func["addr"])
        size = min(max(int(func["size"]), 16), 4096)
        strings = set()
        imports = set()
        for insn in self.md.disasm(self.pe.read(va, size), va):
            for op in insn.operands:
                v = 0
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                    v = op.mem.disp & 0xFFFFFFFF
                if not v:
                    continue
                if v in self.imports:
                    imports.add(self.imports[v])
                s = self.strings.get(v)
                if s and len(s) >= 5:
                    strings.add(s)
        return strings, imports


def main():
    f10 = json.load(open(FUNCS10, encoding="utf-8-sig"))
    f30 = json.load(open(FUNCS30, encoding="utf-8-sig"))
    a = Features(EXE10)
    b = Features(EXE30)
    print(f"imports {len(a.imports)}/{len(b.imports)}, strings {len(a.strings)}/{len(b.strings)}")

    print("features 3.0...", flush=True)
    feat30 = {}
    for i, f in enumerate(f30):
        s, im = b.features(f)
        if s or im:
            feat30[int(f["addr"])] = (s, im)
        if i % 2000 == 0:
            print(f"  {i}/{len(f30)}", flush=True)

    # index by each individual string/import, then count co-occurrences
    idx = defaultdict(list)
    for va, (s, im) in feat30.items():
        for x in s:
            idx[("s", x)].append(va)
        for x in im:
            idx[("i", x)].append(va)

    starts10 = sorted(int(f["addr"]) for f in f10)
    by10 = {int(f["addr"]): f for f in f10}
    import bisect

    def owner(va):
        k = bisect.bisect_right(starts10, va) - 1
        if k < 0:
            return None
        f = by10[starts10[k]]
        return f if va < int(f["addr"]) + int(f["size"]) else None

    rows = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    known = {0x4D3990: 0x4DE2F0, 0x563280: 0x57D370, 0x5A82C0: 0x5BDFE0,
             0x601110: 0x620E70, 0x6190A0: 0x63AB90, 0x734A40: 0x7671B0,
             0x743C60: 0x77D940, 0x7F0990: 0x82A950}
    out = []
    for r in rows:
        v = int(r["Address"], 16)
        if not (0x401000 <= v < 0x857000):
            continue
        f = owner(v)
        if not f:
            continue
        s, im = a.features(f)
        if len(s) + len(im) < 2:
            continue
        votes = Counter()
        for x in s:
            for va in idx.get(("s", x), [])[:400]:
                votes[va] += 1
        for x in im:
            for va in idx.get(("i", x), [])[:400]:
                votes[va] += 3  # imports are more distinctive
        best = []
        for va, n in votes.items():
            s2, im2 = feat30[va]
            union = len(s | s2) + len(im | im2)
            if not union:
                continue
            sim = (len(s & s2) + len(im & im2)) / union
            best.append((sim, n, va))
        best.sort(reverse=True)
        if not best:
            continue
        sim, n, va = best[0]
        second = best[1][0] if len(best) > 1 else 0.0
        out.append({
            "v10": f"0x{v:08X}",
            "v30": f"0x{va:08X}",
            "sim": f"{sim:.3f}",
            "votes": n,
            "margin": f"{sim - second:.3f}",
            "strings": len(s),
            "imports": len(im),
            "func10": f"0x{int(f['addr']):08X}",
            "first": r["First"],
        })
        if v in known:
            print(f"KNOWN {v:08X} -> {va:08X} sim={sim:.2f} want={known[v]:08X}")

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)
    print(f"matched: {len(out)}; written: {OUT}")


if __name__ == "__main__":
    main()
