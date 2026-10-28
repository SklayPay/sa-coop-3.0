"""Consolidate every matcher into one 1.0 -> 3.0 address mapping for the client inventory.

This is the "brain" of the port: it takes the function matches found by
match_functions.py (instruction sequences), match_features.py (strings/imports) and Ghidra
Version Tracking (VtExport.java), resolves conflicts, and then translates the individual
inventory addresses:

  * a function start maps to the 3.0 function start;
  * a call site or byte patch site maps to the same instruction in the aligned 3.0 function;
  * a global variable maps to the absolute operand of the aligned 3.0 instruction, including
    array element addresses (operand + offset).

Nothing is guessed: a row is only emitted when the two functions align on the surrounding
instructions. Rows that disagree between sources are reported as conflicts.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/consolidate.py
"""
import bisect
import csv
import difflib
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match_functions import Pe, token  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
TMP = Path(r"C:\Users\Pc\AppData\Local\Temp")
EXE10 = TMP / "gta_sa_analysis.exe"
EXE30 = Path(r"C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe")
FUNCS10 = TMP / "ghidra_funcs10.csv"
FUNCS30 = TMP / "ghidra_funcs30.csv"
INVENTORY = ROOT / "docs/port/addresses.csv"
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


SET_SEEDS = {}


def in_game(v):
    v &= 0xFFFFFFFF
    return 0x401000 <= v < 0xD3C000


def is_data10(v):
    """1.0 data sections: .rdata, .data, _TEXT_HA, .init second .data."""
    return (0x858000 <= v < 0x8A4000) or (0x8A4000 <= v < 0xC9E000) or (0xC9E000 <= v < 0xCAF000) or (0x12FB000 <= v < 0x1556000)


def is_code10(v):
    """1.0 US has a second .text section and a HOODLUM section; both hold real code."""
    return (0x401000 <= v < 0x857000) or (0xCB1000 <= v < 0x12FB000) or (0x1556000 <= v < 0x1577000)


def operand_value(insn):
    """Absolute address referenced by an instruction, or 0."""
    for kind, v in operands(insn):
        if in_game(v):
            return v
    return 0


def operands(insn):
    """[(kind, absolute address)] for the absolute operands of an instruction."""
    out = []
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp:
            out.append(("mem", op.mem.disp & 0xFFFFFFFF))
        elif op.type == X86_OP_IMM:
            out.append(("imm", op.imm & 0xFFFFFFFF))
    return out


def is_data30(v):
    """3.0 .rdata/.data live in this range; .text ends at 0x8B4000."""
    return 0x8A5000 <= v < 0xD29000


class Model:
    def __init__(self):
        self.p10 = Pe(EXE10)
        self.p30 = Pe(EXE30)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.f10 = {int(f["addr"], 16): f for f in csv.DictReader(open(FUNCS10, encoding="utf-8-sig"))}
        self.f30 = {int(f["addr"], 16): f for f in csv.DictReader(open(FUNCS30, encoding="utf-8-sig"))}
        self.starts10 = sorted(self.f10)
        self.starts30 = sorted(self.f30)
        self._cache = {}
        self._refs = None

    def refs(self):
        """All absolute data references in 1.0 .text, keyed by the referenced address.

        Only instruction operands are used: scanning raw 4-byte windows finds bytes inside
        instructions and reports nonsense targets.
        """
        if self._refs is not None:
            return self._refs
        refs = defaultdict(list)
        self.md.skipdata = True
        for name, start, end, data in self.p10.sections:
            if name not in (".text", ".HOODLUM"):
                continue
            for insn in self.md.disasm(data, start):
                if insn.id == 0:
                    continue
                if insn.mnemonic in ("call", "jmp") or insn.mnemonic.startswith("j"):
                    continue
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp:
                        v = op.mem.disp & 0xFFFFFFFF
                        if in_game(v):
                            refs[v].append(insn.address)
                    elif op.type == X86_OP_IMM:
                        v = op.imm & 0xFFFFFFFF
                        if in_game(v) and not is_code10(v):
                            refs[v].append(insn.address)
        self._refs = refs
        return refs

    def refs_items(self, target):
        """Yield (referenced_address, function_start, instruction_site) for a data target.

        Only exact references are used. An instruction that addresses an array base plus a
        dynamic index says nothing about a particular element, and allowing nearby globals as
        bases makes an unrelated neighbour win the vote.
        """
        for base, sites in self.refs().items():
            if base != target:
                continue
            for site in sites:
                f = self.owner10(site)
                if f:
                    yield base, addr10(f), site


    def owner10(self, va):
        k = bisect.bisect_right(self.starts10, va) - 1
        if k < 0:
            return None
        f = self.f10[self.starts10[k]]
        return f if va < addr10(f) + int(f["size"]) else None

    def insns(self, which, va, size):
        key = (which, va, size)
        if key in self._cache:
            return self._cache[key]
        pe = self.p10 if which == 10 else self.p30
        out = []
        for insn in self.md.disasm(pe.read(va, min(max(size, 16), 8192)), va):
            t = token(insn)
            if t:
                out.append((insn.address, t, insn))
        self._cache[key] = out
        return out


def ghirda_functions():
    """Map from Ghidra Version Tracking, keeping only the best proposal per source."""
    sets = defaultdict(list)
    path = TMP / "vt_matches.csv"
    if not path.exists():
        return {}
    for r in csv.DictReader(open(path, encoding="utf-8-sig")):
        if r["type"] != "Function":
            continue
        sets[int(r["src"], 16)].append(r)
    out = {}
    for src, rs in sets.items():
        rs.sort(key=lambda r: (-float(r["confidence"]), -float(r["similarity"])))
        out[src] = rs[0]
    return out


def build_seeds(model, ghidra, include_propagated=True):
    seeds = {}
    sources = {}
    for v10, r in ghidra.items():
        v30 = int(r["dst"], 16)
        if v10 in model.f10 and v30 in model.f30:
            seeds[v10] = v30
            sources.setdefault(v10, []).append(("ghidra", float(r["similarity"])))
    path = TMP / "function_matches_ghidra.csv"
    if path.exists():
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            if not r["v30"]:
                continue
            s = float(r["score"])
            margin = s - float(r["second"])
            if s < 0.85 or margin < 0.10:
                continue
            # The matcher keys a HOODLUM trampoline by its real body; store the mapping under
            # both the trampoline address and the body so call sites are covered.
            v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
            if v10 in model.f10 and v30 in model.f30:
                if v10 in seeds and seeds[v10] != v30:
                    sources.setdefault(v10, []).append(("conflict-ghidra", s))
                else:
                    seeds[v10] = v30
                    sources.setdefault(v10, []).append(("ghidra-bounds", s))
            # Some inventory addresses are thunk starts whose body the matcher matched; the
            # call site must resolve to the body's 3.0 counterpart, not to a 3.0 thunk.
            if r.get("match10") and r["thunk"] == "yes":
                body10 = int(r["match10"], 16)
                if body10 in model.f10 and v30 in model.f30 and body10 not in seeds:
                    seeds[body10] = v30
                    sources.setdefault(body10, []).append(("thunk-body", s))
    path = TMP / "function_matches.csv"
    if path.exists():
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            if not r["v30"]:
                continue
            s = float(r["score"])
            if s < 0.90:
                continue
            v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
            if v10 in model.f10 and v30 in model.f30:
                if v10 in seeds and seeds[v10] != v30:
                    sources.setdefault(v10, []).append(("conflict-insns", s))
                    continue
                seeds[v10] = v30
                sources.setdefault(v10, []).append(("insns", s))
    path = TMP / "feature_matches.csv"
    if path.exists():
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            if not r["v30"] or float(r["sim"]) < 0.85 or float(r["margin"]) < 0.2:
                continue
            v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
            if v10 in model.f10 and v30 in model.f30:
                if v10 in seeds and seeds[v10] != v30:
                    sources.setdefault(v10, []).append(("conflict-features", float(r["sim"])))
                    continue
                seeds[v10] = v30
                sources.setdefault(v10, []).append(("features", float(r["sim"])))
    for v10, v30 in KNOWN.items():
        seeds[v10] = v30
        sources.setdefault(v10, []).append(("known", 1.0))
    path = TMP / "propagated_ghidra.csv"
    if include_propagated and path.exists():
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
            if v10 in seeds or v10 not in model.f10 or v30 not in model.f30:
                continue
            seeds[v10] = v30
            sources.setdefault(v10, []).append(("calls", 0.9))
    # Hand-checked pairs: call-graph fingerprints, masked byte patterns and 1.0 HOODLUM
    # trampolines whose body was identified by disassembly. They are kept in the repository so
    # the pipeline can be reproduced without the temporary matcher output.
    path = ROOT / "docs/port/manual_seeds.csv"
    if path.exists():
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
            # A reviewed seed may point at a verified body, patch site or global that Ghidra
            # did not describe, so accept any address inside the image with code or data.
            if not (is_code10(v10) or is_data10(v10)):
                continue
            if not (0x401000 <= v30 < 0xD29000):
                continue
            if v10 in seeds and seeds[v10] != v30:
                sources.setdefault(v10, []).append(("conflict-manual", 1.0))
            seeds[v10] = v30
            sources.setdefault(v10, []).append(("manual", 1.0))
    return seeds, sources


def addr10(f):
    return int(f["addr"], 16) if isinstance(f["addr"], str) else int(f["addr"])


def align(model, f10, v30):
    """Return (ins10, ins30, matching_blocks) for two functions."""
    t10 = model.insns(10, addr10(f10), int(f10["size"]))
    t30 = model.insns(30, v30, int(model.f30[v30]["size"]))
    a = [t for _, t, _ in t10]
    b = [t for _, t, _ in t30]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return t10, t30, sm.get_matching_blocks()


def translate(model, f10, v30, target):
    """Translate one address inside f10. Returns (kind, address, strong) or (None, 0, False)."""
    if addr10(f10) == target:
        return "func", v30, True
    t10, t30, blocks = align(model, f10, v30)
    idx = next((i for i, (a, _, _) in enumerate(t10) if a == target), None)
    in_insn = 0
    if idx is None:
        # A byte patch site can sit in the middle of an instruction (a jump, a literal). Match
        # the instruction that contains it and keep the same in-instruction offset.
        for i, (a, _, ins) in enumerate(t10):
            if a < target < a + ins.size:
                idx = i
                in_insn = target - a
                break
    if idx is None:
        return None, 0, False

    for blk in blocks:
        if blk.a <= idx < blk.a + blk.size:
            k = blk.b + (idx - blk.a)
            if k >= len(t30):
                return None, 0, False
            a30, _, ins30 = t30[k]
            a30 += in_insn
            if is_code10(target):
                if not (0x401000 <= a30 < 0x8B4000):
                    return None, 0, False
                # A call site must call the same mapped function, otherwise the alignment
                # can silently pick a different call in a function with many calls.
                i10 = t10[idx][2]
                if i10.mnemonic == "call" and ins30.mnemonic == "call":
                    c10, c30 = direct_call(i10), direct_call(ins30)
                    known = SET_SEEDS.get(c10)
                    if c10 and c30 and known and known == c30:
                        return "code", a30, True
                    if c10 and c30 and (known is None or known != c30):
                        return "code", a30, False
                return "code", a30, True
            ref = operand_value(ins30)
            if ref and is_data30(ref):
                return "data", ref, True
            return None, 0, False
    return None, 0, False


def direct_call(insn):
    if insn.mnemonic in ("call", "jmp") and insn.operands:
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if 0x401000 <= v < 0x857000:
                return v
    return 0


def main():
    global SET_SEEDS
    model = Model()
    print(f"functions 1.0 {len(model.f10)}, 3.0 {len(model.f30)}")
    ghidra = ghirda_functions()
    print(f"ghidra function proposals: {len(ghidra)}")
    seeds, sources = build_seeds(model, ghidra)
    SET_SEEDS = seeds
    print(f"seed functions: {len(seeds)}")

    inv = list(csv.DictReader(open(INVENTORY, encoding="utf-8-sig")))
    rows = []
    stats = Counter()
    for r in inv:
        target = int(r["Address"], 16)
        row = {"v10": r["Address"], "v30": "", "state": "missing", "kind": "",
               "function10": "", "function30": "", "sources": "", "refs": r["Refs"],
               "first": r["First"], "name": r["Entry"]}
        f = model.owner10(target) if is_code10(target) else None
        direct = seeds.get(target) if (is_code10(target) or is_data10(target)) else None
        manual_direct = direct and any(
            s == "manual" for s, _ in sources.get(target, [])
        )
        if manual_direct:
            # A reviewed seed for this exact address is authoritative: it may name a function
            # start, a verified body Ghidra did not split out, or an in-function patch site.
            if is_code10(target):
                is_func = target in model.f10
                row["kind"] = "func" if is_func else "code"
                if is_func:
                    row["function10"] = f"0x{target:08X}"
            else:
                row["kind"] = "data"
            row["v30"] = f"0x{direct:08X}"
            row["state"] = "confirmed"
            row["sources"] = "manual"
            stats[row["state"]] += 1
            rows.append(row)
            continue
        if f:
            row["function10"] = f"0x{addr10(f):08X}"
            v30 = seeds.get(addr10(f))
            if v30:
                kind, addr, strong = translate(model, f, v30, target)
                row["function30"] = f"0x{v30:08X}"
                if kind:
                    row["kind"] = kind
                    row["v30"] = f"0x{addr:08X}"
                    src = sources.get(addr10(f), [])
                    conf = [s for s, q in src if q >= 0.9]
                    manual = any(s == "manual" for s, _ in src)
                    conflict = any(s.startswith("conflict") for s, _ in src)
                    # Conflicting evidence must never yield a confirmed row on its own; a
                    # reviewed manual seed is allowed to override the conflict.
                    strong = strong and (manual or not conflict)
                    row["state"] = "confirmed" if (strong and (len(conf) >= 2 or manual)) else "single"
                    row["sources"] = "+".join(sorted({s for s, _ in src}))
        if not row["v30"] and target >= 0x8A4000:
            # data target: find a code reference in 1.0 and translate the operand
            row["kind"] = "data"
            votes = Counter()
            agrees = 0
            for base, func_start, site in model.refs_items(target):
                v30 = seeds.get(func_start)
                if not v30:
                    continue
                t10, t30, blocks = align(model, model.f10[func_start], v30)
                idx = next((i for i, (a, _, _) in enumerate(t10) if a == site), None)
                if idx is None:
                    continue
                for blk in blocks:
                    if blk.a <= idx < blk.a + blk.size:
                        k = blk.b + (idx - blk.a)
                        if k >= len(t30):
                            break
                        ref = operand_value(t30[k][2])
                        if ref and is_data30(ref):
                            votes[ref + (target - base)] += 1
                        break
            if votes:
                best, n = votes.most_common(1)[0]
                row["v30"] = f"0x{best:08X}"
                row["state"] = "confirmed" if n >= 2 else "single"
                row["sources"] = "xref"
        stats[row["state"]] += 1
        rows.append(row)

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    high = [r for r in rows if r["state"] == "confirmed"]
    with open(OUT_HIGH, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(high)
    print("states:", dict(stats))
    print(f"written {OUT} and {OUT_HIGH} ({len(high)})")


def find_data_refs(model, target):
    """[(function start, instruction site, delta)] for code that references target or an array
    containing it within 0x2000 bytes."""
    out = []
    text_start = 0x401000
    text = model.p10.read(text_start, 0x457000)
    for va in range(text_start, 0x857000 - 4):
        off = va - text_start
        if off + 4 > len(text):
            break
        v = struct.unpack_from("<I", text, off)[0]
        if not in_game(v):
            continue
        delta = target - v
        if 0 <= delta <= 0x2000:
            f = model.owner10(va)
            if f:
                out.append((int(f["addr"]), va, delta))
    return out


if __name__ == "__main__":
    main()
