"""Do the structure offsets the mod reads still hold on 3.0?

The mod's SDK views the game's classes with explicit field offsets (shared/game/Game.h), so a
field that moved between builds would have the mod read and write the wrong memory. Two checks,
which answer different halves of the question:

1. Over every confirmed function pair, how often does each displacement appear in the 1.0 body
   and in the 3.0 body? This is the stronger check, because the instruction token that the
   matchers compare contains a `[reg+disp]` displacement: two instructions only line up when
   their offsets are the same, so an offset seen in a compared pair is one the alignment has
   already accepted. Stack frame accesses (`[esp+..]`, `[ebp+..]`) are excluded - those are
   locals, and the two compilers lay frames out differently.

2. Over the code of the whole image, the same histogram. The pairs only exercise part of the
   mod's offsets; this covers all of them, at the weaker claim that the offset is used at all.
   3.0 has somewhat more code, so counts run a little higher there; what matters is an offset
   that is common on 1.0 and near zero on 3.0, which is what a field that moved looks like.

3. The element sizes of the pools. CPool<T> allocates size * sizeof(T) and indexes with that
   stride, so the size appears in the code as an immediate (`imul eax, eax, 0x7C4`). A different
   sizeof would give a different constant.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/audit_offsets.py
"""

import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consolidate as C  # noqa: E402
from consolidate import Model  # noqa: E402

from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

# Every field the mod reaches for, from shared/game/Game.h and shared/game/Types.h.
MOD_OFFSETS = sorted(set([
    0x04, 0x14, 0x18, 0x1C, 0x22, 0x2F, 0x36,                     # CEntity / CPlaceable
    0x40, 0x44, 0x50, 0x8C, 0xFC,                                 # CPhysical
    0x428, 0x42C, 0x434, 0x43A, 0x460, 0x464, 0x484, 0x488,       # CVehicle
    0x494, 0x49C, 0x4A0, 0x4A4, 0x4C0, 0x4C8, 0x4F8, 0x590, 0x594, 0x59A,
    0x46C, 0x470, 0x474, 0x478, 0x47C, 0x480,                     # CPed
    0x530, 0x534, 0x540, 0x544, 0x548, 0x558, 0x55C, 0x58C, 0x598, 0x5A0,
    0x718, 0x71A, 0x71C, 0x72C, 0x72D, 0x756,
    0xB8, 0xBC, 0xDC, 0x14F, 0x150,                               # CPlayerInfo
    0x10E, 0x118, 0x119, 0x11A, 0x11B, 0x11C, 0x11D, 0x11E, 0x11F,  # CPad
    0x59, 0x174, 0x830,                                           # CCamera
]))

# The element sizes of the pools the mod indexes into (kPedPoolElemSize and friends).
POOL_SIZES = (0x7C4, 0xA18, 0x19C)

# An offset used at least this often and then found at under this share of the expected count is
# worth a look.
MIN_USES = 20
SUSPICIOUS = 0.4

# The executable sections that actually hold code. The 1.0 image is a SecuROM release whose later
# sections are virtual (zero filled), so only its main .text and the HOODLUM section hold code.
CODE_SECTIONS = {10: (".text", ".HOODLUM"), 30: (".text",)}


def disp_of(insn):
    """The structure displacement of the instruction, or None for a stack or address access."""
    if insn.id == 0:
        return None
    for op in insn.operands:
        if op.type == X86_OP_MEM and (op.mem.base or op.mem.index):
            base = insn.reg_name(op.mem.base) if op.mem.base else ""
            if base in ("esp", "ebp"):
                return None
            d = op.mem.disp
            if 0 < d < 0x2000:
                return d
    return None


def pairs(model):
    """Displacement counts over the confirmed function pairs."""
    rows = [r for r in csv.DictReader(open(C.ROOT / "docs/port/mapping.csv", encoding="utf-8-sig"))
            if r["state"] == "confirmed" and r["kind"] == "func"
            and r["function10"] and r["function30"]]
    c10, c30 = Counter(), Counter()
    compared = 0
    for r in rows:
        body10, _ = C.body_of(model, int(r["function10"], 16))
        v30 = int(r["function30"], 16)
        if body10 not in model.f10 or v30 not in model.f30:
            continue
        compared += 1
        for _, _, ins in model.insns(10, body10, int(model.f10[body10]["size"])):
            d = disp_of(ins)
            if d:
                c10[d] += 1
        for _, _, ins in model.insns(30, v30, int(model.f30[v30]["size"])):
            d = disp_of(ins)
            if d:
                c30[d] += 1
    return c10, c30, compared


def whole_image(model):
    """Structure displacements and pool sizes over all the code of both images."""
    disps, imms = {}, {}
    for which in (10, 30):
        c = Counter()
        p = Counter()
        pe = model.p10 if which == 10 else model.p30
        for name, start, _end, data in pe.sections:
            if name not in CODE_SECTIONS[which]:
                continue
            for insn in model.md.disasm(data, start):
                d = disp_of(insn)
                if d:
                    c[d] += 1
                if insn.id == 0:
                    continue
                for op in insn.operands:
                    if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) in POOL_SIZES:
                        p[op.imm & 0xFFFFFFFF] += 1
        disps[which] = c
        imms[which] = p
    return disps[10], disps[30], imms[10], imms[30]


def report(title, c10, c30, note):
    print(f"\n=== {title}")
    print(note)
    print(f"structure accesses: 1.0 {sum(c10.values())}, 3.0 {sum(c30.values())}")
    sus, seen = [], 0
    for d in MOD_OFFSETS:
        a, b = c10[d], c30[d]
        if a == 0:
            continue
        seen += 1
        if b == 0 or (a >= MIN_USES and b / a < SUSPICIOUS):
            sus.append(d)
            print(f"  0x{d:03X}: {a:5d} / {b:5d}   <-- used on 1.0, barely or not on 3.0")
        else:
            print(f"  0x{d:03X}: {a:5d} / {b:5d}")
    print(f"{seen} of the mod's {len(MOD_OFFSETS)} offsets appear")
    return sus


def pools(p10, p30):
    print("\n=== pool element sizes")
    print("(CPool<T> allocates size * sizeof(T); the constant is the stride)")
    sus = []
    for size in POOL_SIZES:
        a, b = p10[size], p30[size]
        flag = ""
        if a >= MIN_USES and b < a * SUSPICIOUS:
            flag = "   <-- used on 1.0, barely or not on 3.0"
            sus.append(size)
        print(f"  0x{size:X}: {a:5d} / {b:5d}{flag}")
    print(f"{len(POOL_SIZES) - len(sus)} of {len(POOL_SIZES)} pool sizes appear")
    return sus


def main():
    model = Model()
    model.md.skipdata = True

    c10, c30, compared = pairs(model)
    sus = report("confirmed pairs", c10, c30,
                 f"({compared} pairs; an offset seen here is one the alignment already accepted)")

    print("\nsweeping the code of both images ...")
    w10, w30, p10, p30 = whole_image(model)
    sus += report("whole image", w10, w30,
                  "(weaker: only says the offset is used at all, and covers every offset)")
    sus += pools(p10, p30)

    print(f"\nsuspicious: {[hex(d) for d in sorted(set(sus))] or 'none'}")
    return 1 if sus else 0


if __name__ == "__main__":
    sys.exit(main())
