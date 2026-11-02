"""Vtable scan: locate virtual method tables in both images and their code-pointer arrays."""
import sys, struct, bisect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, is_code10  # noqa: E402

TEXT_RANGES_10 = ((0x401000, 0x857000), (0xCB1000, 0x12FB000), (0x1556000, 0x1577000))
DATA_RANGES_10 = ((0x858000, 0x8A4000), (0x8A4000, 0xC9E000), (0x1301000, 0x1556000))
TEXT_RANGES_30 = ((0x401000, 0x8A4000),)
DATA_RANGES_30 = ((0x8A5000, 0x913000), (0x913000, 0xD29000))


def is_code(v, ranges):
    return any(lo <= v < hi for lo, hi in ranges)


def is_data(v, ranges):
    return any(lo <= v < hi for lo, hi in ranges)


def arrays(pe, which):
    """[(base, [slot values])] for runs of four or more consecutive code pointers.

    Virtual method tables are the only dense runs of code pointers in a game image, so this
    finds them without any symbol information.
    """
    ranges = DATA_RANGES_10 if which == 10 else DATA_RANGES_30
    text = TEXT_RANGES_10 if which == 10 else TEXT_RANGES_30
    out = []
    for lo, hi in ranges:
        raw = pe.read(lo, hi - lo)
        n = len(raw) // 4
        vals = list(struct.unpack_from(f'<{n}I', raw, 0))
        i = 0
        while i < n:
            if not is_code(vals[i], text):
                i += 1
                continue
            j = i
            while j < n and is_code(vals[j], text):
                j += 1
            if j - i >= 4:
                out.append((lo + 4 * i, vals[i:j]))
            i = j
    return out


def identify(model, tables, base10, idx10, slots10, min_anchors=3, min_ratio=0.6):
    """Find the 3.0 array that lines up with this 1.0 vtable and read the slot at idx10.

    Every slot of the 1.0 table that is already confirmed fixes where the 3.0 table must hold
    its mapped counterpart. A candidate that satisfies most of them is the same table, and its
    slot at the same offset is the 3.0 address of the wanted method.
    """
    fwd_c = tables[0]
    anchors = [(j, fwd_c[v]) for j, v in enumerate(slots10) if v in fwd_c]
    if len(anchors) < min_anchors:
        return None, f'only {len(anchors)} anchored slots'
    best = None
    for base30, slots30 in arrays(model.p30, 30):
        for shift in range(-8, 9):
            good = bad = 0
            for j, w in anchors:
                k = j + shift
                if 0 <= k < len(slots30):
                    if slots30[k] == w:
                        good += 1
                    else:
                        bad += 1
            if good < min_anchors or good < min_ratio * len(anchors) or good <= bad:
                continue
            score = (good, -bad)
            if best is None or score > best[0]:
                best = (score, base30, shift, good, bad, len(anchors))
    if best is None:
        return None, f'no 3.0 table matches {len(anchors)} anchors'
    _, base30, shift, good, bad, total = best
    k = idx10 + shift
    slots30 = dict(arrays(model.p30, 30))[base30]
    if not (0 <= k < len(slots30)):
        return None, 'slot out of range'
    value = slots30[k]
    if value not in model.f30:
        return None, f'0x{value:08X} is not a known 3.0 function start'
    return (value, base30, shift, good, bad, total,
            f'vtable 0x{base30:08X} slot {k}: {good}/{total} anchored slots agree (shift {shift:+d})'), None


def main():
    m = Model()
    for which in (10, 30):
        pe = m.p10 if which == 10 else m.p30
        a = arrays(pe, which)
        slots = sum(len(s) for _, s in a)
        print(f'{which}: {len(a)} candidate arrays, {slots} pointers')
        big = sorted(a, key=lambda x: -len(x[1]))[:5]
        for base, s in big:
            print(f'   0x{base:08X} len={len(s)} first={s[0]:#x} last={s[-1]:#x}')
    a10 = arrays(m.p10, 10)
    print()
    import csv
    from pathlib import Path as P
    root = P(__file__).resolve().parents[2]
    fwd_c = {}
    for r in csv.DictReader(open(root / 'docs/port/mapping.csv', encoding='utf-8-sig')):
        if r['state'] == 'confirmed' and r['kind'] == 'func':
            fwd_c[int(r['v10'], 16)] = int(r['v30'], 16)
    tables = (fwd_c,)

    print('== missing virtual methods ==')
    for target in (0x6A3440, 0x6C4550, 0x6CAC10, 0x4B0C00, 0x4B4E80, 0x60EA90):
        spot = [(base, s.index(target), s) for base, s in a10 if target in s]
        if not spot:
            print(f'0x{target:08X}: not in any vtable')
            continue
        for base, i, s in spot:
            res, err = identify(m, tables, base, i, s)
            if res:
                value, base30, shift, good, bad, total, why = res
                print(f'0x{target:08X} (table 0x{base:08X} slot {i}) -> 0x{value:08X}   {why}')
            else:
                print(f'0x{target:08X} (table 0x{base:08X} slot {i}) -> ?  {err}')

    print()
    print('== self test: re-derive a confirmed virtual method ==')
    for target, want in ((0x7468E0, 0x780720), (0x563280, 0x57D370), (0x5A82C0, 0x5BDFE0)):
        spot = [(base, s.index(target), s) for base, s in a10 if target in s]
        if not spot:
            print(f'0x{target:08X}: not in any vtable (not virtual)')
            continue
        base, i, s = spot[0]
        trimmed = (dict(fwd_c),)
        del trimmed[0][target]
        res, err = identify(m, trimmed, base, i, s)
        if res:
            value = res[0]
            print(f'0x{target:08X} -> 0x{value:08X}  want 0x{want:08X}  '
                  f'{"OK" if value == want else "MISMATCH"}   {res[6]}')
        else:
            print(f'0x{target:08X} -> ?  {err}')


if __name__ == '__main__':
    main()