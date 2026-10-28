"""Regenerate the kEntries block in src/client/shared/game/version/Addresses.cpp.

The mapping pipeline (consolidate.py) produces docs/port/mapping.csv. This script copies every
row whose state is "confirmed" into the C++ table, merges the v30 address into rows that already
exist (so hand-written byte patterns survive), and keeps the table sorted by the 1.0 address.

usage:
  uv run --python 3.12 python tools/port/gen_addresses.py           # preview
  uv run --python 3.12 python tools/port/gen_addresses.py --apply   # write Addresses.cpp
"""
import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
SOURCE = ROOT / "src/client/shared/game/version/Addresses.cpp"
MAPPING = ROOT / "docs/port/mapping.csv"

LINE = re.compile(
    r'^\s*\{\s*"(?P<name>[^"]*)",\s*'
    r'(?P<v10>0x[0-9A-Fa-f]+),\s*'
    r'(?P<v30>[^,]+),\s*'
    r'(?P<pattern>\{.*?\}),\s*'
    r'ResolveKind::(?P<kind>\w+)\s*\},?\s*$'
)


def load_existing(text):
    entries = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        v10 = int(m.group("v10"), 16)
        entries[v10] = {
            "name": m.group("name"),
            "v10": v10,
            "v30": int(m.group("v30"), 0) if m.group("v30").strip() not in ("0", "") else 0,
            "pattern": m.group("pattern"),
            "kind": m.group("kind"),
        }
    return entries


def safe_name(text):
    text = text.replace("\\", "/")
    text = text.replace('"', "")
    return text[:110]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    text = SOURCE.read_text(encoding="utf-8")
    entries = load_existing(text)
    before = len(entries)

    added = 0
    conflicts = 0
    for r in csv.DictReader(open(MAPPING, encoding="utf-8-sig")):
        if r["state"] != "confirmed" or not r["v30"]:
            continue
        v10, v30 = int(r["v10"], 16), int(r["v30"], 16)
        if v10 in entries:
            if entries[v10]["v30"] not in (0, v30):
                # A hand-written byte pattern is authoritative; an auto-generated row is not,
                # and must follow the reviewed mapping instead of pinning an older guess.
                if entries[v10]["pattern"] != "{}":
                    conflicts += 1
                    print(f"conflict {v10:08X}: table {entries[v10]['v30']:08X} vs mapping {v30:08X}", file=sys.stderr)
                    continue
            entries[v10]["v30"] = v30
            continue
        name = r["name"] or r["first"]
        entries[v10] = {
            "name": safe_name(name),
            "v10": v10,
            "v30": v30,
            "pattern": "{}",
            "kind": "Direct",
        }
        added += 1

    rows = []
    for e in sorted(entries.values(), key=lambda x: x["v10"]):
        rows.append(
            '    {{"{name}", 0x{v10:08X}, {v30}, {pattern}, ResolveKind::{kind}}},'.format(
                name=e["name"],
                v10=e["v10"],
                v30=f"0x{e['v30']:08X}" if e["v30"] else "0",
                pattern=e["pattern"],
                kind=e["kind"],
            )
        )

    block = (
        "constexpr Entry kEntries[] = {\n"
        "    // name                                     1.0 US      3.0         pattern                                      kind\n"
        + "\n".join(rows)
        + "\n};\n"
    )
    start = text.index("constexpr Entry kEntries[] = {")
    end = text.index("};", start) + 2
    updated = text[:start] + block + text[end:]

    print(f"existing {before}, added {added}, total {len(rows)}, conflicts {conflicts}")
    if args.apply:
        SOURCE.write_text(updated, encoding="utf-8")
        print(f"written {SOURCE}")
    else:
        print("preview only; pass --apply to write")


if __name__ == "__main__":
    main()
