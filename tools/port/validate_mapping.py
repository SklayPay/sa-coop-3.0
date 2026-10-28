"""Validate docs/port/mapping.csv against the two executables.

Checks every confirmed row:
  * v30 lies inside a 3.0 section (not padding, not the 1.0 image);
  * a `func` row points at a Ghidra 3.0 function start;
  * a `data` row points into .rdata/.data/_TEXT_HA/_rwdseg (never into code);
  * a `code` row points into the 3.0 .text section.

usage:
  uv run --with capstone --with pefile --python 3.12 python tools/port/validate_mapping.py
"""
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from consolidate import Model, is_data30  # noqa: E402

ROOT = Path(r"C:\Users\Pc\Desktop\wibeProjects\sa-coop")
MAPPING = ROOT / "docs/port/mapping.csv"
CODE30 = ".text"


def main():
    model = Model()
    starts30 = set(model.starts30)
    sections = [(name, start, end) for name, start, end, _ in model.p30.sections]

    def section_of(va):
        for name, start, end in sections:
            if start <= va < end:
                return name
        return None

    rows = list(csv.DictReader(open(MAPPING, encoding="utf-8-sig")))
    errors = []
    counts = Counter()
    for r in rows:
        if r["state"] != "confirmed":
            continue
        counts[r["kind"] or "code"] += 1
        va = int(r["v30"], 16)
        sec = section_of(va)
        if sec is None:
            errors.append((r["v10"], r["v30"], r["kind"], "v30 outside every 3.0 section"))
            continue
        kind = r["kind"] or "code"
        if kind == "func":
            if va not in starts30:
                errors.append((r["v10"], r["v30"], kind, "not a Ghidra 3.0 function start"))
            if sec != CODE30:
                errors.append((r["v10"], r["v30"], kind, f"function in {sec}, not .text"))
        elif kind == "data":
            if not is_data30(va):
                errors.append((r["v10"], r["v30"], kind, f"data in {sec}"))
        elif kind == "code":
            if sec != CODE30:
                errors.append((r["v10"], r["v30"], kind, f"code site in {sec}"))
        else:
            errors.append((r["v10"], r["v30"], kind, "unknown kind"))

    print(f"confirmed: {sum(counts.values())} ({dict(counts)})")
    print(f"errors: {len(errors)}")
    for e in errors[:50]:
        print("  %s -> %s %s: %s" % e)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
