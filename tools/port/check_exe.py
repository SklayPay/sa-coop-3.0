#!/usr/bin/env python3
"""Print the GTA SA version of an executable, using the same signatures as GameVersion.cpp.

    uv run --python 3.12 python tools/port/check_exe.py "C:\\path\\gta_sa.exe"

Only reads the file; it does not run it or touch the game folder.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

# (1.0 US virtual address, expected little-endian dword) -> version name
SIGNATURES = (
    (0x82457C, 0x94BF, "GTA SA 1.0 US"),
    (0x8245BC, 0x94BF, "GTA SA 1.0 EU"),
    (0x8252FC, 0x94BF, "GTA SA 1.01 US"),
    (0x82533C, 0x94BF, "GTA SA 1.01 EU"),
    (0x85EC4A, 0x94BF, "GTA SA 3.0 (Steam/RGL)"),
    (0x858D21, 0x3539F633, "GTA SA NewSteam r1"),
    (0x858D51, 0x3539F633, "GTA SA NewSteam r2"),
    (0x858C61, 0x3539F633, "GTA SA NewSteam r2 LV"),
    (0x858501, 0x3539F633, "GTA SA RGL 1.0.22.0"),
)


class PeImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ValueError("not a PE file (missing MZ header)")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file (missing PE header)")
        self.nt = e_lfanew
        self.sections = struct.unpack_from("<H", self.data, self.nt + 6)[0]
        self.optional_size = struct.unpack_from("<H", self.data, self.nt + 20)[0]
        self.optional = self.nt + 24
        self.magic = struct.unpack_from("<H", self.data, self.optional)[0]
        if self.magic == 0x10B:
            self.image_base = struct.unpack_from("<I", self.data, self.optional + 28)[0]
            self.size_of_image = struct.unpack_from("<I", self.data, self.optional + 56)[0]
        elif self.magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", self.data, self.optional + 24)[0]
            self.size_of_image = struct.unpack_from("<I", self.data, self.optional + 56)[0]
        else:
            raise ValueError(f"unsupported optional-header magic 0x{self.magic:X}")

    def read_va(self, va: int, size: int) -> bytes:
        rva = va - self.image_base
        section_table = self.optional + self.optional_size
        for i in range(self.sections):
            off = section_table + i * 40
            virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", self.data, off + 8
            )
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                file_off = raw_ptr + (rva - virtual_address)
                if file_off + size > len(self.data):
                    raise ValueError(f"VA 0x{va:X} is outside the file")
                return self.data[file_off : file_off + size]
        raise ValueError(f"VA 0x{va:X} is not in any section")

    def read_u32(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    args = parser.parse_args()

    try:
        pe = PeImage(args.exe)
    except (OSError, ValueError) as exc:
        print(f"{args.exe}: {exc}", file=sys.stderr)
        return 2

    digest = hashlib.sha256(pe.data).hexdigest().upper()
    print(f"path:        {args.exe}")
    print(f"size:        {len(pe.data)} bytes")
    print(f"sha256:      {digest}")
    print(f"image base:  0x{pe.image_base:X}")
    print(f"image size:  0x{pe.size_of_image:X}")

    found = None
    for va, expected, name in SIGNATURES:
        try:
            actual = pe.read_u32(va)
        except ValueError:
            actual = None
        match = actual == expected
        print(f"0x{va:08X}: 0x{actual:08X} (expected 0x{expected:08X})  {'OK' if match else ''}"
              if actual is not None else f"0x{va:08X}: unavailable")
        if match and found is None:
            found = name

    if found is None:
        print("version:     unknown")
        return 1
    print(f"version:     {found}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
