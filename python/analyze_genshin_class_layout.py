#!/usr/bin/env python3
"""Compare the three class headers captured by the Genshin v11 probe."""

import argparse
import re
import struct
from pathlib import Path


CAPTURE = re.compile(
    r"Genshin class layout probe: (System\.Object|System\.String|System\.Collections\.IEnumerator) "
    r"class 0x([0-9A-F]+) header ([0-9A-F]+) vtable\[(\d+)\] ([0-9A-F]*)"
)


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()

    captures = {}
    for match in CAPTURE.finditer(args.log.read_text(errors="replace")):
        name, address, header, slots, vtable = match.groups()
        if name in captures:
            raise ValueError(f"duplicate {name} capture")
        address = int(address, 16)
        header = bytes.fromhex(header)
        slots = int(slots)
        vtable = bytes.fromhex(vtable)
        if len(header) != 0xD0 or slots != min(u16(header, 0xBE), 8) or len(vtable) != slots * 8:
            raise ValueError(f"invalid {name} capture")
        captures[name] = (address, header, vtable)

    if set(captures) != {"System.Object", "System.String", "System.Collections.IEnumerator"}:
        raise ValueError("the three v11 class captures are required")

    object_address = captures["System.Object"][0]
    class_base = object_address & ~0xFFFFFFFF
    if any(address & ~0xFFFFFFFF != class_base for address, _, _ in captures.values()):
        raise ValueError("sample classes are not in the same 4 GiB region")

    def resolved(header: bytes, offset: int) -> str:
        relative = u32(header, offset)
        return f"{class_base + relative:#x}" if relative else "null"

    print("name                         class          image          methods        record      "
          "+A8        +AC        +B0        vt methods")
    for name, (address, header, vtable) in captures.items():
        print(f"{name:28} {address:013X} {u64(header, 0):013X} {u64(header, 0x20):013X} "
              f"{u64(header, 0x98):011X} {u32(header, 0xA8):08X} {u32(header, 0xAC):08X} "
              f"{u32(header, 0xB0):08X} {u16(header, 0xBE):3} {u16(header, 0xC2):7}")
        print("  vtable sample:", " ".join(f"{value:016X}" for value in struct.unpack(
            f"<{len(vtable) // 8}Q", vtable)) if vtable else "(none)")

    for name, (address, header, _) in captures.items():
        self_offset = address - class_base
        print(f"{name}: +A8 -> {resolved(header, 0xA8)}; "
              f"+AC -> {resolved(header, 0xAC)}; "
              f"+B0 -> {resolved(header, 0xB0)}")
        if u32(header, 0xA8) != self_offset or u32(header, 0xB0) != self_offset:
            raise ValueError(f"{name} self-offset anchors differ")
    if class_base + u32(captures["System.String"][1], 0xAC) != object_address:
        raise ValueError("String +AC does not resolve to Object")
    print("Observed: +A8 and +B0 resolve to self for all three; String +AC resolves to Object.")


if __name__ == "__main__":
    main()
