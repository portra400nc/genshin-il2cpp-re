#!/usr/bin/env python3
"""Decode metadata strings for the inspected Genshin 7.2 build."""

import argparse
import hashlib
import struct
from pathlib import Path


EXE_SHA256 = "b3001fc110b63e0e0ce24a77386e71d0eefaffaae244ea0c72645a659cb5ea6e"
METADATA_SHA256 = "4ed10538735861ad87b027d30039e2afb92e334f1b4de4f643e17c9c79d19fd7"
HEADER_FILE_OFFSET = 0x2806360
BODY_FILE_OFFSET = 0x210
MASK64 = (1 << 64) - 1
ANCHORS = {
    0x08000000: "mscorlib",
    0x080003D4: "hidden_3",
    0x0900040D: "hidden_12",
    0x08000487: "hash_alg",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def string_section(header: bytes) -> int:
    return (struct.unpack_from("<I", header, 0x1C4)[0] + 0xB7F07125) & 0xFFFFFFFF


def decode_string(stream, string_section: int, index: int) -> str:
    if index == 0xFFFFFFFF:
        return ""
    offset = index & 0xFFFFFF
    length = index >> 24
    key = (0x6838EB6663769160 * offset - 0x54E2A947F9BBD4F0) & MASK64 ^ 0x49F2143B1E15D9FC
    key = 0x6D1C485921CA3D0F * key & MASK64
    stream.seek(BODY_FILE_OFFSET + string_section + offset)
    encoded = stream.read((length + 7) // 8 * 8)
    if len(encoded) != (length + 7) // 8 * 8:
        raise ValueError(f"string index 0x{index:08x} extends past the metadata file")
    decoded = bytearray()
    for pos in range(0, len(encoded), 8):
        block = struct.unpack_from("<Q", encoded, pos)[0]
        decoded.extend((block ^ key).to_bytes(8, "little"))
        key = (key + 0x7E3422D00C531C8C) & MASK64
    return decoded[:length].split(b"\0", 1)[0].decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("indices", nargs="*", type=lambda value: int(value, 0))
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256 or sha256(args.metadata) != METADATA_SHA256:
        parser.error("inputs do not match the inspected EXE and metadata build")

    with args.exe.open("rb") as exe:
        exe.seek(HEADER_FILE_OFFSET)
        header = exe.read(0x210)
    if len(header) != 0x210 or header[:4] != b"MHY\0":
        raise ValueError("embedded metadata header is missing")
    section = string_section(header)
    print(f"String section offset from metadata body: 0x{section:x}")

    with args.metadata.open("rb") as metadata:
        for index in args.indices or ANCHORS:
            value = decode_string(metadata, section, index)
            if not args.indices and value != ANCHORS[index]:
                raise ValueError(f"anchor 0x{index:08x} decoded as {value!r}")
            print(f"0x{index:08x} {value}")


if __name__ == "__main__":
    main()
