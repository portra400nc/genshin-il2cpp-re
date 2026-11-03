#!/usr/bin/env python3
"""Decode metadata strings for the inspected September 2026 Genshin build."""

import argparse
import hashlib
import struct
from pathlib import Path


EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"
METADATA_SHA256 = "05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0"
HEADER_FILE_OFFSET = 0x27D3BD0
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


def decode_string(stream, string_section: int, index: int) -> str:
    if index == 0xFFFFFFFF:
        return ""
    offset = index & 0xFFFFFF
    length = index >> 24
    key = (0x694418957C890198 * offset & MASK64) ^ 0x55A357D81EF0E48B
    key = 0x5C2B4E660E2D0544 * key & MASK64
    stream.seek(BODY_FILE_OFFSET + string_section + offset)
    encoded = stream.read((length + 7) // 8 * 8)
    if len(encoded) != (length + 7) // 8 * 8:
        raise ValueError(f"string index 0x{index:08x} extends past the metadata file")
    decoded = bytearray()
    for pos in range(0, len(encoded), 8):
        block = struct.unpack_from("<Q", encoded, pos)[0]
        decoded.extend((block ^ key).to_bytes(8, "little"))
        key = (key + 0x6B0B40C349AE61E5) & MASK64
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
        header = exe.read(0x188)
    if len(header) != 0x188 or header[:4] != b"MHY\0":
        raise ValueError("embedded metadata header is missing")
    string_section = (struct.unpack_from("<I", header, 0x184)[0] + 0xBF9D4735) & 0xFFFFFFFF
    print(f"String section offset from metadata body: 0x{string_section:x}")

    with args.metadata.open("rb") as metadata:
        for index in args.indices or ANCHORS:
            value = decode_string(metadata, string_section, index)
            if not args.indices and value != ANCHORS[index]:
                raise ValueError(f"anchor 0x{index:08x} decoded as {value!r}")
            print(f"0x{index:08x} {value}")


if __name__ == "__main__":
    main()
