#!/usr/bin/env python3
"""Decode image and assembly membership for the matched Genshin build."""

import argparse
import struct
from pathlib import Path

from decode_genshin_strings import (
    EXE_SHA256,
    HEADER_FILE_OFFSET,
    METADATA_SHA256,
    decode_string,
    sha256,
    string_section,
)


STARTUP_SHA256 = "2a5fe7adbeb7cba81db69d7c62dee3536615e5b77efa0514c464e9c9e72d93c0"
TYPE_COUNT = 89_748
IMAGE_COUNT = 75
MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def s32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def image_table(header: bytes) -> int:
    return (u32(header, 0x150) + 0xAB9C4CF7) & MASK32


def image_key(index: int) -> int:
    value = ((index * 0xA351) ^ 0x63E6B5AA) * 0x2172B0FD & MASK64
    return ((value >> 8) * 0x3F783CCF + 0x2C34178B) & MASK32


def assembly_key(index: int) -> int:
    value = (((index * 0x78E7) ^ 0x72D2C88F) * 0x6300F877 + 0x6BBA1492) & MASK64
    return ((value ^ 0x7F9325D8) * 0x2EE4421A & MASK64) >> 10 & MASK32


def link_key(index: int) -> int:
    value = (index * 0x7D070ED9CC4 & MASK64) >> 14
    return (value * 0x330D1458 & MASK32) ^ 0x50DADEAE


def image_fields(image: bytes, index: int) -> tuple[int, int, int]:
    """Return the name string index, first type index and type count of a 40-byte image record."""
    key = image_key(index)
    name_index = ((u32(image, 0x10) + 0x814D27F6) & MASK32) ^ key
    type_start = u32(image, 0x18) ^ key ^ 0x351A07FF
    type_count = ((u32(image, 0x08) + 0xFAA1B862) & MASK32) ^ key
    return name_index, type_start, type_count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("startup_metadata", type=Path)
    parser.add_argument("image_indices", nargs="*", type=lambda value: int(value, 0))
    parser.add_argument("--verify-all", action="store_true")
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256 or sha256(args.metadata) != METADATA_SHA256:
        parser.error("EXE and global metadata do not match the inspected build")
    if sha256(args.startup_metadata) != STARTUP_SHA256:
        parser.error("startup metadata does not match the inspected build")
    if any(index < 0 or index >= IMAGE_COUNT for index in args.image_indices):
        parser.error("image indices must be from 0 to 74")

    with args.exe.open("rb") as exe:
        exe.seek(HEADER_FILE_OFFSET)
        header = exe.read(0x210)
    if len(header) != 0x210 or header[:4] != b"MHY\0":
        raise ValueError("embedded metadata header is missing")
    # The game floors the image-table size to whole 40-byte records; this build's size is 3003.
    image_bytes = (s32(header, 0x28) ^ 0x35DFAC98) & MASK64
    assembly_link_bytes = (u32(header, 0x19C) + 0xED4842C1) & MASK32
    type_bytes = (u32(header, 0x188) + 0xE580E3AE) & MASK32
    if image_bytes // 40 != IMAGE_COUNT or assembly_link_bytes != IMAGE_COUNT * 16:
        raise ValueError("image and assembly-link table counts do not match")
    if type_bytes != TYPE_COUNT * 70:
        raise ValueError("type-definition count does not match")
    image_base = image_table(header)
    assembly_base = (u32(header, 0x1E0) + 0xD9111CE5) & MASK32
    assembly_link_base = (s32(header, 0xE8) ^ 0x1021F0B9) & MASK64
    section = string_section(header)
    startup = args.startup_metadata.read_bytes()
    for base, stride in ((image_base, 40), (assembly_base, 44), (assembly_link_base, 16)):
        if base + IMAGE_COUNT * stride > len(startup):
            raise ValueError(f"startup table at 0x{base:x} extends past the file")

    end = 0
    exported_end = 0
    names = []
    with args.metadata.open("rb") as metadata:
        for index in range(IMAGE_COUNT):
            image = startup[image_base + 40 * index : image_base + 40 * (index + 1)]
            assembly = startup[assembly_base + 44 * index : assembly_base + 44 * (index + 1)]
            link = startup[assembly_link_base + 16 * index : assembly_link_base + 16 * (index + 1)]
            key = image_key(index)
            image_name_index, type_start, type_count = image_fields(image, index)
            image_name = decode_string(metadata, section, image_name_index)
            assembly_name_index = ((u32(assembly, 0x0C) + 0xF11FEE5C) & MASK32) ^ assembly_key(index)
            assembly_name = decode_string(metadata, section, assembly_name_index)
            if image_name.removesuffix(".dll") != assembly_name:
                raise ValueError(f"image {index} and assembly names disagree: {image_name}, {assembly_name}")
            linked_image_index = (u32(link, 8) - link_key(index) + 0x93A56980) & MASK32
            if linked_image_index != index:
                raise ValueError(f"assembly {index} links to image {linked_image_index}")
            if type_start != end or type_start + type_count > TYPE_COUNT:
                raise ValueError(f"image {index} type range {type_start}+{type_count} does not follow {end}")
            end += type_count
            exported_start = ((u32(image, 0x14) + 0xF262B145) & MASK32) ^ key
            exported_count = ((u32(image, 0x0C) + 0x864A7AEF) & MASK32) ^ key
            if exported_count:
                if exported_start != exported_end:
                    raise ValueError(f"image {index} exported-type range does not follow {exported_end}")
                exported_end += exported_count
            elif exported_start != 0xFFFFFFFF:
                raise ValueError(f"image {index} has no exported types but a non-sentinel start")
            names.append(image_name)
            if (not args.verify_all and not args.image_indices) or index in args.image_indices:
                print(f"{index}: {image_name} (types {type_start}..{end - 1}, count {type_count}; "
                      f"exported types {exported_count})")
    if args.verify_all:
        if (end != TYPE_COUNT - 2 or exported_end != 1352 or names[0] != "mscorlib.dll"
                or names[-1] != "Assembly-CSharp.dll"):
            raise ValueError("image ranges or endpoint names do not match the expected anchors")
        print(f"Verified {IMAGE_COUNT} matching image/assembly names and links; "
              f"contiguous type coverage: 0..{end - 1}; exported types: {exported_end}; "
              "two trailing unassigned type records")


if __name__ == "__main__":
    main()
