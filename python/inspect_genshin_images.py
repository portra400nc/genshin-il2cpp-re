#!/usr/bin/env python3
"""Decode image and assembly membership for the matched Genshin build."""

import argparse
import struct
from pathlib import Path

from decode_genshin_strings import EXE_SHA256, METADATA_SHA256, decode_string, sha256


STARTUP_SHA256 = "66c684950af332966887cfd6f5263a05704230999ee290c27d5b3bdb8a713923"
HEADER_FILE_OFFSET = 0x27D3BD0
TYPE_COUNT = 88_904
IMAGE_COUNT = 75
MASK64 = (1 << 64) - 1


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def image_key(index: int) -> int:
    value = (((index * 0x32E5) ^ 0x43E2DEB7) * 0x27CBE870 + 0xCB287082F0) & MASK64
    return (((value >> 8) * 0x518C1F3A) + 0x59BCEA57) & 0xFFFFFFFF


def assembly_key(index: int) -> int:
    value = (((index * 0xD0C3 + 0x1DC9B916) ^ 0x38345B4C) * 0x260DA7D6) & MASK64
    value = (((value >> 19) * 0x3E7B45BA) + 0xE6CC8E163578) & MASK64
    return (value >> 20) & 0xFFFFFFFF


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
    image_bytes = (u32(header, 0x2C) + 0xDB9A4FDD) & 0xFFFFFFFF
    assembly_link_bytes = (u32(header, 0xDC) + 0xC3D3697A) & 0xFFFFFFFF
    type_bytes = (u32(header, 0xE0) + 0xE2F9B07D) & 0xFFFFFFFF
    if image_bytes != IMAGE_COUNT * 40 or assembly_link_bytes != IMAGE_COUNT * 16:
        raise ValueError("image and assembly-link table counts do not match")
    if type_bytes != TYPE_COUNT * 70:
        raise ValueError("type-definition count does not match")
    image_base = (u32(header, 0x20C) + 0xF134D80B) & 0xFFFFFFFF
    assembly_base = (u32(header, 0x78) + 0xE63A6EDB) & 0xFFFFFFFF
    assembly_link_base = (u32(header, 0x1B8) + 0xD2393C88) & 0xFFFFFFFF
    string_section = (u32(header, 0x184) + 0xBF9D4735) & 0xFFFFFFFF
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
            image_name_index = u32(image, 0x20) ^ key ^ 0x772FA51E
            image_name = decode_string(metadata, string_section, image_name_index)
            assembly_name_index = (u32(assembly, 8) - assembly_key(index) + 0xF9B62E3D) & 0xFFFFFFFF
            assembly_name = decode_string(metadata, string_section, assembly_name_index)
            if image_name.removesuffix(".dll") != assembly_name:
                raise ValueError(f"image {index} and assembly names disagree: {image_name}, {assembly_name}")
            link_key = (((index * 0x8F5B9FAF + 0x3B2F2A11) & 0xFFFFFFFF) ^ 0x151AADA5)
            linked_image_index = (u32(link, 8) - link_key + 0x93F6F2BD) & 0xFFFFFFFF
            if linked_image_index != index:
                raise ValueError(f"assembly {index} links to image {linked_image_index}")
            type_start = u32(image, 0x0C) ^ key ^ 0x38EAB186 ^ 0x4B1CB1C1
            type_count = ((u32(image, 0x14) + 0xAA3CAE09) & 0xFFFFFFFF) ^ key
            if type_start != end or type_start + type_count > TYPE_COUNT:
                raise ValueError(f"image {index} type range {type_start}+{type_count} does not follow {end}")
            end += type_count
            exported_start = ((u32(image, 4) + 0xC881EFAC) & 0xFFFFFFFF) ^ key
            exported_count = u32(image, 0x18) ^ key ^ 0x0F898FBE
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
        if (end != TYPE_COUNT - 2 or exported_end != 1351 or names[0] != "mscorlib.dll"
                or names[-1] != "Assembly-CSharp.dll"):
            raise ValueError("image ranges or endpoint names do not match the expected anchors")
        print(f"Verified {IMAGE_COUNT} matching image/assembly names and links; "
              f"contiguous type coverage: 0..{end - 1}; exported types: {exported_end}; "
              "two trailing unassigned type records")


if __name__ == "__main__":
    main()
