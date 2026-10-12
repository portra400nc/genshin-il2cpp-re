#!/usr/bin/env python3
"""Validate the static generic argument lists in the matched Genshin EXE."""

import argparse
import collections
import json
import mmap
import struct
from pathlib import Path

from decode_genshin_strings import EXE_SHA256, sha256
from inspect_genshin_types import MAX_STATIC_TYPE_INDEX, TYPE_ARRAY_FILE_OFFSET, TYPE_ARRAY_VA


INSTANCE_FILE_OFFSET = 0x2342960
INSTANCE_COUNT = 69_146
DATA_SECTION_VA = 0x1454B3000
DATA_SECTION_FILE_OFFSET = 0x54B1800
DATA_SECTION_RAW_SIZE = 0x17BC00


def inspect(path: Path, selected: list[int], output: Path | None) -> None:
    if sha256(path) != EXE_SHA256:
        raise ValueError("EXE does not match the inspected Genshin build")
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        type_end_va = TYPE_ARRAY_VA + 16 * (MAX_STATIC_TYPE_INDEX + 1)
        arities = collections.Counter()
        examples = {}
        instances = [] if output is not None else None
        for index in range(INSTANCE_COUNT):
            arity, argv_va = struct.unpack_from("<QQ", data, INSTANCE_FILE_OFFSET + index * 16)
            argv_offset = DATA_SECTION_FILE_OFFSET + argv_va - DATA_SECTION_VA
            if not 1 <= arity <= 10 or argv_va % 8 or not (
                DATA_SECTION_FILE_OFFSET <= argv_offset
                and argv_offset + 8 * arity <= DATA_SECTION_FILE_OFFSET + DATA_SECTION_RAW_SIZE
            ):
                raise ValueError(f"generic instance {index} has invalid argument storage")
            arities[arity] += 1
            arguments = []
            for position in range(arity):
                type_va = struct.unpack_from("<Q", data, argv_offset + position * 8)[0]
                if not TYPE_ARRAY_VA <= type_va < type_end_va or (type_va - TYPE_ARRAY_VA) % 16:
                    raise ValueError(f"generic instance {index} argument {position} is not a type entry")
                arguments.append((type_va - TYPE_ARRAY_VA) // 16)
            if index in selected:
                examples[index] = arguments
            if instances is not None:
                instances.append(arguments)
        boundary = struct.unpack_from("<Q", data, INSTANCE_FILE_OFFSET + INSTANCE_COUNT * 16)[0]
        if boundary != 0:
            raise ValueError("generic instance table did not end at the expected boundary")
        print(f"Verified {INSTANCE_COUNT} generic argument lists; arities: {dict(sorted(arities.items()))}")
        for index in selected:
            if index < 0 or index >= INSTANCE_COUNT:
                raise ValueError(f"generic instance index {index} is out of range")
            parts = []
            for type_index in examples[index]:
                type_offset = TYPE_ARRAY_FILE_OFFSET + type_index * 16
                kind = data[type_offset + 0xA]
                parts.append(f"{type_index}:0x{kind:02x}")
            print(f"instance {index}: " + ", ".join(parts))
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps({"format": "genshin-generic-insts-v1",
                                          "exe_sha256": EXE_SHA256,
                                          "instances": instances}, separators=(",", ":")),
                              encoding="utf-8")
            print(f"Wrote {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("indices", nargs="*", type=lambda value: int(value, 0))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        inspect(args.exe, args.indices, args.output)
    except (OSError, ValueError, struct.error) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
