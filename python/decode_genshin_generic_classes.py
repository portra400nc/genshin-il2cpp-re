#!/usr/bin/env python3
"""Decode the generic definition and arguments of every generic-instance Il2CppType in the matched Genshin build.

A kind-0x15 Il2CppType stores an index into the runtime generic-class list.
The metadata initializer at RVA 0x53F750 builds that list in order from an
8-byte table in startup-metadata.dat: the generic type definition, then an
int32 generic-instance index. The table offset and length come from the
embedded header's +0x6C and +0xF0 fields.
"""

import argparse
import json
import struct
from pathlib import Path

from decode_genshin_strings import EXE_SHA256, HEADER_FILE_OFFSET, sha256
from inspect_genshin_images import STARTUP_SHA256, s32
from inspect_genshin_types import EXPECTED_TYPE_COUNT, MAX_STATIC_TYPE_INDEX, TYPE_ARRAY_FILE_OFFSET


M32 = 0xFFFFFFFF
GENERIC_INSTANCE_KIND = 0x15
KINDS_WITH_DEFINITION = (0x11, 0x12)

# Generic class index -> (definition, argument definitions), from the
# exporter's generic types, which the 7.1 build's Deck logs named: IList<UICharInfo>, IList<UILineInfo>,
# List<Dropdown.OptionData>, ExecuteEvents.EventFunction<ISelectHandler> and
# UnityEvent<Vector2>.
ANCHORS = {
    0xD44: (1250, [2718]),
    0xD59: (1250, [2719]),
    0x13A9: (1255, [3485]),
    0x164B: (3645, [3634]),
    0x1522: (2604, [2533]),
}


def type_entry(exe: bytes, index: int) -> tuple[int, int]:
    offset = TYPE_ARRAY_FILE_OFFSET + index * 16
    return exe[offset + 0xA], struct.unpack_from("<I", exe, offset)[0]


def reference(exe: bytes, index: int) -> dict:
    kind, data = type_entry(exe, index)
    result = {"index": index, "kind": kind}
    if kind in KINDS_WITH_DEFINITION:
        result["definition"] = data
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("startup_metadata", type=Path)
    parser.add_argument("generic_insts", type=Path, help="output of inspect_genshin_generic_insts.py --output")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256 or sha256(args.startup_metadata) != STARTUP_SHA256:
        parser.error("inputs do not match the inspected EXE and startup metadata build")

    exe = args.exe.read_bytes()
    startup = args.startup_metadata.read_bytes()
    instances = json.loads(args.generic_insts.read_text())["instances"]
    header = exe[HEADER_FILE_OFFSET : HEADER_FILE_OFFSET + 0x210]
    table = (s32(header, 0x6C) ^ 0x511D9E20) & M32
    count = (s32(header, 0xF0) >> 3) ^ 0x0C041BE3
    if table + 8 * count > len(startup):
        raise ValueError(f"generic class table at 0x{table:x} with {count} records extends past the file")

    def generic_class(index: int) -> tuple[int, list[int]]:
        if not 0 <= index < count:
            raise ValueError(f"generic class index {index} is outside the {count}-record table")
        definition, instance = struct.unpack_from("<Ii", startup, table + 8 * index)
        if definition >= EXPECTED_TYPE_COUNT or not 0 <= instance < len(instances):
            raise ValueError(f"generic class {index} has definition {definition} and instance {instance}")
        return definition, instances[instance]

    for index, (definition, arguments) in ANCHORS.items():
        actual_definition, actual_arguments = generic_class(index)
        actual = [type_entry(exe, argument)[1] for argument in actual_arguments]
        if (actual_definition, actual) != (definition, arguments):
            raise ValueError(f"generic class 0x{index:x} decoded as {actual_definition} with {actual}")

    types = {}
    for index in range(MAX_STATIC_TYPE_INDEX + 1):
        kind, data = type_entry(exe, index)
        if kind != GENERIC_INSTANCE_KIND:
            continue
        definition, arguments = generic_class(data)
        types[index] = {"generic_definition": definition, "arguments": [reference(exe, argument) for argument in arguments]}

    args.output.write_text(json.dumps({"format": "genshin-generic-types-v1", "exe_sha256": EXE_SHA256, "types": types}))
    print(f"Verified {len(ANCHORS)} anchors in the {count}-record generic class table")
    print(f"Decoded {len(types)} generic-instance types")


if __name__ == "__main__":
    main()
