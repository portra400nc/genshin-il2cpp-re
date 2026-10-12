#!/usr/bin/env python3
"""Match v12 method records and vtable slots to the decoded Genshin metadata."""

import argparse
import json
import re
import struct
from pathlib import Path

from decode_genshin_strings import BODY_FILE_OFFSET, EXE_SHA256, METADATA_SHA256, sha256
from inspect_genshin_types import TYPE_STRIDE


HEADER = re.compile(
    r"Genshin (?:class|injector) layout probe: "
    r"(System\.Object|System\.Collections\.IEnumerator|UnityEngine\.MonoBehaviour) "
    r"class 0x([0-9A-F]+) header ([0-9A-F]+) vtable\[(\d+)\] ([0-9A-F]*)"
)
METHOD = re.compile(
    r"Genshin injector layout probe: "
    r"(System\.Object|System\.Collections\.IEnumerator|UnityEngine\.MonoBehaviour) "
    r"method\[(\d+)\] 0x([0-9A-F]+) ([0-9A-F]+)"
)
DETAILS = re.compile(
    r"Genshin injector details probe: "
    r"(System\.Object|System\.Collections\.IEnumerator|UnityEngine\.MonoBehaviour) "
    r"hierarchy\[(\d+)\] ([0-9A-F]+) metadata 0x([0-9A-F]+) ([0-9A-F]+)"
)
IMAGE = {
    "System.Object": "mscorlib.dll",
    "System.Collections.IEnumerator": "mscorlib.dll",
    "UnityEngine.MonoBehaviour": "UnityEngine.CoreModule.dll",
}


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("api", type=Path)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    log = args.log.read_text(errors="replace")
    api = json.loads(args.api.read_text())

    headers = {}
    for match in HEADER.finditer(log):
        name, address, raw, count, slots = match.groups()
        if name in headers:
            raise ValueError(f"duplicate {name} header")
        address, raw, count, slots = int(address, 16), bytes.fromhex(raw), int(count), bytes.fromhex(slots)
        if len(raw) != 0xD0 or len(slots) != count * 8 or count != min(u16(raw, 0xBE), 8):
            raise ValueError(f"invalid {name} header")
        headers[name] = (address, raw, slots)
    if set(headers) != set(IMAGE):
        raise ValueError("Object, IEnumerator, and MonoBehaviour headers are required")

    definitions = {}
    code_index = {}
    definitions_by_index = {}
    for image in api["images"]:
        for klass in image["types"]:
            definitions_by_index[klass["index"]] = klass
            full_name = ".".join(filter(None, (klass["namespace"], klass["name"])))
            if IMAGE.get(full_name) == image["name"]:
                definitions[full_name] = klass
            for method in klass["methods"]:
                if method["code_rva"] is not None:
                    code_index.setdefault(method["code_rva"], []).append(
                        f"{full_name}.{method['name']}#{method['index']}")
    if set(definitions) != set(IMAGE):
        raise ValueError("decoded API lacks a sampled class")

    def inheritance_depth(klass: dict) -> int:
        parent = klass["parent"]
        if parent is None:
            return 1
        return 1 + inheritance_depth(definitions_by_index[parent["definition"]])

    for name, (_, header, _) in headers.items():
        depth = inheritance_depth(definitions[name])
        if header[0xC5] != depth:
            raise ValueError(f"{name} class hierarchy depth differs")
        print(f"{name}: class+0xc5 hierarchy depth {depth} matches decoded parent chain")

    records = {name: [] for name in IMAGE}
    for match in METHOD.finditer(log):
        name, position, address, raw = match.groups()
        position, address, raw = int(position), int(address, 16), bytes.fromhex(raw)
        if len(raw) != 0x38 or position != len(records[name]):
            raise ValueError(f"invalid {name} method record order or size")
        records[name].append((address, raw))

    module_base = None
    for name, (class_address, _, _) in headers.items():
        expected = min(len(definitions[name]["methods"]), 16)
        if len(records[name]) != expected:
            raise ValueError(f"incomplete {name} method records")
        for position, (address, record) in enumerate(records[name]):
            method = definitions[name]["methods"][position]
            if position and address - records[name][position - 1][0] != 0x38:
                raise ValueError(f"{name} method record stride differs")
            if u64(record, 8) != class_address or u32(record, 0x10) != method["index"]:
                raise ValueError(f"{name} method owner or metadata index differs")
            if u16(record, 0x2C) != method["flags"] or record[0x2E] != len(method["parameters"]):
                raise ValueError(f"{name} method flags or parameter count differs")
            code = u64(record, 0)
            if method["code_rva"] is None:
                if code != 0:
                    raise ValueError(f"abstract {name} method has a code pointer")
            else:
                candidate_base = code - method["code_rva"]
                if module_base is None:
                    module_base = candidate_base
                if candidate_base != module_base:
                    raise ValueError(f"{name} method code pointer differs from metadata")
        print(f"{name}: {len(records[name])} contiguous 0x38-byte MethodInfo records match "
              "owner, index, flags, parameters, and code RVA")

    if module_base is None:
        raise ValueError("no native code pointer established the module base")
    print(f"Game module base from method records: {module_base:#x}")
    object_by_code = {u64(record, 0): record for _, record in records["System.Object"]}
    for name in ("System.Object", "UnityEngine.MonoBehaviour"):
        slots = headers[name][2]
        for index in range(len(slots) // 8):
            pointer = u64(slots, index * 8)
            matches = code_index.get(pointer - module_base, [])
            print(f"{name} vtable[{index}] {pointer:#x}: {', '.join(matches) or '(no metadata match)'}")
            if not matches:
                raise ValueError(f"{name} vtable slot {index} has no decoded method")
            if name == "System.Object" and (
                pointer not in object_by_code or u16(object_by_code[pointer], 0x2A) != index
            ):
                raise ValueError(f"Object vtable slot {index} differs from MethodInfo+0x2a")
    print("Object vtable slots also match their MethodInfo slot numbers at +0x2a.")

    if "Genshin injector details probe armed" in log:
        details = list(DETAILS.finditer(log))
        if len(details) != 3 or {match.group(1) for match in details} != set(IMAGE):
            raise ValueError("incomplete injector class details")
        metadata_bytes = None
        type_section = None
        if args.exe or args.metadata:
            if not args.exe or not args.metadata:
                raise ValueError("both --exe and --metadata are needed to check raw class records")
            if sha256(args.exe) != EXE_SHA256 or sha256(args.metadata) != METADATA_SHA256:
                raise ValueError("EXE or metadata differs from the inspected build")
            exe_bytes = args.exe.read_bytes()
            metadata_bytes = args.metadata.read_bytes()
            header_offset = 0x27D3BD0
            type_section = (u32(exe_bytes, header_offset + 0xB4) + 0xEC48AB9F) & 0xFFFFFFFF
        for match in details:
            name, sampled, raw, metadata_address, definition = match.groups()
            class_address, header, _ = headers[name]
            sample = bytes.fromhex(raw)
            definition = bytes.fromhex(definition)
            sampled = int(sampled)
            if sampled != header[0xC5] or len(sample) != sampled * 8 \
                    or int(metadata_address, 16) != u64(header, 0x98) \
                    or len(definition) != TYPE_STRIDE:
                raise ValueError(f"{name} class detail differs from its header")
            if metadata_bytes is not None:
                offset = BODY_FILE_OFFSET + type_section + definitions[name]["index"] * TYPE_STRIDE
                if definition != metadata_bytes[offset:offset + TYPE_STRIDE]:
                    raise ValueError(f"{name} native metadata record differs from the copied file")

            # 0x5156B0 allocates (metadata[0x40] + 0x38) modulo 256 pointers.
            # All three samples request zero bytes; the allocator can return an
            # address immediately before a later allocation. The observed
            # MethodInfo records do not define the meaning of class+0x48.
            count = (definition[0x40] + 0x38) & 0xFF
            if count != 0:
                raise ValueError(f"{name} class+0x48 metadata count is not zero")
            array = u64(header, 0x48)
            first_method = u64(sample, 0)
            method_count, remainder = divmod(first_method - array, 8)
            if remainder or method_count < 1 or method_count > 1024:
                raise ValueError(f"{name} class+0x48 did not alias a method allocation")
            owner = definitions[name]
            if name == "UnityEngine.MonoBehaviour":
                owner = definitions_by_index[owner["parent"]["definition"]]
            if method_count != len(owner["methods"]):
                raise ValueError(f"{name} class+0x48 method allocation count differs")
            for position in range(min(sampled, method_count)):
                if u64(sample, position * 8) != first_method + 0x38 * position:
                    raise ValueError(f"{name} class+0x48 method pointers are not contiguous")
            if name != "UnityEngine.MonoBehaviour":
                if array != u64(header, 0x20) or first_method != records[name][0][0]:
                    raise ValueError(f"{name} class+0x48 is not its own method array")
            elif sampled > method_count:
                first_code = owner["methods"][0]["code_rva"] + module_base
                if u64(sample, method_count * 8) != first_code:
                    raise ValueError("MonoBehaviour's fifth sample is not Behaviour's first method code")
            print(f"{name}: class+0x48 zero-byte allocation aliases {method_count} "
                  f"{owner['name']} method records; sampled length came from unrelated class+0xc5")
        if metadata_bytes is not None:
            print("All three native class metadata records match the copied metadata file.")


if __name__ == "__main__":
    main()
