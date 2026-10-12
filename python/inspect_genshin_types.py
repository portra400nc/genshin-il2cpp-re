#!/usr/bin/env python3
"""Inspect type definitions in the matched September 2026 Genshin files."""

import argparse
import math
import struct
from pathlib import Path

from decode_genshin_strings import (
    BODY_FILE_OFFSET,
    EXE_SHA256,
    HEADER_FILE_OFFSET,
    METADATA_SHA256,
    decode_string,
    sha256,
)


TYPE_ARRAY_FILE_OFFSET = 0x2E1DA20
TYPE_ARRAY_VA = 0x142E1EA20
CODE_REGISTRATION_FILE_OFFSET = 0x22DD370
METHOD_POINTER_ARRAY_RVA = 0x2870B90
METHOD_POINTER_ARRAY_FILE_OFFSET = METHOD_POINTER_ARRAY_RVA - 0x1000
IL2CPP_CODE_RVA_START = 0x6C04000
IL2CPP_CODE_RVA_END = 0x19DA45B0
IL2CPP_CODE_FILE_BIAS = IL2CPP_CODE_RVA_START - 0x63B9A00
PARENT_TYPE_BIAS = 0xC28B6FE1
TYPE_FLAGS_BIAS = 0x4159BB8E
MAX_STATIC_TYPE_INDEX = 683_573
TYPE_STRIDE = 0x46
EXPECTED_TYPE_COUNT = 88_904
EXPECTED_METHOD_COUNT = 733_442
EXPECTED_FIELD_COUNT = 440_172
METHOD_START_XOR = 0x4D8127F2
METHOD_COUNT_BIAS = 0x12C6
FIELD_START_XOR = 0x29010897
FIELD_COUNT_XOR = 0x51A8
METHOD_STRIDE = 26
FIELD_STRIDE = 8
PARAMETER_STRIDE = 8
FIELD_TYPE_XOR = 0x2D27D873
FIELD_DEFAULT_TABLE_HEADER_OFFSET = 0x13C
FIELD_DEFAULT_TABLE_XOR = 0x593DE464
DEFAULT_VALUE_DATA_HEADER_OFFSET = 0xA0
DEFAULT_VALUE_DATA_XOR = 0x3F525210
FIELD_DEFAULT_STRIDE = 12
FIELD_DEFAULT_RECORD_COUNT = 75_548
FIELD_ATTRIBUTE_LITERAL = 0x40
FIELD_ATTRIBUTE_HAS_FIELD_RVA = 0x100
LITERAL_KINDS = {
    0x02: ("bool", "<?"),
    0x03: ("char", "<H"),
    0x04: ("sbyte", "<b"),
    0x05: ("byte", "<B"),
    0x06: ("int16", "<h"),
    0x07: ("uint16", "<H"),
    0x08: ("int32", "<i"),
    0x09: ("uint32", "<I"),
    0x0A: ("int64", "<q"),
    0x0B: ("uint64", "<Q"),
    0x0C: ("single", "<f"),
    0x0D: ("double", "<d"),
    0x0E: ("string", None),
}
ANCHORS = {
    28: ("Mono.Globalization.Unicode", "CodePointIndexer"),
    42: ("", "ExtenderType"),
    204: ("System", "Enum"),
    314: ("System", "Type"),
    371: ("System", "Object"),
    405: ("System", "ValueType"),
    545: ("System.Reflection", "FieldInfo"),
}


def member_ranges(record: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    method_start = struct.unpack_from("<I", record, 0x0C)[0] ^ METHOD_START_XOR
    method_count = (struct.unpack_from("<H", record, 0x30)[0] + METHOD_COUNT_BIAS) & 0xFFFF
    field_start = struct.unpack_from("<I", record, 0x1C)[0] ^ FIELD_START_XOR
    field_count = struct.unpack_from("<H", record, 0x38)[0] ^ FIELD_COUNT_XOR
    return (method_start, method_count), (field_start, field_count)


def method_details(metadata, string_section: int, method_section: int, method_index: int) -> tuple[str, int, int, int, int]:
    metadata.seek(BODY_FILE_OFFSET + method_section + METHOD_STRIDE * method_index)
    record = metadata.read(METHOD_STRIDE)
    if len(record) != METHOD_STRIDE:
        raise ValueError(f"method {method_index} extends past the metadata file")
    key = (((method_index * 0x68E83348BF73) ^ 0x73758947) + 0x5C439E5B) & 0xFFFFFFFF
    name_index = ((struct.unpack_from("<I", record, 0)[0] + 0xA52959D7) ^ key) & 0xFFFFFFFF
    name = "<unnamed>" if name_index == 0xFFFFFFFF else decode_string(metadata, string_section, name_index)
    parameter_count = ((record[0x18] - 0x1F) & 0xFF) ^ (key & 0xFF)
    return_type_index = struct.unpack_from("<I", record, 8)[0] ^ key ^ 0x3F7BDF39
    parameter_start = ((struct.unpack_from("<I", record, 4)[0] + 0xF0A05526) & 0xFFFFFFFF) ^ key
    flags = struct.unpack_from("<H", record, 0x16)[0] ^ (key & 0xFFFF) ^ 0x8F60
    return name, parameter_count, return_type_index, parameter_start, flags


def parameter_details(metadata, string_section: int, parameter_section: int, parameter_index: int) -> tuple[str, int]:
    metadata.seek(BODY_FILE_OFFSET + parameter_section + PARAMETER_STRIDE * parameter_index)
    record = metadata.read(PARAMETER_STRIDE)
    if len(record) != PARAMETER_STRIDE:
        raise ValueError(f"parameter {parameter_index} extends past the metadata file")
    scaled = ((parameter_index * 0xA291 + 0x48B5FFB1) ^ 0x19E1D47A) & 0xFFFFFFFFFFFFFFFF
    key = (((scaled * 0x56E732D7) & 0xFFFFFFFFFFFFFFFF) >> 21) + 0x7B48E804
    key &= 0xFFFFFFFF
    name_index = (((struct.unpack_from("<I", record, 4)[0] + 0x96D3F6A4) & 0xFFFFFFFF)
                  ^ key ^ 0x4CDBD093)
    type_index = struct.unpack_from("<I", record, 0)[0] ^ key ^ 0x31BF59F3
    name = "<unnamed>" if name_index == 0xFFFFFFFF else decode_string(metadata, string_section, name_index)
    return name, type_index


def field_key(field_index: int) -> int:
    scaled = ((field_index * 0x87DE) ^ 0x59B1DB19) & 0xFFFFFFFFFFFFFFFF
    return ((((scaled * 0x6CB83B74) & 0xFFFFFFFFFFFFFFFF) >> 16) + 0x540C1A0D) & 0xFFFFFFFF


def field_details(metadata, string_section: int, field_section: int, field_index: int) -> tuple[str, int]:
    metadata.seek(BODY_FILE_OFFSET + field_section + FIELD_STRIDE * field_index)
    record = metadata.read(FIELD_STRIDE)
    if len(record) != FIELD_STRIDE:
        raise ValueError(f"field {field_index} extends past the metadata file")
    key = field_key(field_index)
    type_index = struct.unpack_from("<I", record, 0)[0] ^ key ^ FIELD_TYPE_XOR
    name_index = (((struct.unpack_from("<I", record, 4)[0] + 0xA810CEF4) & 0xFFFFFFFF)
                  ^ key ^ 0x2D027B84)
    name = "<unnamed>" if name_index == 0xFFFFFFFF else decode_string(metadata, string_section, name_index)
    return name, type_index


def field_default_values(metadata, header: bytes, type_array: bytes) -> dict[int, tuple[str, object]]:
    """Map each literal field index to its (type name, value) from the field default-value table."""
    field_section = (struct.unpack_from("<I", header, 0x18C)[0] + 0xEBF0392C) & 0xFFFFFFFF
    table = struct.unpack_from("<I", header, FIELD_DEFAULT_TABLE_HEADER_OFFSET)[0] ^ FIELD_DEFAULT_TABLE_XOR
    data = struct.unpack_from("<I", header, DEFAULT_VALUE_DATA_HEADER_OFFSET)[0] ^ DEFAULT_VALUE_DATA_XOR
    metadata.seek(BODY_FILE_OFFSET + field_section)
    field_records = metadata.read(FIELD_STRIDE * EXPECTED_FIELD_COUNT)
    metadata.seek(BODY_FILE_OFFSET + table)
    records = metadata.read(FIELD_DEFAULT_STRIDE * EXPECTED_FIELD_COUNT)
    if len(field_records) != FIELD_STRIDE * EXPECTED_FIELD_COUNT:
        raise ValueError("field-definition table extends past the metadata file")
    values = {}
    previous = -1
    offset = 0
    # The table has no count; the game scans it linearly, and the next table breaks the ascending field order.
    while offset + FIELD_DEFAULT_STRIDE <= len(records):
        field_index, data_index, type_index = struct.unpack_from("<iii", records, offset)
        if not previous < field_index < EXPECTED_FIELD_COUNT:
            break
        previous = field_index
        offset += FIELD_DEFAULT_STRIDE
        field_type = (struct.unpack_from("<I", field_records, FIELD_STRIDE * field_index)[0]
                      ^ field_key(field_index) ^ FIELD_TYPE_XOR)
        field_flags = struct.unpack_from("<H", type_array, 16 * field_type + 8)[0]
        if not field_flags & FIELD_ATTRIBUTE_LITERAL:
            if not field_flags & FIELD_ATTRIBUTE_HAS_FIELD_RVA:
                raise ValueError(f"field {field_index} has a default-value record but is neither literal nor RVA data")
            continue
        kind = type_array[16 * type_index + 0xA]
        if kind not in LITERAL_KINDS:
            raise ValueError(f"literal field {field_index} has unsupported default-value kind {kind}")
        type_name, layout = LITERAL_KINDS[kind]
        metadata.seek(BODY_FILE_OFFSET + data + data_index)
        if layout is not None:
            size = struct.calcsize(layout)
            values[field_index] = (type_name, struct.unpack(layout, metadata.read(size))[0])
            continue
        length = struct.unpack("<i", metadata.read(4))[0]
        if length < 0:
            raise ValueError(f"literal field {field_index} has string length {length}")
        # The length counts UTF-16 code units (C# string.Length), not the UTF-8 bytes that follow.
        encoded = metadata.read(3 * length)
        text = []
        units = 0
        for character in encoded.decode("utf-8", errors="replace"):
            if units == length:
                break
            text.append(character)
            units += 1 + (ord(character) > 0xFFFF)
        value = "".join(text)
        if units != length or not encoded.startswith(value.encode("utf-8")):
            raise ValueError(f"literal field {field_index} string is not {length} UTF-16 units of UTF-8")
        values[field_index] = (type_name, value)
    if offset // FIELD_DEFAULT_STRIDE != FIELD_DEFAULT_RECORD_COUNT:
        raise ValueError(f"field default-value table has {offset // FIELD_DEFAULT_STRIDE} records, "
                         f"expected {FIELD_DEFAULT_RECORD_COUNT}")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("type_indices", nargs="*", type=lambda value: int(value, 0))
    parser.add_argument("--verify-all", action="store_true", help="decode and check every type record")
    parser.add_argument("--methods", action="store_true", help="show methods for the selected type indices")
    parser.add_argument("--parameters", action="store_true", help="show parameters with selected methods")
    parser.add_argument("--fields", action="store_true", help="show fields for the selected type indices")
    parser.add_argument("--parents", action="store_true", help="show parent type indices for selected types")
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256 or sha256(args.metadata) != METADATA_SHA256:
        parser.error("inputs do not match the inspected EXE and metadata build")
    if any(index < 0 for index in args.type_indices):
        parser.error("type indices must be nonnegative")
    if (args.methods or args.fields or args.parents) and not args.type_indices:
        parser.error("--methods, --fields, and --parents require at least one type index")
    if args.parameters and not args.methods:
        parser.error("--parameters requires --methods")

    with args.exe.open("rb") as exe:
        exe.seek(HEADER_FILE_OFFSET)
        header = exe.read(0x190)
        exe.seek(TYPE_ARRAY_FILE_OFFSET)
        type_array = exe.read(16 * 256)
        parent_type_array = b""
        if args.parents or args.verify_all:
            exe.seek(TYPE_ARRAY_FILE_OFFSET)
            parent_type_array = exe.read(16 * (MAX_STATIC_TYPE_INDEX + 1))
            if len(parent_type_array) != 16 * (MAX_STATIC_TYPE_INDEX + 1):
                raise ValueError("static Il2CppType array is truncated")
        exe.seek(CODE_REGISTRATION_FILE_OFFSET + 0x88)
        method_pointer_array_va = struct.unpack("<Q", exe.read(8))[0]
        if method_pointer_array_va != 0x140000000 + METHOD_POINTER_ARRAY_RVA:
            raise ValueError("code registration does not point to the expected method-pointer array")
        exe.seek(0x194E82D0 - IL2CPP_CODE_FILE_BIAS)
        if exe.read(7) != bytes.fromhex("48 39 d1 0f 94 c0 c3"):
            raise ValueError("System.Object.Equals(object) code does not compare two object pointers")
    if header[:4] != b"MHY\0" or len(type_array) != 16 * 256:
        raise ValueError("embedded metadata header or type array is missing")
    valid_kinds = sum(1 <= type_array[16 * i + 0xA] <= 0x1F for i in range(256))
    if valid_kinds < 240 or type_array[0x1A] != 0x1C or struct.unpack_from("<I", type_array, 16)[0] != 371:
        raise ValueError("static Il2CppType array did not pass its anchor checks")
    string_section = (struct.unpack_from("<I", header, 0x184)[0] + 0xBF9D4735) & 0xFFFFFFFF
    type_section = (struct.unpack_from("<I", header, 0xB4)[0] + 0xEC48AB9F) & 0xFFFFFFFF
    type_size = (struct.unpack_from("<I", header, 0xE0)[0] + 0xE2F9B07D) & 0xFFFFFFFF
    if type_size % TYPE_STRIDE:
        raise ValueError("decoded type-definition size is not a multiple of the record stride")
    type_count = type_size // TYPE_STRIDE
    if type_count != EXPECTED_TYPE_COUNT:
        raise ValueError(f"unexpected type-definition count: {type_count}")
    print(f"Il2CppType kinds valid in first 256 entries: {valid_kinds}")
    print(f"Type-definition offset from metadata body: 0x{type_section:x}")
    print(f"Type-definition count from metadata header: {type_count}")
    method_section = (struct.unpack_from("<I", header, 0x16C)[0] + 0xE33589AC) & 0xFFFFFFFF
    field_section = (struct.unpack_from("<I", header, 0x18C)[0] + 0xEBF0392C) & 0xFFFFFFFF
    parameter_section = struct.unpack_from("<I", header, 0x114)[0] ^ 0x3E5D33E6
    method_pointers = b""
    if args.methods or args.verify_all:
        with args.exe.open("rb") as exe:
            exe.seek(METHOD_POINTER_ARRAY_FILE_OFFSET)
            method_pointers = exe.read(8 * EXPECTED_METHOD_COUNT)
        if len(method_pointers) != 8 * EXPECTED_METHOD_COUNT:
            raise ValueError("method-pointer array extends past the EXE")

    with args.metadata.open("rb") as metadata:
        metadata.seek(BODY_FILE_OFFSET + type_section)
        records = metadata.read(type_size)
        if len(records) != type_size:
            raise ValueError("type-definition table extends past the metadata file")
        for type_index in args.type_indices or ANCHORS:
            if type_index >= type_count:
                raise ValueError(f"type index {type_index} extends past the type-definition table")
            record = records[TYPE_STRIDE * type_index : TYPE_STRIDE * (type_index + 1)]
            namespace_index = (struct.unpack_from("<I", record, 0)[0] + 0xBBB4CF40) & 0xFFFFFFFF
            name_index = (struct.unpack_from("<I", record, 0x24)[0] + 0xFBAD8E98) & 0xFFFFFFFF
            namespace = decode_string(metadata, string_section, namespace_index)
            name = decode_string(metadata, string_section, name_index)
            if not args.type_indices and (namespace, name) != ANCHORS[type_index]:
                raise ValueError(f"type index {type_index} decoded as {(namespace, name)!r}")
            print(f"{type_index}: {namespace + '.' if namespace else ''}{name}")
            if args.parents:
                parent_type_index = (struct.unpack_from("<I", record, 0x18)[0] + PARENT_TYPE_BIAS) & 0xFFFFFFFF
                if parent_type_index == 0xFFFFFFFF:
                    print("  parent: none")
                else:
                    kind = parent_type_array[16 * parent_type_index + 0xA]
                    parent_definition = (struct.unpack_from("<I", parent_type_array, 16 * parent_type_index)[0]
                                         if kind in (0x12, 0x1C) else None)
                    print(f"  parent type index: {parent_type_index} (kind {kind}, "
                          f"type definition {parent_definition if parent_definition is not None else 'generic'})")
            (method_start, method_count), (field_start, field_count) = member_ranges(record)
            if args.methods:
                for method_index in range(method_start, method_start + method_count):
                    name, parameter_count, return_type_index, parameter_start, flags = method_details(
                        metadata, string_section, method_section, method_index)
                    pointer = struct.unpack_from("<Q", method_pointers, 8 * method_index)[0]
                    method_rva = pointer - 0x140000000 if pointer else 0
                    print(f"  {method_index}: {name} ({parameter_count} params, return type {return_type_index}, "
                          f"flags 0x{flags:04x}, "
                          f"code RVA 0x{method_rva:x})")
                    if args.parameters:
                        for parameter_index in range(parameter_start, parameter_start + parameter_count):
                            parameter_name, parameter_type = parameter_details(
                                metadata, string_section, parameter_section, parameter_index)
                            print(f"    {parameter_index}: {parameter_name} (type {parameter_type})")
            if args.fields:
                for field_index in range(field_start, field_start + field_count):
                    print(f"  {field_index}: {field_details(metadata, string_section, field_section, field_index)[0]}")

        if args.verify_all:
            ends = {"methods": 0, "fields": 0}
            empty_names = 0
            parent_kinds = {0x12: 0, 0x15: 0, 0x1C: 0}
            parentless = 0
            type_flags_seen = set()
            for type_index in range(type_count):
                record = records[TYPE_STRIDE * type_index : TYPE_STRIDE * (type_index + 1)]
                type_flags = (struct.unpack_from("<I", record, 0x28)[0] - TYPE_FLAGS_BIAS) & 0xFFFFFFFF
                if type_flags & ~0x1FFFFF:
                    raise ValueError(f"type {type_index} has implausible attributes 0x{type_flags:x}")
                type_flags_seen.add(type_flags)
                name_index = (struct.unpack_from("<I", record, 0x24)[0] + 0xFBAD8E98) & 0xFFFFFFFF
                if not decode_string(metadata, string_section, name_index):
                    empty_names += 1
                parent_type_index = (struct.unpack_from("<I", record, 0x18)[0] + PARENT_TYPE_BIAS) & 0xFFFFFFFF
                if parent_type_index == 0xFFFFFFFF:
                    parentless += 1
                else:
                    if parent_type_index > MAX_STATIC_TYPE_INDEX:
                        raise ValueError(f"type {type_index} has out-of-range parent type index {parent_type_index}")
                    kind = parent_type_array[16 * parent_type_index + 0xA]
                    if kind not in parent_kinds:
                        raise ValueError(f"type {type_index} has unexpected parent type kind {kind}")
                    parent_kinds[kind] += 1
                    if kind in (0x12, 0x1C):
                        parent_definition = struct.unpack_from("<I", parent_type_array, 16 * parent_type_index)[0]
                        if parent_definition >= type_count:
                            raise ValueError(f"type {type_index} has out-of-range parent definition {parent_definition}")
                ranges = zip(("methods", "fields"), member_ranges(record))
                for kind, (start, count) in ranges:
                    if start == 0xFFFFFFFF:
                        if count:
                            raise ValueError(f"type {type_index} has {count} {kind} but no start")
                    elif start != ends[kind]:
                        raise ValueError(f"type {type_index} {kind} start {start} does not follow {ends[kind]}")
                    else:
                        ends[kind] += count
            print(f"Verified all {type_count} names and contiguous member ranges; "
                  f"empty names: {empty_names}; methods: {ends['methods']}; fields: {ends['fields']}")
            expected_type_flags = {
                371: 0x102001, 405: 0x102081, 204: 0x102081, 251: 0x102109,
                2209: 0x100101, 2279: 0x100101, 2377: 0x100009,
                2386: 0x100001, 2263: 0x100001,
            }
            for index, expected in expected_type_flags.items():
                record = records[TYPE_STRIDE * index : TYPE_STRIDE * (index + 1)]
                actual = (struct.unpack_from("<I", record, 0x28)[0] - TYPE_FLAGS_BIAS) & 0xFFFFFFFF
                if actual != expected:
                    raise ValueError(f"type {index} attributes 0x{actual:x} did not match 0x{expected:x}")
            print(f"Verified {len(expected_type_flags)} type-attribute anchors and "
                  f"{len(type_flags_seen)} distinct attribute values")
            def parent_definition(index: int) -> int | None:
                record = records[TYPE_STRIDE * index : TYPE_STRIDE * (index + 1)]
                parent_type_index = (struct.unpack_from("<I", record, 0x18)[0] + PARENT_TYPE_BIAS) & 0xFFFFFFFF
                if parent_type_index == 0xFFFFFFFF:
                    return None
                return struct.unpack_from("<I", parent_type_array, 16 * parent_type_index)[0]
            if [parent_definition(index) for index in (371, 405, 204, 251, 293, 211, 117)] != [
                None, 371, 405, 405, 371, 371, 371,
            ]:
                raise ValueError("System.Object, ValueType, Enum, and derived-type parent anchors disagree")
            print(f"Verified seven parent-type anchors and all parent references; "
                  f"no parent: {parentless}; class: {parent_kinds[0x1C]}; "
                  f"value type: {parent_kinds[0x12]}; generic instance: {parent_kinds[0x15]}")
            if ends["methods"] != EXPECTED_METHOD_COUNT:
                raise ValueError(f"method count {ends['methods']} does not match the pointer array")
            object_methods = [method_details(metadata, string_section, method_section, index)
                              for index in range(3869, 3876)]
            if [(name, count) for name, count, _, _, _ in object_methods] != [
                (".ctor", 0), ("Equals", 1), ("Equals", 2), ("Finalize", 0),
                ("GetHashCode", 0), ("GetType", 0), ("MemberwiseClone", 0),
            ]:
                raise ValueError(f"System.Object method names or parameter counts did not match: {object_methods!r}")
            with args.exe.open("rb") as exe:
                object_return_kinds = []
                for _, _, type_index, _, _ in object_methods:
                    exe.seek(TYPE_ARRAY_FILE_OFFSET + 16 * type_index + 0xA)
                    object_return_kinds.append(exe.read(1)[0])
            if object_return_kinds != [1, 2, 2, 1, 8, 0x12, 0x1C]:
                raise ValueError(f"System.Object return-type kinds did not match: {object_return_kinds!r}")
            print("Verified seven System.Object method-name, parameter-count, and return-type anchors")
            if [flags for _, _, _, _, flags in object_methods] != [
                0x1886, 0x01C6, 0x0096, 0x01C4, 0x01C6, 0x0086, 0x0084,
            ]:
                raise ValueError("System.Object method flags did not match expected static/virtual anchors")
            print("Verified seven System.Object method-flag anchors")
            object_method_rvas = [struct.unpack_from("<Q", method_pointers, 8 * index)[0] - 0x140000000
                                  for index in range(3869, 3876)]
            if object_method_rvas != [
                0x194D1110, 0x194E82D0, 0x194E82E0, 0x194E8320,
                0x194E8330, 0x194DD890, 0x194DDA30,
            ]:
                raise ValueError(f"System.Object method pointer anchors did not match: {object_method_rvas!r}")
            print("Verified seven System.Object method-pointer anchors")
            equals_parameters = [parameter_details(metadata, string_section, parameter_section, index)
                                 for index in (5743, 5744, 5745)]
            if equals_parameters != [("obj", 1), ("objA", 1), ("objB", 1)]:
                raise ValueError(f"System.Object.Equals parameters did not match: {equals_parameters!r}")
            print("Verified three System.Object.Equals parameter-name and type anchors")
            unicode_fields = [field_details(metadata, string_section, field_section, index)[0]
                              for index in range(75, 79)]
            if unicode_fields != ["ranges", "defaultIndex", "defaultCP", "TotalCount"]:
                raise ValueError(f"CodePointIndexer field names did not match: {unicode_fields!r}")
            print("Verified four CodePointIndexer field-name anchors")
            unnamed_methods = 0
            total_parameters = 0
            max_parameters = 0
            return_types = []
            next_parameter = 0
            for index in range(ends["methods"]):
                name, parameter_count, return_type_index, parameter_start, _ = method_details(
                    metadata, string_section, method_section, index)
                if not name:
                    raise ValueError(f"method {index} has an empty decoded name")
                unnamed_methods += name == "<unnamed>"
                total_parameters += parameter_count
                max_parameters = max(max_parameters, parameter_count)
                return_types.append(return_type_index)
                if parameter_count:
                    if parameter_start != next_parameter:
                        raise ValueError(f"method {index} parameter start {parameter_start} does not follow {next_parameter}")
                    next_parameter += parameter_count
                elif parameter_start != 0xFFFFFFFF:
                    raise ValueError(f"method {index} has zero parameters but start {parameter_start}")
            if max_parameters > 64:
                raise ValueError(f"implausible maximum parameter count: {max_parameters}")
            if next_parameter != total_parameters:
                raise ValueError("method parameter ranges do not match their total count")
            null_method_pointers = 0
            for index in range(ends["methods"]):
                pointer = struct.unpack_from("<Q", method_pointers, 8 * index)[0]
                if pointer == 0:
                    null_method_pointers += 1
                elif not 0x140000000 + IL2CPP_CODE_RVA_START <= pointer < 0x140000000 + IL2CPP_CODE_RVA_END:
                    raise ValueError(f"method {index} points outside the IL2CPP code section: 0x{pointer:x}")
            parameter_types = []
            empty_parameter_names = 0
            for index in range(next_parameter):
                name, type_index = parameter_details(metadata, string_section, parameter_section, index)
                empty_parameter_names += not name
                if name == "<unnamed>":
                    raise ValueError(f"parameter {index} has a sentinel name index")
                parameter_types.append(type_index)
            unnamed_fields = 0
            field_types = []
            for index in range(ends["fields"]):
                name, type_index = field_details(metadata, string_section, field_section, index)
                if not name:
                    raise ValueError(f"field {index} has an empty decoded name")
                unnamed_fields += name == "<unnamed>"
                field_types.append(type_index)
            with args.exe.open("rb") as exe:
                exe.seek(TYPE_ARRAY_FILE_OFFSET)
                type_array = exe.read(16 * (max(max(field_types), max(return_types), max(parameter_types)) + 1))
            if len(type_array) != 16 * (max(max(field_types), max(return_types), max(parameter_types)) + 1):
                raise ValueError("member type index extends past the static type array")
            for field_index, type_index in enumerate(field_types):
                kind = type_array[16 * type_index + 0xA]
                if not 1 <= kind <= 0x1F:
                    raise ValueError(f"field {field_index} has invalid type kind {kind}")
            for method_index, type_index in enumerate(return_types):
                kind = type_array[16 * type_index + 0xA]
                if not 1 <= kind <= 0x1F:
                    raise ValueError(f"method {method_index} has invalid return type kind {kind}")
            for parameter_index, type_index in enumerate(parameter_types):
                kind = type_array[16 * type_index + 0xA]
                if not 1 <= kind <= 0x1F:
                    raise ValueError(f"parameter {parameter_index} has invalid type kind {kind}")
            print(f"Verified all member names and field type kinds; unnamed methods: {unnamed_methods}; "
                  f"unnamed fields: {unnamed_fields}; highest field type index: {max(field_types)}; "
                  f"highest method return type index: {max(return_types)}; "
                  f"parameters: {total_parameters}; empty parameter names: {empty_parameter_names}; "
                  f"highest parameter type index: {max(parameter_types)}; "
                  f"max parameters per method: {max_parameters}; null method pointers: {null_method_pointers}")
            if ends["fields"] != EXPECTED_FIELD_COUNT:
                raise ValueError(f"field count {ends['fields']} does not match {EXPECTED_FIELD_COUNT}")
            defaults = field_default_values(metadata, header, parent_type_array)
            field_flags = [struct.unpack_from("<H", parent_type_array, 16 * type_index + 8)[0]
                           for type_index in field_types]
            literals = {index for index, flags in enumerate(field_flags) if flags & FIELD_ATTRIBUTE_LITERAL}
            if set(defaults) != literals:
                raise ValueError(f"{len(literals - set(defaults))} literal fields have no default value")
            rva_fields = sum(bool(flags & FIELD_ATTRIBUTE_HAS_FIELD_RVA) for flags in field_flags)
            if rva_fields != FIELD_DEFAULT_RECORD_COUNT - len(defaults):
                raise ValueError(f"{rva_fields} RVA-data fields do not match the non-literal default-value records")
            strings = sum(type_name == "string" for type_name, _ in defaults.values())
            if strings != 2038:
                raise ValueError(f"expected 2038 string constants, found {strings}")
            default_anchors = {
                555: ("TrueLiteral", ("string", "True")),
                556: ("FalseLiteral", ("string", "False")),
                3370: ("rfc1123Pattern", ("string", "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
                3382: ("CJKYearSuff", ("string", "年")),
                3383: ("CJKMonthSuff", ("string", "月")),
                3384: ("CJKDaySuff", ("string", "日")),
                1121: ("MaxValue", ("int32", 2147483647)),
                12031: ("AfterEverything", ("int32", 22)),
            }
            for index, (name, value) in default_anchors.items():
                actual = (field_details(metadata, string_section, field_section, index)[0], defaults[index])
                if actual != (name, value):
                    raise ValueError(f"field {index} default value {actual!r} did not match {(name, value)!r}")
            single_nan = defaults[1203]
            if single_nan[0] != "single" or not math.isnan(single_nan[1]):
                raise ValueError(f"Single.NaN decoded as {single_nan!r}")
            print(f"Verified {FIELD_DEFAULT_RECORD_COUNT} field default-value records: "
                  f"{len(defaults)} literal fields all covered, {strings} strings, "
                  f"{rva_fields} RVA-data records excluded, {len(default_anchors) + 1} value anchors")


if __name__ == "__main__":
    main()
