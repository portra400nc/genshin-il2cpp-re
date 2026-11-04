#!/usr/bin/env python3
"""Inspect type definitions in the matched Genshin 7.2 files."""

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
    string_section,
)


TYPE_ARRAY_FILE_OFFSET = 0x2E61B80
TYPE_ARRAY_VA = 0x142E63580
CODE_REGISTRATION_FILE_OFFSET = 0x22F91D0
CODE_REGISTRATION_METHOD_POINTERS = 0x18
METHOD_POINTER_ARRAY_RVA = 0x28A67B0
METHOD_POINTER_ARRAY_FILE_OFFSET = METHOD_POINTER_ARRAY_RVA - 0x1A00
IL2CPP_CODE_RVA_START = 0x6D2B000
IL2CPP_CODE_RVA_END = 0x1A3FFAF0
IL2CPP_CODE_FILE_BIAS = IL2CPP_CODE_RVA_START - 0x64D4000
MAX_STATIC_TYPE_INDEX = 690_944
TYPE_STRIDE = 0x46
EXPECTED_TYPE_COUNT = 89_748
EXPECTED_METHOD_COUNT = 741_021
EXPECTED_FIELD_COUNT = 445_462
METHOD_STRIDE = 26
FIELD_STRIDE = 8
PARAMETER_STRIDE = 8
FIELD_DEFAULT_STRIDE = 12
FIELD_DEFAULT_RECORD_COUNT = 76_320
FIELD_ATTRIBUTE_LITERAL = 0x40
FIELD_ATTRIBUTE_HAS_FIELD_RVA = 0x100
M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
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


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def s32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def type_section(header: bytes) -> tuple[int, int]:
    """Return the type-definition table's body offset and byte length."""
    return (s32(header, 0x34) ^ 0x0557E082) & M32, (u32(header, 0x188) + 0xE580E3AE) & M32


def method_section(header: bytes) -> int:
    return (s32(header, 0x48) ^ 0x4CE0F588) & M32


def field_section(header: bytes) -> int:
    return (s32(header, 0x1C8) ^ 0x01AF207A) & M32


def parameter_section(header: bytes) -> int:
    return (s32(header, 0xC0) + 0xEF2E6C51) & M32


def type_names(record: bytes) -> tuple[int, int]:
    """Return the namespace and name string indices of a type-definition record."""
    return (u32(record, 0x10) + 0xF7A6BD0E) & M32, (u32(record, 0x18) + 0xCFF1BA1A) & M32


# No instruction carries the parent and flags constants; they come from the Object, ValueType, Enum and Int32 anchors.
def type_parent(record: bytes) -> int:
    return u32(record, 0x00) ^ 0x383F0947


def type_flags(record: bytes) -> int:
    return (u32(record, 0x08) - 0x45258EF9) & M32


def member_ranges(record: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    method_start = (u32(record, 0x04) + 0xE31EC02A) & M32
    method_count = struct.unpack_from("<H", record, 0x3C)[0] ^ 0x7182
    field_start = u32(record, 0x2C) ^ 0x4B3258A4
    field_count = struct.unpack_from("<H", record, 0x38)[0] ^ 0x21EC
    return (method_start, method_count), (field_start, field_count)


def method_key(method_index: int) -> int:
    value = (((method_index * 0xB0BB) ^ 0x6EB052E1) * 0x6695B47A & M64) >> 13
    return ((value * 0x78F2AF5D + 0x11ECF7A9584B0B66) & M64) >> 16 & M32


def method_details(metadata, strings: int, section: int, method_index: int) -> tuple[str, int, int, int, int]:
    metadata.seek(BODY_FILE_OFFSET + section + METHOD_STRIDE * method_index)
    record = metadata.read(METHOD_STRIDE)
    if len(record) != METHOD_STRIDE:
        raise ValueError(f"method {method_index} extends past the metadata file")
    key = method_key(method_index) ^ 0x92462677
    inverse_key = key ^ M32
    name_index = ((u32(record, 4) ^ 0x2DBC268D) + key + 1) & M32
    name = "<unnamed>" if name_index == M32 else decode_string(metadata, strings, name_index)
    parameter_count = (record[0x18] - inverse_key + 0x1A) & 0xFF
    return_type_index = ((u32(record, 0) ^ 0x2E54C6EB) + key + 1) & M32
    parameter_start = (u32(record, 8) + key + 0xCBB1D910) & M32
    flags = (struct.unpack_from("<H", record, 0x16)[0] - inverse_key + 0x26E0) & 0xFFFF
    return name, parameter_count, return_type_index, parameter_start, flags


def parameter_details(metadata, strings: int, section: int, parameter_index: int) -> tuple[str, int]:
    metadata.seek(BODY_FILE_OFFSET + section + PARAMETER_STRIDE * parameter_index)
    record = metadata.read(PARAMETER_STRIDE)
    if len(record) != PARAMETER_STRIDE:
        raise ValueError(f"parameter {parameter_index} extends past the metadata file")
    scaled = ((parameter_index * 0xB135 + 0x4C18A44D) & M64) ^ 0x45F490A1
    key = ((scaled * 0x3C0B26CB & M64) >> 8) + 0x3A15E734 & M32
    name_index = ((u32(record, 4) + 0xA2BADD59) & M32) ^ key ^ 0x15C329C1
    type_index = u32(record, 0) ^ key ^ 0x7F4A5346
    name = "<unnamed>" if name_index == M32 else decode_string(metadata, strings, name_index)
    return name, type_index


def field_key(field_index: int) -> int:
    scaled = (((field_index * 0xB3D6) & M64) ^ 0x3B1F6E2F) * 0x226AA767 & M64
    return (((scaled + 0x49AFA280E6) & M64) >> 8) * 0x4A8CF52F + 0x87CB08AD & M32


def field_type_index(record: bytes, field_index: int) -> int:
    return ((u32(record, 4) + 0xAFCA0402) & M32) ^ field_key(field_index)


def field_details(metadata, strings: int, section: int, field_index: int) -> tuple[str, int]:
    metadata.seek(BODY_FILE_OFFSET + section + FIELD_STRIDE * field_index)
    record = metadata.read(FIELD_STRIDE)
    if len(record) != FIELD_STRIDE:
        raise ValueError(f"field {field_index} extends past the metadata file")
    name_index = ((u32(record, 0) + 0xD622CC8A) & M32) ^ field_key(field_index)
    name = "<unnamed>" if name_index == M32 else decode_string(metadata, strings, name_index)
    return name, field_type_index(record, field_index)


def field_default_values(metadata, header: bytes, type_array: bytes) -> dict[int, tuple[str, object]]:
    """Map each literal field index to its (type name, value) from the field default-value table."""
    table = (s32(header, 0xB4) ^ 0x1926D64A) & M32
    table_bytes = (s32(header, 0x1B4) ^ 0x2427FA8C) & M32
    data = (s32(header, 0x13C) + 0x8722DF9F) & M32
    # The game floors the size to whole records; this build's size is two bytes past the last one.
    if table_bytes // FIELD_DEFAULT_STRIDE != FIELD_DEFAULT_RECORD_COUNT:
        raise ValueError(f"field default-value table holds {table_bytes} bytes")
    table_bytes = FIELD_DEFAULT_STRIDE * FIELD_DEFAULT_RECORD_COUNT
    metadata.seek(BODY_FILE_OFFSET + field_section(header))
    field_records = metadata.read(FIELD_STRIDE * EXPECTED_FIELD_COUNT)
    metadata.seek(BODY_FILE_OFFSET + table)
    records = metadata.read(table_bytes)
    if len(field_records) != FIELD_STRIDE * EXPECTED_FIELD_COUNT or len(records) != table_bytes:
        raise ValueError("field-definition or default-value table extends past the metadata file")
    values = {}
    previous = -1
    for offset in range(0, table_bytes, FIELD_DEFAULT_STRIDE):
        field_index, data_index, type_index = struct.unpack_from("<iii", records, offset)
        if not previous < field_index < EXPECTED_FIELD_COUNT:
            raise ValueError(f"default-value record {offset // FIELD_DEFAULT_STRIDE} breaks the ascending field order")
        previous = field_index
        field_type = field_type_index(field_records[FIELD_STRIDE * field_index:FIELD_STRIDE * (field_index + 1)], field_index)
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
        header = exe.read(0x210)
        exe.seek(TYPE_ARRAY_FILE_OFFSET)
        type_array = exe.read(16 * 256)
        parent_type_array = b""
        if args.parents or args.verify_all:
            exe.seek(TYPE_ARRAY_FILE_OFFSET)
            parent_type_array = exe.read(16 * (MAX_STATIC_TYPE_INDEX + 1))
            if len(parent_type_array) != 16 * (MAX_STATIC_TYPE_INDEX + 1):
                raise ValueError("static Il2CppType array is truncated")
        exe.seek(CODE_REGISTRATION_FILE_OFFSET + CODE_REGISTRATION_METHOD_POINTERS)
        method_pointer_array_va = struct.unpack("<Q", exe.read(8))[0]
        if method_pointer_array_va != 0x140000000 + METHOD_POINTER_ARRAY_RVA:
            raise ValueError("code registration does not point to the expected method-pointer array")
        exe.seek(0x19B42700 - IL2CPP_CODE_FILE_BIAS)
        if exe.read(7) != bytes.fromhex("48 39 d1 0f 94 c0 c3"):
            raise ValueError("System.Object.Equals(object) code does not compare two object pointers")
    if header[:4] != b"MHY\0" or len(type_array) != 16 * 256:
        raise ValueError("embedded metadata header or type array is missing")
    valid_kinds = sum(1 <= type_array[16 * i + 0xA] <= 0x1F for i in range(256))
    if valid_kinds < 240 or type_array[0x1A] != 0x1C or struct.unpack_from("<I", type_array, 16)[0] != 371:
        raise ValueError("static Il2CppType array did not pass its anchor checks")
    strings = string_section(header)
    types, type_size = type_section(header)
    if type_size % TYPE_STRIDE:
        raise ValueError("decoded type-definition size is not a multiple of the record stride")
    type_count = type_size // TYPE_STRIDE
    if type_count != EXPECTED_TYPE_COUNT:
        raise ValueError(f"unexpected type-definition count: {type_count}")
    print(f"Il2CppType kinds valid in first 256 entries: {valid_kinds}")
    print(f"Type-definition offset from metadata body: 0x{types:x}")
    print(f"Type-definition count from metadata header: {type_count}")
    methods = method_section(header)
    fields = field_section(header)
    parameters = parameter_section(header)
    method_pointers = b""
    if args.methods or args.verify_all:
        with args.exe.open("rb") as exe:
            exe.seek(METHOD_POINTER_ARRAY_FILE_OFFSET)
            method_pointers = exe.read(8 * EXPECTED_METHOD_COUNT)
        if len(method_pointers) != 8 * EXPECTED_METHOD_COUNT:
            raise ValueError("method-pointer array extends past the EXE")

    with args.metadata.open("rb") as metadata:
        metadata.seek(BODY_FILE_OFFSET + types)
        records = metadata.read(type_size)
        if len(records) != type_size:
            raise ValueError("type-definition table extends past the metadata file")
        for type_index in args.type_indices or ANCHORS:
            if type_index >= type_count:
                raise ValueError(f"type index {type_index} extends past the type-definition table")
            record = records[TYPE_STRIDE * type_index : TYPE_STRIDE * (type_index + 1)]
            namespace_index, name_index = type_names(record)
            namespace = decode_string(metadata, strings, namespace_index)
            name = decode_string(metadata, strings, name_index)
            if not args.type_indices and (namespace, name) != ANCHORS[type_index]:
                raise ValueError(f"type index {type_index} decoded as {(namespace, name)!r}")
            print(f"{type_index}: {namespace + '.' if namespace else ''}{name}")
            if args.parents:
                parent_type_index = type_parent(record)
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
                        metadata, strings, methods, method_index)
                    pointer = struct.unpack_from("<Q", method_pointers, 8 * method_index)[0]
                    method_rva = pointer - 0x140000000 if pointer else 0
                    print(f"  {method_index}: {name} ({parameter_count} params, return type {return_type_index}, "
                          f"flags 0x{flags:04x}, "
                          f"code RVA 0x{method_rva:x})")
                    if args.parameters:
                        for parameter_index in range(parameter_start, parameter_start + parameter_count):
                            parameter_name, parameter_type = parameter_details(
                                metadata, strings, parameters, parameter_index)
                            print(f"    {parameter_index}: {parameter_name} (type {parameter_type})")
            if args.fields:
                for field_index in range(field_start, field_start + field_count):
                    print(f"  {field_index}: {field_details(metadata, strings, fields, field_index)[0]}")

        if args.verify_all:
            ends = {"methods": 0, "fields": 0}
            empty_names = 0
            parent_kinds = {0x12: 0, 0x15: 0, 0x1C: 0}
            parentless = 0
            type_flags_seen = set()
            for type_index in range(type_count):
                record = records[TYPE_STRIDE * type_index : TYPE_STRIDE * (type_index + 1)]
                flags = type_flags(record)
                if flags & ~0x1FFFFF:
                    raise ValueError(f"type {type_index} has implausible attributes 0x{flags:x}")
                type_flags_seen.add(flags)
                name_index = type_names(record)[1]
                if not decode_string(metadata, strings, name_index):
                    empty_names += 1
                parent_type_index = type_parent(record)
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
                2206: 0x100101, 2276: 0x100101, 2374: 0x100009,
                2383: 0x100001, 2260: 0x100001,
            }
            for index, expected in expected_type_flags.items():
                record = records[TYPE_STRIDE * index : TYPE_STRIDE * (index + 1)]
                actual = type_flags(record)
                if actual != expected:
                    raise ValueError(f"type {index} attributes 0x{actual:x} did not match 0x{expected:x}")
            print(f"Verified {len(expected_type_flags)} type-attribute anchors and "
                  f"{len(type_flags_seen)} distinct attribute values")
            def parent_definition(index: int) -> int | None:
                record = records[TYPE_STRIDE * index : TYPE_STRIDE * (index + 1)]
                parent_type_index = type_parent(record)
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
            object_methods = [method_details(metadata, strings, methods, index)
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
                0x19B2B4B0, 0x19B42700, 0x19B42710, 0x19B42750,
                0x19B42760, 0x19B37C50, 0x19B37DF0,
            ]:
                raise ValueError(f"System.Object method pointer anchors did not match: {object_method_rvas!r}")
            print("Verified seven System.Object method-pointer anchors")
            equals_parameters = [parameter_details(metadata, strings, parameters, index)
                                 for index in (5743, 5744, 5745)]
            if equals_parameters != [("obj", 1), ("objA", 1), ("objB", 1)]:
                raise ValueError(f"System.Object.Equals parameters did not match: {equals_parameters!r}")
            print("Verified three System.Object.Equals parameter-name and type anchors")
            unicode_fields = [field_details(metadata, strings, fields, index)[0]
                              for index in range(75, 79)]
            if unicode_fields != ["ranges", "TotalCount", "defaultIndex", "defaultCP"]:
                raise ValueError(f"CodePointIndexer field names did not match: {unicode_fields!r}")
            print("Verified four CodePointIndexer field-name anchors")
            unnamed_methods = 0
            total_parameters = 0
            max_parameters = 0
            return_types = []
            next_parameter = 0
            for index in range(ends["methods"]):
                name, parameter_count, return_type_index, parameter_start, _ = method_details(
                    metadata, strings, methods, index)
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
                name, type_index = parameter_details(metadata, strings, parameters, index)
                empty_parameter_names += not name
                if name == "<unnamed>":
                    raise ValueError(f"parameter {index} has a sentinel name index")
                parameter_types.append(type_index)
            unnamed_fields = 0
            field_types = []
            for index in range(ends["fields"]):
                name, type_index = field_details(metadata, strings, fields, index)
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
            string_constants = sum(type_name == "string" for type_name, _ in defaults.values())
            if string_constants != 2057:
                raise ValueError(f"expected 2057 string constants, found {string_constants}")
            default_anchors = {
                555: ("TrueLiteral", ("string", "True")),
                556: ("FalseLiteral", ("string", "False")),
                3370: ("rfc1123Pattern", ("string", "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
                3382: ("CJKYearSuff", ("string", "年")),
                3383: ("CJKMonthSuff", ("string", "月")),
                3384: ("CJKDaySuff", ("string", "日")),
                1121: ("MaxValue", ("int32", 2147483647)),
                12024: ("AfterEverything", ("int32", 22)),
            }
            for index, (name, value) in default_anchors.items():
                actual = (field_details(metadata, strings, fields, index)[0], defaults[index])
                if actual != (name, value):
                    raise ValueError(f"field {index} default value {actual!r} did not match {(name, value)!r}")
            single_nan = defaults[1203]
            if single_nan[0] != "single" or not math.isnan(single_nan[1]):
                raise ValueError(f"Single.NaN decoded as {single_nan!r}")
            print(f"Verified {FIELD_DEFAULT_RECORD_COUNT} field default-value records: "
                  f"{len(defaults)} literal fields all covered, {string_constants} strings, "
                  f"{rva_fields} RVA-data records excluded, {len(default_anchors) + 1} value anchors")


if __name__ == "__main__":
    main()
