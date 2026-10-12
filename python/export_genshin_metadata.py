#!/usr/bin/env python3
"""Export the verified subset of this Genshin build's IL2CPP metadata."""

import argparse
import bisect
import json
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
from inspect_genshin_images import (
    IMAGE_COUNT,
    STARTUP_SHA256,
    image_key,
    u32,
)
from inspect_genshin_types import (
    EXPECTED_METHOD_COUNT,
    EXPECTED_TYPE_COUNT,
    FIELD_ATTRIBUTE_LITERAL,
    IL2CPP_CODE_RVA_END,
    IL2CPP_CODE_RVA_START,
    MAX_STATIC_TYPE_INDEX,
    METHOD_POINTER_ARRAY_FILE_OFFSET,
    PARENT_TYPE_BIAS,
    TYPE_FLAGS_BIAS,
    TYPE_ARRAY_FILE_OFFSET,
    TYPE_ARRAY_VA,
    TYPE_STRIDE,
    field_default_values,
    field_details,
    member_ranges,
    method_details,
    parameter_details,
)


# Names from matched Deck logs: fdab0c9cf8656d5b9ad54a8efb539c907406618988448bd887cf22cba75d1569
# and e6af30865cd5baf23d022404f97e0c15d6a044fbda7c144e7a4ae3d3a9f24010.
# Other kind-21 entries remain unresolved.
GENERIC_INSTANCE_TYPES = {
    3663: (0xD47, 1253, (18, 2721), "System.Collections.Generic.IList<UnityEngine.UICharInfo>"),
    3685: (0xD5C, 1253, (18, 2722), "System.Collections.Generic.IList<UnityEngine.UILineInfo>"),
    5396: (0x13AC, 1258, (17, 3487), "System.Collections.Generic.List<UnityEngine.UI.Dropdown.OptionData>"),
    5573: (0x1456, 1258, (18, 3651), "System.Collections.Generic.List<UnityEngine.EventSystems.RaycastResult>"),
    6067: (0x1632, 3647, (17, 3637), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<UnityEngine.EventSystems.IDeselectHandler>"),
    6096: (0x164D, 3647, (17, 3636), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<UnityEngine.EventSystems.ISelectHandler>"),
    447975: (0x61EB4, 2606, (19, 0), "UnityEngine.Events.UnityAction<T0>"),
    450948: (0x61EC8, 3647, (30, 0), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<T>"),
    3514: (0xCC4, 2607, (8, 0), "UnityEngine.Events.UnityEvent<System.Int32>"),
    5709: (0x14DA, 2607, (14, 0), "UnityEngine.Events.UnityEvent<System.String>"),
    5786: (0x1523, 2607, (12, 0), "UnityEngine.Events.UnityEvent<System.Single>"),
    5787: (0x1524, 2607, (17, 2536), "UnityEngine.Events.UnityEvent<UnityEngine.Vector2>"),
    5476: (0x13F8, 2607, (2, 0), "UnityEngine.Events.UnityEvent<System.Boolean>"),
}


def type_reference(type_array: bytes, index: int, definitions: set[int]) -> dict:
    if index > MAX_STATIC_TYPE_INDEX:
        raise ValueError(f"Il2CppType index {index} exceeds the verified static type array")
    offset = index * 16
    kind = type_array[offset + 0xA]
    if not 1 <= kind <= 0x1F:
        raise ValueError(f"Il2CppType {index} has invalid kind {kind}")
    result = {"index": index, "kind": kind}
    if index in GENERIC_INSTANCE_TYPES:
        encoded_data, generic_definition, argument, name = GENERIC_INSTANCE_TYPES[index]
        actual_data = u32(type_array, offset)
        if kind != 0x15 or actual_data != encoded_data:
            raise ValueError(
                f"Il2CppType {index} disagrees with its verified generic instance: "
                f"kind={kind}, data=0x{actual_data:x}"
            )
        argument_kind, argument_value = argument
        generic_argument = {"kind": argument_kind}
        if argument_kind in (0x11, 0x12):
            if argument_value >= EXPECTED_TYPE_COUNT:
                raise ValueError(f"Il2CppType {index} has invalid generic argument {argument_value}")
            generic_argument["definition"] = argument_value
            definitions.add(argument_value)
        elif argument_kind in (0x13, 0x1E):
            generic_argument["generic_parameter_position"] = argument_value
        elif argument_kind in (2, 8, 12, 14) and argument_value == 0:
            pass
        else:
            raise ValueError(f"Il2CppType {index} has unsupported generic argument kind {argument_kind}")
        if generic_definition >= EXPECTED_TYPE_COUNT:
            raise ValueError(f"Il2CppType {index} has invalid generic definition {generic_definition}")
        result["generic_definition"] = generic_definition
        result["generic_arguments"] = [generic_argument]
        result["generic_name"] = name
        definitions.add(generic_definition)
    elif kind in (0x11, 0x12, 0x1C):
        definition = u32(type_array, offset)
        if definition >= EXPECTED_TYPE_COUNT:
            raise ValueError(f"Il2CppType {index} has invalid definition {definition}")
        result["definition"] = definition
        definitions.add(definition)
    elif kind in (0x13, 0x1E):
        result["generic_parameter_index"] = u32(type_array, offset)
    elif kind in (0x0F, 0x1D):
        pointer = struct.unpack_from("<Q", type_array, offset)[0]
        child_offset = pointer - TYPE_ARRAY_VA
        if child_offset < 0 or child_offset % 16 or child_offset >= len(type_array):
            raise ValueError(f"Il2CppType {index} has an invalid element pointer 0x{pointer:x}")
        child_index = child_offset // 16
        if child_index == index:
            raise ValueError(f"Il2CppType {index} points to itself")
        result["element_type"] = type_reference(type_array, child_index, definitions)
    return result


def default_value_json(type_name: str, value: object) -> dict:
    if type_name in ("single", "double") and not math.isfinite(value):
        value = "NaN" if math.isnan(value) else "Infinity" if value > 0 else "-Infinity"
    return {"type": type_name, "value": value}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("startup_metadata", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image", action="append", dest="images", metavar="NAME",
                        help="assembly image to export (default: UnityEngine.CoreModule.dll)")
    parser.add_argument("--unity-engine", action="store_true",
                        help="export all UnityEngine.* images")
    parser.add_argument("--system-libraries", action="store_true",
                        help="export mscorlib, Mono.Security, and System.* images")
    parser.add_argument("--all-images", action="store_true",
                        help="export every image in the matched game build")
    args = parser.parse_args()

    for path, expected in ((args.exe, EXE_SHA256), (args.metadata, METADATA_SHA256),
                           (args.startup_metadata, STARTUP_SHA256)):
        if sha256(path) != expected:
            parser.error(f"{path} does not match the inspected game build")

    with args.exe.open("rb") as exe:
        exe.seek(HEADER_FILE_OFFSET)
        header = exe.read(0x210)
        exe.seek(TYPE_ARRAY_FILE_OFFSET)
        type_array = exe.read(16 * (MAX_STATIC_TYPE_INDEX + 1))
        exe.seek(METHOD_POINTER_ARRAY_FILE_OFFSET)
        method_pointers = exe.read(8 * EXPECTED_METHOD_COUNT)
    if len(header) != 0x210 or header[:4] != b"MHY\0":
        raise ValueError("embedded MHY header is missing")
    if len(type_array) != 16 * (MAX_STATIC_TYPE_INDEX + 1):
        raise ValueError("static Il2CppType array is truncated")
    indirect_type_count = 0
    for index in range(MAX_STATIC_TYPE_INDEX + 1):
        if type_array[16 * index + 0xA] in (0x0F, 0x1D):
            type_reference(type_array, index, set())
            indirect_type_count += 1
    if indirect_type_count != 9603:
        raise ValueError(f"expected 9603 pointer and array types, found {indirect_type_count}")
    for index, element_index, element_kind in ((4239, 17, 5), (15484, 1, 0x1C),
                                               (452, 70, 8)):
        element = type_reference(type_array, index, set()).get("element_type")
        if element != type_reference(type_array, element_index, set()) or element["kind"] != element_kind:
            raise ValueError(f"array type {index} disagrees with its verified element type")
    if len(method_pointers) != 8 * EXPECTED_METHOD_COUNT:
        raise ValueError("method-pointer array is truncated")

    string_section = (u32(header, 0x184) + 0xBF9D4735) & 0xFFFFFFFF
    type_section = (u32(header, 0xB4) + 0xEC48AB9F) & 0xFFFFFFFF
    type_size = (u32(header, 0xE0) + 0xE2F9B07D) & 0xFFFFFFFF
    method_section = (u32(header, 0x16C) + 0xE33589AC) & 0xFFFFFFFF
    field_section = (u32(header, 0x18C) + 0xEBF0392C) & 0xFFFFFFFF
    parameter_section = u32(header, 0x114) ^ 0x3E5D33E6
    image_section = (u32(header, 0x20C) + 0xF134D80B) & 0xFFFFFFFF
    if type_size != EXPECTED_TYPE_COUNT * TYPE_STRIDE:
        raise ValueError("unexpected type-definition table length")

    startup = args.startup_metadata.read_bytes()
    if image_section + IMAGE_COUNT * 40 > len(startup):
        raise ValueError("startup image table is truncated")
    image_ranges = []
    with args.metadata.open("rb") as metadata:
        for image_index in range(IMAGE_COUNT):
            image = startup[image_section + 40 * image_index:image_section + 40 * (image_index + 1)]
            key = image_key(image_index)
            name = decode_string(metadata, string_section, u32(image, 0x20) ^ key ^ 0x772FA51E)
            start = u32(image, 0x0C) ^ key ^ 0x38EAB186 ^ 0x4B1CB1C1
            count = ((u32(image, 0x14) + 0xAA3CAE09) & 0xFFFFFFFF) ^ key
            if start + count > EXPECTED_TYPE_COUNT:
                raise ValueError(f"image {name} has an invalid type range")
            image_ranges.append((name, start, count))

        wanted = set(args.images or [])
        if args.all_images:
            wanted.update(name for name, _, _ in image_ranges)
        if args.unity_engine:
            wanted.update(name for name, _, _ in image_ranges if name.startswith("UnityEngine."))
        if args.system_libraries:
            wanted.update(name for name, _, _ in image_ranges
                          if name in ("mscorlib.dll", "Mono.Security.dll")
                          or name.startswith("System."))
        if not wanted:
            wanted.add("UnityEngine.CoreModule.dll")
        found = {name for name, _, _ in image_ranges}
        unknown = wanted - found
        if unknown:
            parser.error(f"unknown image(s): {', '.join(sorted(unknown))}")

        defaults = field_default_values(metadata, header, type_array)
        metadata.seek(BODY_FILE_OFFSET + type_section)
        type_records = metadata.read(type_size)
        if len(type_records) != type_size:
            raise ValueError("type-definition table is truncated")

        exported = []
        referenced_definitions = set()
        for name, start, count in image_ranges:
            if name not in wanted:
                continue
            image_types = []
            for definition_index in range(start, start + count):
                record = type_records[definition_index * TYPE_STRIDE:(definition_index + 1) * TYPE_STRIDE]
                namespace_index = (u32(record, 0) + 0xBBB4CF40) & 0xFFFFFFFF
                name_index = (u32(record, 0x24) + 0xFBAD8E98) & 0xFFFFFFFF
                namespace = decode_string(metadata, string_section, namespace_index)
                type_name = decode_string(metadata, string_section, name_index)
                parent_index = (u32(record, 0x18) + PARENT_TYPE_BIAS) & 0xFFFFFFFF
                type_flags = (u32(record, 0x28) - TYPE_FLAGS_BIAS) & 0xFFFFFFFF
                if type_flags & ~0x1FFFFF:
                    raise ValueError(f"type {definition_index} has implausible attributes 0x{type_flags:x}")
                (method_start, method_count), (field_start, field_count) = member_ranges(record)
                methods = []
                for method_index in range(method_start, method_start + method_count):
                    method_name, parameter_count, return_index, parameter_start, method_flags = method_details(
                        metadata, string_section, method_section, method_index)
                    if parameter_count and parameter_start == 0xFFFFFFFF:
                        raise ValueError(f"method {method_index} has parameters but no start")
                    parameters = []
                    for parameter_index in range(parameter_start, parameter_start + parameter_count):
                        parameter_name, parameter_type = parameter_details(
                            metadata, string_section, parameter_section, parameter_index)
                        parameters.append({"name": parameter_name,
                                           "type": type_reference(type_array, parameter_type, referenced_definitions)})
                    pointer = struct.unpack_from("<Q", method_pointers, 8 * method_index)[0]
                    code_rva = None if pointer == 0 else pointer - 0x140000000
                    if code_rva is not None and not IL2CPP_CODE_RVA_START <= code_rva < IL2CPP_CODE_RVA_END:
                        raise ValueError(f"method {method_index} pointer is outside IL2CPP code")
                    if method_index == 3392:
                        if (namespace, type_name, method_name, method_flags, code_rva,
                            parameters, type_reference(type_array, return_index, referenced_definitions)) != (
                                "System", "Type", "<unnamed>", 145, 0x19566F70,
                                [{"name": "handle", "type": {"index": 495, "kind": 24}}],
                                {"index": 9, "kind": 18, "definition": 314}):
                            raise ValueError("System.Type.internal_from_handle anchor differs")
                        method_name = "internal_from_handle"
                    methods.append({"index": method_index, "name": method_name,
                                    "flags": method_flags,
                                    "code_rva": code_rva,
                                    "return_type": type_reference(type_array, return_index, referenced_definitions),
                                    "parameters": parameters})
                fields = []
                for field_index in range(field_start, field_start + field_count):
                    field_name, field_type = field_details(metadata, string_section, field_section, field_index)
                    if field_type > MAX_STATIC_TYPE_INDEX:
                        raise ValueError(f"field {field_index} has invalid Il2CppType index {field_type}")
                    field_flags = struct.unpack_from("<H", type_array, 16 * field_type + 8)[0]
                    field = {"index": field_index, "name": field_name,
                             "flags": field_flags,
                             "type": type_reference(type_array, field_type, referenced_definitions)}
                    if field_flags & FIELD_ATTRIBUTE_LITERAL:
                        field["default_value"] = default_value_json(*defaults[field_index])
                    fields.append(field)
                image_types.append({
                    "index": definition_index,
                    "namespace": namespace,
                    "name": type_name,
                    "flags": type_flags,
                    "parent": None if parent_index == 0xFFFFFFFF else type_reference(
                        type_array, parent_index, referenced_definitions),
                    "methods": methods,
                    "fields": fields,
                })
            exported.append({"name": name, "type_start": start, "type_count": count,
                             "types": image_types})

        image_starts = [start for _, start, _ in image_ranges]
        referenced_types = []
        for definition_index in sorted(referenced_definitions):
            record = type_records[definition_index * TYPE_STRIDE:(definition_index + 1) * TYPE_STRIDE]
            namespace_index = (u32(record, 0) + 0xBBB4CF40) & 0xFFFFFFFF
            name_index = (u32(record, 0x24) + 0xFBAD8E98) & 0xFFFFFFFF
            image_index = bisect.bisect_right(image_starts, definition_index) - 1
            image_name = None
            if image_index >= 0:
                image, start, count = image_ranges[image_index]
                if definition_index < start + count:
                    image_name = image
            referenced_types.append({
                "index": definition_index,
                "namespace": decode_string(metadata, string_section, namespace_index),
                "name": decode_string(metadata, string_section, name_index),
                "image": image_name,
            })

    result = {"format": "genshin-mhy-verified-subset-v1", "exe_sha256": EXE_SHA256,
              "metadata_sha256": METADATA_SHA256, "startup_metadata_sha256": STARTUP_SHA256,
              "images": exported, "referenced_types": referenced_types}
    type_anchors = {
        293: ("System", "String", 0x102101),
        371: ("System", "Object", 0x102001),
        2209: ("UnityEngine", "Application", 0x100101),
        2279: ("UnityEngine", "GameObject", 0x100101),
    }
    method_anchors = {3871: ("Equals", 0x0096), 15974: (".ctor", 0x1886),
                      16042: ("Quit", 0x0096)}
    field_anchors = {(251, "MaxValue"): 0x8056, (2377, "m_CachedPtr"): 0x0001}
    default_anchors = {
        (251, "MaxValue"): {"type": "int32", "value": 2147483647},
        (291, "NaN"): {"type": "single", "value": "NaN"},
        (2697, "AfterEverything"): {"type": "int32", "value": 22},
    }
    for image in exported:
        for type_info in image["types"]:
            index = type_info["index"]
            if index in type_anchors:
                actual = (type_info["namespace"], type_info["name"], type_info["flags"])
                if actual != type_anchors[index]:
                    raise ValueError(f"exported type {index} disagrees with its verified anchor: {actual}")
            for method in type_info["methods"]:
                index = method["index"]
                if index in method_anchors and (method["name"], method["flags"]) != method_anchors[index]:
                    raise ValueError(f"exported method {index} disagrees with its verified anchor")
            for field in type_info["fields"]:
                anchor = (type_info["index"], field["name"])
                if anchor in field_anchors and field["flags"] != field_anchors[anchor]:
                    raise ValueError(f"exported field {anchor} disagrees with its verified attributes")
                if anchor in default_anchors and field.get("default_value") != default_anchors[anchor]:
                    raise ValueError(f"exported field {anchor} disagrees with its verified default value")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")), encoding="utf-8")
    print(f"Exported {sum(image['type_count'] for image in exported)} types from "
          f"{len(exported)} image(s) to {args.output}")


if __name__ == "__main__":
    main()
