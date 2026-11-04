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
    string_section,
)
from inspect_genshin_images import (
    IMAGE_COUNT,
    STARTUP_SHA256,
    image_fields,
    image_table,
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
    TYPE_ARRAY_FILE_OFFSET,
    TYPE_ARRAY_VA,
    TYPE_STRIDE,
    field_default_values,
    field_details,
    field_section,
    member_ranges,
    method_details,
    method_section,
    parameter_details,
    parameter_section,
    type_flags,
    type_names,
    type_parent,
    type_section,
)


# The generic instances that the 7.1 build's Deck logs named, found again in this build by their
# generic definition and argument, or by the parameter that uses them: UnityEvent`1.AddListener(call)
# for UnityAction<T0> and ExecuteEvents.Execute(target, eventData, functor) for EventFunction<T>.
# Other kind-21 entries remain unresolved.
GENERIC_INSTANCE_TYPES = {
    3660: (0xD44, 1250, (17, 2718), "System.Collections.Generic.IList<UnityEngine.UICharInfo>"),
    3682: (0xD59, 1250, (17, 2719), "System.Collections.Generic.IList<UnityEngine.UILineInfo>"),
    5393: (0x13A9, 1255, (18, 3485), "System.Collections.Generic.List<UnityEngine.UI.Dropdown.OptionData>"),
    5570: (0x1453, 1255, (17, 3649), "System.Collections.Generic.List<UnityEngine.EventSystems.RaycastResult>"),
    6065: (0x1630, 3645, (18, 3635), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<UnityEngine.EventSystems.IDeselectHandler>"),
    6094: (0x164B, 3645, (18, 3634), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<UnityEngine.EventSystems.ISelectHandler>"),
    453026: (0x631B8, 2603, (19, 0), "UnityEngine.Events.UnityAction<T0>"),
    456002: (0x631CC, 3645, (30, 0), "UnityEngine.EventSystems.ExecuteEvents.EventFunction<T>"),
    3511: (0xCC1, 2604, (8, 0), "UnityEngine.Events.UnityEvent<System.Int32>"),
    5706: (0x14D7, 2604, (14, 0), "UnityEngine.Events.UnityEvent<System.String>"),
    5784: (0x1521, 2604, (12, 0), "UnityEngine.Events.UnityEvent<System.Single>"),
    5785: (0x1522, 2604, (17, 2533), "UnityEngine.Events.UnityEvent<UnityEngine.Vector2>"),
    5473: (0x13F5, 2604, (2, 0), "UnityEngine.Events.UnityEvent<System.Boolean>"),
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
    if indirect_type_count != 9752:
        raise ValueError(f"expected 9752 pointer and array types, found {indirect_type_count}")
    for index, element_index, element_kind in ((4236, 17, 5), (15514, 1, 0x1C),
                                               (452, 70, 8)):
        element = type_reference(type_array, index, set()).get("element_type")
        if element != type_reference(type_array, element_index, set()) or element["kind"] != element_kind:
            raise ValueError(f"array type {index} disagrees with its verified element type")
    if len(method_pointers) != 8 * EXPECTED_METHOD_COUNT:
        raise ValueError("method-pointer array is truncated")

    strings = string_section(header)
    type_base, type_size = type_section(header)
    method_base = method_section(header)
    field_base = field_section(header)
    parameter_base = parameter_section(header)
    image_section = image_table(header)
    if type_size != EXPECTED_TYPE_COUNT * TYPE_STRIDE:
        raise ValueError("unexpected type-definition table length")

    startup = args.startup_metadata.read_bytes()
    if image_section + IMAGE_COUNT * 40 > len(startup):
        raise ValueError("startup image table is truncated")
    image_ranges = []
    with args.metadata.open("rb") as metadata:
        for image_index in range(IMAGE_COUNT):
            image = startup[image_section + 40 * image_index:image_section + 40 * (image_index + 1)]
            name_index, start, count = image_fields(image, image_index)
            name = decode_string(metadata, strings, name_index)
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
        metadata.seek(BODY_FILE_OFFSET + type_base)
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
                namespace_index, name_index = type_names(record)
                namespace = decode_string(metadata, strings, namespace_index)
                type_name = decode_string(metadata, strings, name_index)
                parent_index = type_parent(record)
                flags = type_flags(record)
                if flags & ~0x1FFFFF:
                    raise ValueError(f"type {definition_index} has implausible attributes 0x{flags:x}")
                (method_start, method_count), (field_start, field_count) = member_ranges(record)
                methods = []
                for method_index in range(method_start, method_start + method_count):
                    method_name, parameter_count, return_index, parameter_start, method_flags = method_details(
                        metadata, strings, method_base, method_index)
                    if parameter_count and parameter_start == 0xFFFFFFFF:
                        raise ValueError(f"method {method_index} has parameters but no start")
                    parameters = []
                    for parameter_index in range(parameter_start, parameter_start + parameter_count):
                        parameter_name, parameter_type = parameter_details(
                            metadata, strings, parameter_base, parameter_index)
                        parameters.append({"name": parameter_name,
                                           "type": type_reference(type_array, parameter_type, referenced_definitions)})
                    pointer = struct.unpack_from("<Q", method_pointers, 8 * method_index)[0]
                    code_rva = None if pointer == 0 else pointer - 0x140000000
                    if code_rva is not None and not IL2CPP_CODE_RVA_START <= code_rva < IL2CPP_CODE_RVA_END:
                        raise ValueError(f"method {method_index} pointer is outside IL2CPP code")
                    if method_index == 3392:
                        if (namespace, type_name, method_name, method_flags, code_rva,
                            parameters, type_reference(type_array, return_index, referenced_definitions)) != (
                                "System", "Type", "<unnamed>", 145, 0x19BC1390,
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
                    field_name, field_type = field_details(metadata, strings, field_base, field_index)
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
                    "flags": flags,
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
            namespace_index, name_index = type_names(record)
            image_index = bisect.bisect_right(image_starts, definition_index) - 1
            image_name = None
            if image_index >= 0:
                image, start, count = image_ranges[image_index]
                if definition_index < start + count:
                    image_name = image
            referenced_types.append({
                "index": definition_index,
                "namespace": decode_string(metadata, strings, namespace_index),
                "name": decode_string(metadata, strings, name_index),
                "image": image_name,
            })

    result = {"format": "genshin-mhy-verified-subset-v1", "exe_sha256": EXE_SHA256,
              "metadata_sha256": METADATA_SHA256, "startup_metadata_sha256": STARTUP_SHA256,
              "images": exported, "referenced_types": referenced_types}
    type_anchors = {
        293: ("System", "String", 0x102101),
        371: ("System", "Object", 0x102001),
        2206: ("UnityEngine", "Application", 0x100101),
        2276: ("UnityEngine", "GameObject", 0x100101),
    }
    method_anchors = {3871: ("Equals", 0x0096), 15951: (".ctor", 0x1886),
                      16019: ("Quit", 0x0096)}
    field_anchors = {(251, "MaxValue"): 0x8056, (2374, "m_CachedPtr"): 0x0001}
    default_anchors = {
        (251, "MaxValue"): {"type": "int32", "value": 2147483647},
        (291, "NaN"): {"type": "single", "value": "NaN"},
        (2694, "AfterEverything"): {"type": "int32", "value": 22},
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
