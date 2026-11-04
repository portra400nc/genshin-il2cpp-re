"""Instance field offsets of IL2CPP classes, computed from the metadata export.

IL2CPP lays a class out sequentially: the parent's fields first, then the class's own instance fields in
declaration order, each aligned to its own alignment. Offsets include the 0x10-byte object header, as
il2cpp_field_get_offset reports them, value types included. References take 8 bytes, primitives their size,
value types their computed size and alignment. Explicit layouts and packing are not modelled, so check a
computed offset against one read from code or at runtime before relying on it.
"""

import json

PRIMITIVE_SIZES = {2: 1, 3: 2, 4: 1, 5: 1, 6: 2, 7: 2, 8: 4, 9: 4, 10: 8, 11: 8, 12: 4, 13: 8, 24: 8, 25: 8}
VALUE_TYPE, CLASS_GENERIC_PARAMETER, GENERIC_INSTANCE = 17, 19, 21
FIELD_STATIC, FIELD_LITERAL = 0x10, 0x40
HEADER = 0x10


class Layout:
    def __init__(self, types: dict[int, dict], generics: dict[int, dict]):
        """`types` maps a type definition index to its export record; `generics` is generic-types.json by index."""
        self.types = types
        self.generics = generics
        self.sizes: dict[tuple, tuple[int, int]] = {}
        self.positions: dict[int, int] = {}
        for type_def in types.values():
            self.learn_positions(type_def)

    def learn_positions(self, type_def: dict) -> None:
        """Ranks the class generic parameters a generic type mentions, so a parameter reference gives its argument position."""
        refs = [f["type"] for f in type_def["fields"]]
        for method in type_def["methods"]:
            refs.append(method["return_type"])
            refs.extend(p["type"] for p in method["parameters"])
        seen = {r["generic_parameter_index"] for r in refs if r["kind"] == CLASS_GENERIC_PARAMETER and "generic_parameter_index" in r}
        if seen:
            base = min(seen)
            for index in seen:
                self.positions[index] = index - base

    @staticmethod
    def instance_fields(type_def: dict) -> list[dict]:
        return [f for f in type_def["fields"] if not f["flags"] & (FIELD_STATIC | FIELD_LITERAL)]

    def parent(self, type_def: dict) -> dict | None:
        parent = type_def.get("parent")
        return self.types.get(parent.get("definition")) if parent else None

    def size_of(self, ref: dict, arguments: tuple = ()) -> tuple[int, int]:
        """Size and alignment of a field of this type."""
        kind = ref["kind"]
        if kind in PRIMITIVE_SIZES:
            size = PRIMITIVE_SIZES[kind]
            return size, size
        if kind == VALUE_TYPE:
            return self.value_size(self.types[ref["definition"]], ())
        if kind == GENERIC_INSTANCE:
            generic = self.generics[ref["index"]]
            definition = self.types[generic["generic_definition"]]
            parent = self.parent(definition)
            if parent is not None and parent["name"] == "ValueType":
                return self.value_size(definition, tuple(json.dumps(a, sort_keys=True) for a in generic["arguments"]))
            return 8, 8
        if kind == CLASS_GENERIC_PARAMETER and arguments:
            position = self.positions.get(ref.get("generic_parameter_index"))
            if position is None or position >= len(arguments):
                raise ValueError(f"generic parameter {ref} has no known position")
            return self.size_of(json.loads(arguments[position]))
        return 8, 8

    def value_size(self, type_def: dict, arguments: tuple) -> tuple[int, int]:
        key = (type_def["index"], arguments)
        if key not in self.sizes:
            parent = self.parent(type_def)
            fields = self.instance_fields(type_def)
            if parent is not None and parent["name"] == "Enum":
                self.sizes[key] = self.size_of(fields[0]["type"])
            else:
                offset, align = 0, 1
                for field in fields:
                    size, field_align = self.size_of(field["type"], arguments)
                    offset = -(-offset // field_align) * field_align + size
                    align = max(align, field_align)
                self.sizes[key] = (-(-offset // align) * align or 1, align)
        return self.sizes[key]

    def offsets(self, type_def: dict) -> dict[int, int]:
        """Field index to offset for every instance field of the class and its parents."""
        chain = []
        current = type_def
        while current is not None and not (current["name"] == "Object" and current["namespace"] == "System"):
            chain.append(current)
            current = self.parent(current)
        offset, result = HEADER, {}
        for klass in reversed(chain):
            for field in self.instance_fields(klass):
                size, align = self.size_of(field["type"])
                offset = -(-offset // align) * align
                result[field["index"]] = offset
                offset += size
        return result
