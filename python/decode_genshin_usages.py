#!/usr/bin/env python3
"""Decode which metadata items each Genshin IL2CPP method uses: string literals, classes, methods and fields.

Every IL2CPP method that touches metadata starts by calling an initializer
with its usage-list index, `mov ecx, <list>; call <initializer>`. The list
names a range of usage pairs in global-metadata.dat. Each pair holds the
item's kind and index and the runtime slot the method reads it from. This
build stores both tables with per-entry keys; the formulas below come from
the initializer at RVA 0x523400.
"""

import argparse
import bisect
import collections
import json
import re
import struct
from pathlib import Path

from decode_genshin_strings import BODY_FILE_OFFSET, EXE_SHA256, HEADER_FILE_OFFSET, METADATA_SHA256, sha256


M32 = 0xFFFFFFFF
IMAGE_BASE = 0x140000000
INITIALIZER_RVA = 0x523400
LIST_TABLE_HEADER_OFFSET = 0x15C
LIST_TABLE_XOR = 0x7AFBCC1D
PAIR_TABLE_HEADER_OFFSET = 0x1E4
PAIR_TABLE_BIAS = 0x7204BFC3
LIST_BOUND_XOR = 0x684F73D6

KIND_NAMES = {1: "class", 3: "method", 4: "field", 5: "string", 6: "method_ref", 7: "type_7", 0: "type_0"}

# Each kind resolves into its own static slot array, found through the
# registration struct at RVA 0x2870B28. The string array holds one slot per
# literal.
SLOT_ARRAYS = {1: 0x14579D000, 3: 0x145880000, 4: 0x1459D7530, 5: 0x1459D9260, 0: 0x145A86570, 7: 0x145A81550}
STRING_SLOT_COUNT = 86_109

# Method RVA 0x6C04230 reads the class slot at VA 0x1457A87E0 after calling
# the initializer with list 0x2F8E.
ANCHOR_LIST = 0x2F8E
ANCHOR_ENTRIES = [(1, 472_093, 5_884)]


def s32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


class Executable:
    def __init__(self, data: bytes):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        count = struct.unpack_from("<H", data, pe + 6)[0]
        optional = pe + 24
        table = optional + struct.unpack_from("<H", data, pe + 20)[0]
        self.sections = {}
        for index in range(count):
            name, virtual_size, rva, raw_size, raw = struct.unpack_from("<8sIIII", data, table + 40 * index)
            self.sections[name.rstrip(b"\0").decode()] = (rva, virtual_size, raw, raw_size)
        exception_rva, exception_size = struct.unpack_from("<II", data, optional + 112 + 8 * 3)
        offset = self.offset(exception_rva)
        functions = sorted(
            struct.unpack_from("<II", data, offset + 12 * index) for index in range(exception_size // 12)
        )
        self.function_starts = [start for start, _ in functions]
        self.function_ends = [end for _, end in functions]

    def offset(self, rva: int) -> int:
        for start, virtual_size, raw, raw_size in self.sections.values():
            if start <= rva < start + max(virtual_size, raw_size):
                return rva - start + raw
        raise ValueError(f"RVA 0x{rva:x} is outside every section")

    def function_start(self, rva: int) -> int | None:
        index = bisect.bisect_right(self.function_starts, rva) - 1
        if index >= 0 and rva < self.function_ends[index]:
            return self.function_starts[index]
        return None


class UsageTables:
    def __init__(self, header: bytes, metadata: bytes):
        self.metadata = metadata
        self.lists = BODY_FILE_OFFSET + s32(struct.unpack_from("<I", header, LIST_TABLE_HEADER_OFFSET)[0] ^ LIST_TABLE_XOR)
        self.pairs = BODY_FILE_OFFSET + s32(
            (struct.unpack_from("<I", header, PAIR_TABLE_HEADER_OFFSET)[0] - PAIR_TABLE_BIAS) & M32
        )

    def bound(self, list_index: int) -> int:
        key = ((((list_index * -0x2678209D + 0x992B0DB5) & M32) ^ 0x6B05DBD6) * 0x7B92463D) & M32
        return key ^ struct.unpack_from("<I", self.metadata, self.lists + 4 * list_index)[0] ^ LIST_BOUND_XOR

    def entries(self, list_index: int) -> list[tuple[int, int, int]]:
        result = []
        for entry in range(self.bound(list_index), self.bound(list_index + 1)):
            key = ((((((entry * 0x92DD + 0x4F440D42) & M32) ^ 0x3455F4E9) * 0x2AACE465) & M32) ^ 0x65D8218A) + 0x14032AEE
            key &= M32
            encoded_source, encoded_slot = struct.unpack_from("<II", self.metadata, self.pairs + 8 * entry)
            source = ((encoded_source + 0x9D8F2FB5) & M32) ^ key
            result.append((source >> 29, source & 0x1FFFFFFF, key ^ encoded_slot ^ 0x5C14F482))
        return result


def initializer_calls(exe: Executable) -> dict[int, list[int]]:
    """Maps each function start to the usage lists it passes to the initializer, in code order."""
    rva, _, raw, raw_size = exe.sections["il2cpp"]
    code = exe.data[raw : raw + raw_size]
    calls = collections.defaultdict(list)
    for match in re.finditer(rb"\xB9(....)\xE8(....)", code, re.S):
        call = rva + match.start() + 5
        if call + 5 + struct.unpack_from("<i", code, match.start() + 6)[0] != INITIALIZER_RVA:
            continue
        start = exe.function_start(call)
        if start is not None:
            calls[start].append(struct.unpack_from("<I", code, match.start() + 1)[0])
    return calls


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("api_json", type=Path, help="the --all-images export from export_genshin_metadata.py")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256 or sha256(args.metadata) != METADATA_SHA256:
        parser.error("inputs do not match the inspected EXE and metadata build")

    exe = Executable(args.exe.read_bytes())
    header = exe.data[HEADER_FILE_OFFSET : HEADER_FILE_OFFSET + 0x210]
    if header[:4] != b"MHY\0":
        raise ValueError("embedded metadata header is missing")
    tables = UsageTables(header, args.metadata.read_bytes())
    if tables.entries(ANCHOR_LIST) != ANCHOR_ENTRIES:
        raise ValueError(f"usage list 0x{ANCHOR_LIST:x} decoded as {tables.entries(ANCHOR_LIST)}")

    methods_by_rva = collections.defaultdict(list)
    for image in json.loads(args.api_json.read_text())["images"]:
        for type_def in image["types"]:
            for method in type_def["methods"]:
                if method["code_rva"]:
                    methods_by_rva[method["code_rva"]].append(method["index"])

    records = []
    kinds = collections.Counter()
    for start, lists in sorted(initializer_calls(exe).items()):
        if start not in methods_by_rva:
            continue
        usages = []
        for list_index in dict.fromkeys(lists):
            for kind, source, slot in tables.entries(list_index):
                if kind == 5 and (source >= STRING_SLOT_COUNT or slot >= STRING_SLOT_COUNT):
                    raise ValueError(f"list 0x{list_index:x} has string usage {source} in slot {slot}")
                kinds[KIND_NAMES.get(kind, kind)] += 1
                usages.append([kind, source, slot])
        records.append({"code_rva": start, "methods": methods_by_rva[start], "lists": list(dict.fromkeys(lists)), "usages": usages})

    args.output.write_text(json.dumps({"format": "genshin-method-usages-v1", "exe_sha256": EXE_SHA256, "functions": records}))
    shared = sum(len(record["methods"]) > 1 for record in records)
    inlined = sum(len(record["lists"]) > 1 for record in records)
    print(f"Decoded usages for {len(records)} functions covering {sum(len(r['methods']) for r in records)} methods")
    print(f"{shared} functions are shared by several methods; {inlined} pass more than one list, from inlined callees")
    print("Usages by kind: " + ", ".join(f"{name} {count}" for name, count in kinds.most_common()))


if __name__ == "__main__":
    main()
