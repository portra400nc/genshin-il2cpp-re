#!/usr/bin/env python3
"""Read a GenshinMemoryDump.zip: rebuild an unpacked EXE for Ghidra and inspect live classes."""

import argparse
import json
import struct
from bisect import bisect_right
from pathlib import Path
from zipfile import ZipFile


class MemoryDump:
    def __init__(self, dump: Path, exe: Path):
        self.archive = ZipFile(dump)
        self.manifest = json.loads(self.archive.read("manifest.json"))
        self.module = int(self.manifest["module_base"], 16)
        self.exe = exe.read_bytes()
        if len(self.exe) != self.manifest["exe_size"]:
            raise ValueError("The EXE does not match the dumped process")
        pe = struct.unpack_from("<I", self.exe, 0x3C)[0]
        count = struct.unpack_from("<H", self.exe, pe + 6)[0]
        table = pe + 24 + struct.unpack_from("<H", self.exe, pe + 20)[0]
        self.sections = [struct.unpack_from("<8sIIII", self.exe, table + 40 * index) for index in range(count)]
        self.ranges = sorted((int(item["address"], 16), item["size"], item["entry"])
                             for item in self.manifest["ranges"])
        self.starts = [start for start, _, _ in self.ranges]
        self.cache: dict[str, bytes] = {}

    def entry(self, name: str) -> bytes:
        if name not in self.cache:
            self.cache[name] = self.archive.read(name)
        return self.cache[name]

    def read(self, address: int, size: int) -> bytes:
        index = bisect_right(self.starts, address) - 1
        if index >= 0:
            start, length, name = self.ranges[index]
            if address + size <= start + length:
                offset = address - start
                return self.entry(name)[offset:offset + size]
        rva = address - self.module
        for _, virtual_size, virtual_address, raw_size, raw_offset in self.sections:
            if virtual_address <= rva and rva + size <= virtual_address + virtual_size:
                offset = rva - virtual_address
                data = self.exe[raw_offset + offset:raw_offset + min(offset + size, raw_size)]
                return data + bytes(size - len(data))
        raise KeyError(f"0x{address:X} (+{size}) is not in the dump or the EXE image")

    def pointer(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def cstring(self, address: int, limit: int = 256) -> str:
        data = self.read(address, limit)
        return data.split(b"\0", 1)[0].decode("utf-8", "replace")

    def unpacked_exe(self) -> bytes:
        output = bytearray(self.exe)
        for start, size, name in self.ranges:
            if not name.startswith("image/"):
                continue
            rva = start - self.module
            data = self.entry(name)
            for _, virtual_size, virtual_address, raw_size, raw_offset in self.sections:
                if virtual_address <= rva < virtual_address + virtual_size:
                    offset = rva - virtual_address
                    length = min(size, raw_size - offset)
                    if length > 0:
                        output[raw_offset + offset:raw_offset + offset + length] = data[:length]
        return bytes(output)


def method_names(metadata: Path) -> dict[int, str]:
    names = {}
    for image in json.loads(metadata.read_text())["images"]:
        for klass in image["types"]:
            for method in klass["methods"]:
                names[method["index"]] = f"{klass['namespace']}.{klass['name']}::{method['name']}"
    return names


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("exe", type=Path)
    parser.add_argument("--unpacked-exe", type=Path, help="write the EXE with every dumped image page overlaid")
    parser.add_argument("--class-methods", metavar="SEED", help="list a seeded class's method array, e.g. 'class System.Type'")
    parser.add_argument("--metadata", type=Path, help="GenshinAllMetadata.json, to name methods by index")
    args = parser.parse_args()

    dump = MemoryDump(args.dump, args.exe)
    image_bytes = sum(size for _, size, name in dump.ranges if name.startswith("image/"))
    heap_bytes = sum(size for _, size, name in dump.ranges if name.startswith("heap/"))
    print(f"module 0x{dump.module:X}, frame {dump.manifest['frame']}, {len(dump.ranges)} ranges, "
          f"image {image_bytes >> 20} MiB, heap {heap_bytes >> 20} MiB")
    for note in dump.manifest["notes"]:
        print(note)

    if args.unpacked_exe:
        args.unpacked_exe.write_bytes(dump.unpacked_exe())
        print(f"wrote {args.unpacked_exe}")

    if args.class_methods:
        klass = int(dump.manifest["seeds"][args.class_methods], 16)
        names = method_names(args.metadata) if args.metadata else {}
        methods = dump.pointer(klass + 0x20)
        count = struct.unpack("<H", dump.read(klass + 0xC2, 2))[0]
        print(f"{args.class_methods} 0x{klass:X}: {count} methods at 0x{methods:X}")
        for index in range(count):
            method = dump.pointer(methods + 8 * index)
            method_index = struct.unpack("<i", dump.read(method + 0x10, 4))[0]
            code = dump.pointer(method)
            print(f"  [{index:3}] 0x{method:X} index {method_index} code 0x{code:X} {names.get(method_index, '')}")


if __name__ == "__main__":
    main()
