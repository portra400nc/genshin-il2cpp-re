#!/usr/bin/env python3
"""Print PE metadata useful for locating a Unity/IL2CPP bootstrap target.

Uses only Python's standard library and does not execute the inspected file.
"""

import mmap
import struct
import sys
from pathlib import Path


def inspect(path: Path, function_rva: int | None = None) -> None:
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        size = len(data)

        def u16(offset: int) -> int:
            if offset < 0 or offset + 2 > size:
                raise ValueError("PE field is outside the file")
            return struct.unpack_from("<H", data, offset)[0]

        def u32(offset: int) -> int:
            if offset < 0 or offset + 4 > size:
                raise ValueError("PE field is outside the file")
            return struct.unpack_from("<I", data, offset)[0]

        def u64(offset: int) -> int:
            if offset < 0 or offset + 8 > size:
                raise ValueError("PE field is outside the file")
            return struct.unpack_from("<Q", data, offset)[0]

        def cstr(offset: int) -> str:
            if offset < 0 or offset >= size:
                raise ValueError("PE string is outside the file")
            end = data.find(b"\0", offset, min(size, offset + 512))
            if end < 0:
                raise ValueError("Unterminated PE string")
            return data[offset:end].decode("ascii", errors="replace")

        if data[:2] != b"MZ":
            raise ValueError("Not a PE file")
        pe = u32(0x3C)
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("Invalid PE header")

        coff = pe + 4
        section_count = u16(coff + 2)
        optional_size = u16(coff + 16)
        optional = coff + 20
        magic = u16(optional)
        if magic == 0x20B:
            image_base = u64(optional + 24)
            data_directories = optional + 112
            thunk_size = 8
            ordinal_flag = 1 << 63
        elif magic == 0x10B:
            image_base = u32(optional + 28)
            data_directories = optional + 96
            thunk_size = 4
            ordinal_flag = 1 << 31
        else:
            raise ValueError("Unsupported PE optional header")

        headers_size = u32(optional + 60)
        sections = []
        for index in range(section_count):
            offset = optional + optional_size + index * 40
            name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            virtual_size = u32(offset + 8)
            virtual_address = u32(offset + 12)
            raw_size = u32(offset + 16)
            raw_offset = u32(offset + 20)
            sections.append((name, virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))

        def from_rva(rva: int) -> int:
            if rva < headers_size:
                return rva
            for _, address, span, raw_offset, raw_size in sections:
                if address <= rva < address + span and rva - address < raw_size:
                    return raw_offset + rva - address
            raise ValueError(f"RVA 0x{rva:x} has no file mapping")

        print(f"File: {path.name}")
        print(f"Size: {size} bytes")
        print(f"Architecture: {'x64' if magic == 0x20B else 'x86'}")
        print(f"Image base: 0x{image_base:x}")
        print("Sections: " + ", ".join(name for name, *_ in sections))

        if function_rva is not None:
            exception_rva = u32(data_directories + 3 * 8)
            exception_size = u32(data_directories + 3 * 8 + 4)
            if not exception_rva or exception_size % 12:
                raise ValueError("PE has no valid x64 exception function table")
            table = from_rva(exception_rva)
            lo, hi = 0, exception_size // 12
            while lo < hi:
                mid = (lo + hi) // 2
                if u32(table + mid * 12) <= function_rva:
                    lo = mid + 1
                else:
                    hi = mid
            index = lo - 1
            if index < 0 or function_rva >= u32(table + index * 12 + 4):
                raise ValueError(f"RVA 0x{function_rva:x} is not in a function table entry")
            print(
                f"Function containing RVA 0x{function_rva:x}: "
                f"0x{u32(table + index * 12):x}..0x{u32(table + index * 12 + 4):x}"
            )

        export_rva = u32(data_directories)
        if export_rva:
            export = from_rva(export_rva)
            count = min(u32(export + 24), 100_000)
            names = from_rva(u32(export + 32))
            matching = []
            for index in range(count):
                name = cstr(from_rva(u32(names + index * 4)))
                if any(word in name.lower() for word in ("il2cpp", "mono", "unity")):
                    matching.append(name)
            print(f"Named exports: {count}")
            print("Unity/IL2CPP exports: " + (", ".join(matching[:100]) or "none"))
        else:
            print("Named exports: none")

        import_rva = u32(data_directories + 8)
        if import_rva:
            imports = from_rva(import_rva)
            modules = []
            symbols = []
            for index in range(4096):
                descriptor = imports + index * 20
                original_thunk = u32(descriptor)
                name_rva = u32(descriptor + 12)
                first_thunk = u32(descriptor + 16)
                if not any((original_thunk, name_rva, first_thunk)):
                    break
                module = cstr(from_rva(name_rva))
                modules.append(module)
                thunk = from_rva(original_thunk or first_thunk)
                for symbol_index in range(100_000):
                    value = u64(thunk + symbol_index * thunk_size) if thunk_size == 8 else u32(thunk + symbol_index * thunk_size)
                    if value == 0:
                        break
                    if value & ordinal_flag:
                        continue
                    symbol = cstr(from_rva(value) + 2)
                    if any(word in symbol.lower() for word in ("getprocaddress", "loadlibrary", "il2cpp", "mono")):
                        symbols.append(f"{module}:{symbol}")
            print("Imported DLLs: " + (", ".join(modules) or "none"))
            print("Relevant imports: " + (", ".join(symbols[:100]) or "none"))
        else:
            print("Imported DLLs: none")

        for marker in ("UnityPlayer.dll", "GameAssembly.dll", "UserAssembly.dll", "il2cpp_init"):
            ascii_found = data.find(marker.encode("ascii")) >= 0
            wide_found = data.find(marker.encode("utf-16le")) >= 0
            print(f"Contains {marker}: ASCII={ascii_found}, UTF-16={wide_found}")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"Usage: {sys.argv[0]} /path/to/GenshinImpact.exe [function-rva]")
    try:
        inspect(Path(sys.argv[1]), int(sys.argv[2], 0) if len(sys.argv) == 3 else None)
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit(f"Inspection failed: {error}") from error
