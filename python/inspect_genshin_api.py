#!/usr/bin/env python3
"""Check IL2CPP runtime entry-point leads in the matched Genshin EXE."""

import argparse
import struct
from pathlib import Path

from decode_genshin_strings import EXE_SHA256, sha256
from inspect_genshin_types import IL2CPP_CODE_FILE_BIAS


TEXT_RAW_OFFSET_BIAS = 0xC00
RDATA_FILE_BIAS = 0x1A00


def read_rva(exe: bytes, rva: int, size: int) -> bytes:
    return exe[rva - TEXT_RAW_OFFSET_BIAS : rva - TEXT_RAW_OFFSET_BIAS + size]


def check_bytes(exe: bytes, rva: int, expected: bytes) -> None:
    actual = read_rva(exe, rva, len(expected))
    if actual != expected:
        raise ValueError(f"RVA 0x{rva:x}: expected {expected.hex()}, got {actual.hex()}")


def check_relative_branch(exe: bytes, source: int, opcode: int, target: int) -> None:
    instruction = read_rva(exe, source, 5)
    if len(instruction) != 5 or instruction[0] != opcode:
        raise ValueError(f"RVA 0x{source:x} is not the expected relative branch")
    actual_target = source + 5 + struct.unpack_from("<i", instruction, 1)[0]
    if actual_target != target:
        raise ValueError(f"RVA 0x{source:x} targets 0x{actual_target:x}, expected 0x{target:x}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    args = parser.parse_args()
    if sha256(args.exe) != EXE_SHA256:
        parser.error("EXE does not match the inspected build")
    exe = args.exe.read_bytes()

    check_bytes(exe, 0x4BBD40, bytes.fromhex("56 48 83 ec 20 48 89 ce 48 8d 15 e6 d8 61 03 31"))
    check_relative_branch(exe, 0x4BBD59, 0xE8, 0x53F750)
    check_bytes(exe, 0x4BCA00, bytes.fromhex("48 8b 51 30 48 85 d2 74 11"))
    check_bytes(exe, 0x4BC9E0, bytes.fromhex("48 8b 51 30 48 85 d2 74 10"))
    check_bytes(exe, 0x4BC9E9, bytes.fromhex("48 b8 69 5b 34 cd 40 81 62 9b 48 03 02"))
    check_bytes(exe, 0x4BCA09, bytes.fromhex("48 b8 02 44 19 df 2e b1 1e e5 48 03 42 10"))
    check_bytes(exe, 0x4BCB88, bytes.fromhex("48 b8 4c 9c 0a 00 60 2a 69 4d 48 33 42 08"))
    check_bytes(exe, 0x4BCA20, bytes.fromhex("0f b6 41 2f 24 20 c0 e8 05 c3"))
    check_bytes(exe, 0x4BC640, bytes.fromhex("e9 db a7 06 00"))
    check_bytes(exe, 0x4BC780, bytes.fromhex("55 48 83 ec 30 48 8d 6c 24 30"))
    check_bytes(exe, 0x4BC798, bytes.fromhex("48 83 ca 02"))
    check_bytes(exe, 0x4BC7E0, bytes.fromhex("55 48 83 ec 30 48 8d 6c 24 30"))
    check_bytes(exe, 0x4BC7F8, bytes.fromhex("48 8d 04 52"))
    check_bytes(exe, 0x4BC840, bytes.fromhex("89 c8 c1 e8 1a 48 c1 e0 10"))
    check_bytes(exe, 0x4BC870, bytes.fromhex("55 56 48 83 ec 28 48 8d 6c 24 20"))
    check_relative_branch(exe, 0x4BCA1A, 0xE9, 0x532E60)
    check_bytes(exe, 0x4BCA50, bytes.fromhex("0f b6 41 2e c3"))
    check_bytes(exe, 0x4BCB9E, bytes.fromhex("48 8b 04 c8"))
    check_bytes(exe, 0x4BCA8E, bytes.fromhex("48 8b 44 c8 08"))
    check_bytes(exe, 0x4BCC30, bytes.fromhex("48 8d 41 10 c3"))
    check_bytes(exe, 0x4BCC70, bytes.fromhex("55 41 56 56 57 53 48 83 ec 40"))
    check_relative_branch(exe, 0x4BCCE2, 0xE8, 0x549310)
    check_bytes(exe, 0x4BCD60, bytes.fromhex("48 8d 41 14 c3"))
    check_bytes(exe, 0x4BCD90, bytes.fromhex(
        "55 56 57 53 48 83 ec 28 48 8d 6c 24 20 48 c7 45 "
        "00 fe ff ff ff 48 89 ce 85 d2 74 4e"))
    check_bytes(exe, 0x4BCDF0, bytes.fromhex("89 78 10 01 ff"))
    check_bytes(exe, 0x4BCE04, bytes.fromhex("48 8d 4b 14 48 89 f2"))
    check_relative_branch(exe, 0x4BCE0B, 0xE8, 0x1FE0310)
    # UnitySynchronizationContext.ExecuteTasks is an optional frame-callback probe.
    frame_rva = 0x1A240F10
    frame_prologue = bytes.fromhex("48 83 ec 28 e8 77 5b 92 ff 48 85 c0 74 0c 48 8b")
    frame_file_offset = frame_rva - IL2CPP_CODE_FILE_BIAS
    if exe[frame_file_offset:frame_file_offset + len(frame_prologue)] != frame_prologue:
        raise ValueError("UnitySynchronizationContext.ExecuteTasks prologue differs")
    check_bytes(exe, 0x549377, bytes.fromhex("41 ff d4"))
    check_bytes(exe, 0x526C20, bytes.fromhex(
        "55 56 57 53 48 83 ec 78 48 8d 6c 24 70 48 c7 45 "
        "00 fe ff ff ff 80 b9 c7 00 00 00 00"))
    check_bytes(exe, 0x526D5A, bytes.fromhex("48 8d 15 ea a9 5a 03"))
    check_bytes(exe, 0x526D1A, bytes.fromhex("45 31 c0 e8 ce 22 02 00"))
    check_bytes(exe, 0x51D860, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    check_bytes(exe, 0x51D883, bytes.fromhex("0f b6 81 ca 00 00 00 a8 10"))
    check_relative_branch(exe, 0x51D8C8, 0xE8, 0x51D860)
    check_relative_branch(exe, 0x51D950, 0xE8, 0x51F110)
    check_bytes(exe, 0x51DB5F, bytes.fromhex("49 89 b4 c7 d0 00 00 00"))
    check_bytes(exe, 0x51E8B4, bytes.fromhex("24 af 0c 10 41 88 87 ca 00 00 00"))
    # The class+0x30 helper derives an 8-byte-entry count from metadata+0x45.
    check_bytes(exe, 0x5202FF, bytes.fromhex("49 8b 46 40 0f b6 40 45 04 ec"))
    check_bytes(exe, 0x520313, bytes.fromhex("48 8d 3c dd 00 00 00 00 48 89 fa"))
    check_bytes(exe, 0x5203AB, bytes.fromhex("49 87 76 30"))
    # A native caller acquires the metadata lock, passes the address of a
    # local pointer to its global slot, then releases the lock through it.
    check_bytes(exe, 0x4CE24C, bytes.fromhex(
        "48 8d 05 55 b3 6f 05 48 89 85 d8 00 00 00 48 8b "
        "0d 47 b3 6f 05 ff 15 89 ef 6d 03 48 8d 95 d8 00 "
        "00 00 48 89 f1"))
    check_relative_branch(exe, 0x4CE271, 0xE8, 0x51D860)
    check_bytes(exe, 0x4CE276, bytes.fromhex("48 8b 85 d8 00 00 00 48 8b 08 ff 15 72 f3 6d 03"))
    # Class setup uses the same global slot when interface setup needs a lock.
    check_bytes(exe, 0x51E212, bytes.fromhex(
        "48 8d 05 8f b3 6a 05 48 89 45 c8 48 8b 0d 84 b3 "
        "6a 05 ff 15 c6 ef 68 03 48 8d 55 c8 4c 89 f9"))
    check_relative_branch(exe, 0x51E231, 0xE8, 0x51D300)
    check_bytes(exe, 0x51E236, bytes.fromhex("48 8b 45 c8 48 8b 08 ff 15 b5 f3 68 03"))
    # Interface-table construction copies one 8-byte vtable entry per slot.
    # The stock Il2CppInterop VirtualInvokeData is two pointers (16 bytes).
    check_bytes(exe, 0x4E9C1E, bytes.fromhex(
        "48 8d 88 d0 00 00 00 48 8d 96 d0 00 00 00 44 0f "
        "b7 86 c2 00 00 00 49 c1 e0 03"))
    check_relative_branch(exe, 0x4E9C38, 0xE8, 0x1FE0310)
    check_bytes(exe, 0x4BC2F0, bytes.fromhex("48 8b 01 c3"))
    check_bytes(exe, 0x4BC110, bytes.fromhex("f6 81 c8 00 00 00 0e 75 0e 0f b6 41 22"))
    check_relative_branch(exe, 0x4BC020, 0xE9, 0x5203C0)
    check_bytes(exe, 0x4BC0C0, bytes.fromhex("e9 4b f6 05 00"))
    check_relative_branch(exe, 0x4BC0B0, 0xE9, 0x51B200)
    check_bytes(exe, 0x51B200, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    check_bytes(exe, 0x51B2E0, bytes.fromhex(
        "8b bf a4 00 00 00 48 85 ff 74 10 48 8b 05 de d7 "
        "6a 05 48 03 38 0f 85 4d ff ff ff"))
    check_bytes(exe, 0x5203C0, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    if exe[0x3AD174B - RDATA_FILE_BIAS:0x3AD174B - RDATA_FILE_BIAS + 50] != b"The type initializer for '%s' threw an exception.\0":
        raise ValueError("Class-init error text differs")
    check_bytes(exe, 0x4BBF90, bytes.fromhex("48 b8 9d c9 d2 05 df 85 9b 1a 48 33 41 10 c3"))
    check_bytes(exe, 0x4BBF10, bytes.fromhex("48 8b 05 a1 d8 70 05 c3"))
    check_bytes(exe, 0x5436D1, bytes.fromhex(
        "48 8d 0d 09 49 56 03 e8 43 3b fd ff 48 8b 40 10 "
        "48 b9 9d c9 d2 05 df 85 9b 1a 48 31 c8 48 89 05 "
        "c3 60 68 05"))
    check_bytes(exe, 0x5400D2, bytes.fromhex("44 89 3d 57 8e 68 05"))
    check_bytes(exe, 0x5400E3, bytes.fromhex("48 89 f0 48 c1 e0 04 48 8d 1c 80"))
    check_bytes(exe, 0x5401A3, bytes.fromhex("4c 89 35 8e 8d 68 05"))
    check_bytes(exe, 0x540B8F, bytes.fromhex(
        "48 b9 eb e1 f7 48 48 20 56 32 48 01 c8 4b 89 44 "
        "2f 18"))
    check_bytes(exe, 0x5401BE, bytes.fromhex("44 89 f8 c1 f8 04 89 05 76 8d 68 05"))
    check_bytes(exe, 0x540282, bytes.fromhex("4c 89 35 bf 8c 68 05"))
    check_bytes(exe, 0x540F56, bytes.fromhex("48 bb 9d c9 d2 05 df 85 9b 1a"))
    check_bytes(exe, 0x540F71, bytes.fromhex("48 89 44 3b 10"))
    check_bytes(exe, 0x540FD8, bytes.fromhex(
        "48 b9 e3 c5 a0 6a 7e d9 0a 46 48 01 c8 48 89 44 "
        "3b 30"))

    print("0x4bbd40: init wrapper calls metadata initialization at 0x53f750")
    print("0x4bca00: method-name wrapper falls back to the metadata decoder at 0x532e60")
    print("0x4bc9e0/0x4bca20: method record and generic-flag candidates have matched code bytes")
    print("0x4bc4f0: static field value getter candidate has matched code bytes")
    print("0x4bca50: parameter-count candidate returns the byte at MethodInfo+0x2e")
    print("0x4bcb70/0x4bca60: parameter type/name candidates load adjacent fields from a 24-byte record")
    print("0x4bcc70: runtime-invoke candidate calls 0x549310, which calls the pointer at MethodInfo+0x18")
    print("0x526c20: runtime static-constructor initializer checks completion flags, invokes the cctor, and references the type-initializer error")
    print("0x51d860: class-setup candidate recurses on the parent, initializes methods, writes vtable entries, and sets the completion bit at class+0xca")
    print("0x4ce24c: caller passes class and address of a local metadata-lock slot to 0x51d860 under a critical section")
    print("0x51e212: class setup uses the same lock-slot pattern around interface setup at 0x51d300")
    print("0x4e9c1e: interface-table builder copies the base vtable from class+0xd0 in 8-byte slots")
    print("0x4bc2f0: returns the first pointer from its argument; class-to-image candidate")
    print("0x4bc110: decodes a class namespace through its metadata record; class namespace candidate")
    print("0x4bc020: forwards image, namespace, and class-name arguments to lookup at 0x5203c0")
    print("0x4bc040/0x4bc0b0: class method enumeration and field-name lookup candidates have matched code bytes")
    print("0x51b2e0: field-name lookup follows the 32-bit relative parent link at class+0xa4")
    print("0x4bbf90: xors assembly+0x10 with the image-pointer key 0x1a9b85df05d2c99d; assembly-to-image candidate")
    print("0x4bbf10: returns a global set from an assembly image at 0x5436d1; corlib-image candidate")
    print("0x5400d2/0x5401a3: store the 75-image count and image-array pointer at RVAs 0x5bc8f30/0x5bc8f38")
    print("0x540b8f: stores the image name pointer plus 0x3256204848f7e1eb at image+0x18")
    print("0x5401be/0x540282: store the 75-assembly count and array pointer at RVAs 0x5bc8f40/0x5bc8f48")
    print("0x540f56/0x540f71: store the assembly image pointer xor 0x1a9b85df05d2c99d at assembly+0x10")
    print("0x540fd8: stores the assembly name pointer plus 0x460ad97e6aa0c5e3 at assembly+0x30")
    print("Static checks passed.")


if __name__ == "__main__":
    main()
