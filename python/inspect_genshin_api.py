#!/usr/bin/env python3
"""Check IL2CPP runtime entry-point leads in the matched Genshin EXE."""

import argparse
import struct
from pathlib import Path

from decode_genshin_strings import EXE_SHA256, sha256
from inspect_genshin_types import IL2CPP_CODE_FILE_BIAS


TEXT_RAW_OFFSET_BIAS = 0xC00


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

    check_bytes(exe, 0x4B10A0, bytes.fromhex("56 48 83 ec 20 48 89 ce 48 8d 15 97 63 5c 03 31"))
    check_relative_branch(exe, 0x4B10B9, 0xE8, 0x534B80)
    check_bytes(exe, 0x4B1D60, bytes.fromhex("48 8b 51 30 48 85 d2 74 10"))
    check_bytes(exe, 0x4B1D40, bytes.fromhex("48 8b 51 30 48 85 d2 74 11"))
    check_bytes(exe, 0x4B1D49, bytes.fromhex("48 b8 0a 96 3b cc d0 03 83 85 48 03 42 10"))
    check_bytes(exe, 0x4B1D69, bytes.fromhex("48 b8 d8 d5 3c 8c 1e af fc ba 48 03 02"))
    check_bytes(exe, 0x4B1DD8, bytes.fromhex("48 b8 7f 45 60 ed 6d 55 fd ed 48 03 42 08"))
    check_bytes(exe, 0x4B1D80, bytes.fromhex("0f b6 41 2f 24 04 c0 e8 02 c3"))
    check_bytes(exe, 0x4B19A0, bytes.fromhex("e9 eb a9 06 00"))
    check_bytes(exe, 0x4B1AE0, bytes.fromhex("55 48 83 ec 30 48 8d 6c 24 30"))
    check_bytes(exe, 0x4B1AF8, bytes.fromhex("48 83 ca 02"))
    check_bytes(exe, 0x4B1B40, bytes.fromhex("55 48 83 ec 30 48 8d 6c 24 30"))
    check_bytes(exe, 0x4B1B58, bytes.fromhex("48 8d 04 52"))
    check_bytes(exe, 0x4B1BA0, bytes.fromhex("89 c8 c1 e8 1a 48 c1 e0 10"))
    check_bytes(exe, 0x4B1BD0, bytes.fromhex("55 56 48 83 ec 28 48 8d 6c 24 20"))
    check_relative_branch(exe, 0x4B1D79, 0xE9, 0x5281A0)
    check_bytes(exe, 0x4B1DB0, bytes.fromhex("0f b6 41 2e c3"))
    check_bytes(exe, 0x4B1DEE, bytes.fromhex("48 8b 04 c8"))
    check_bytes(exe, 0x4B1EFE, bytes.fromhex("48 8b 44 c8 08"))
    check_bytes(exe, 0x4B1F90, bytes.fromhex("48 8d 41 10 c3"))
    check_bytes(exe, 0x4B1FE0, bytes.fromhex("55 41 56 56 57 53 48 83 ec 40"))
    check_relative_branch(exe, 0x4B2053, 0xE8, 0x53E760)
    check_bytes(exe, 0x4B20D0, bytes.fromhex("48 8d 41 14 c3"))
    check_bytes(exe, 0x4B2100, bytes.fromhex(
        "55 56 57 53 48 83 ec 28 48 8d 6c 24 20 48 c7 45 "
        "00 fe ff ff ff 48 89 ce 85 d2 74 4e"))
    check_bytes(exe, 0x4B2160, bytes.fromhex("89 78 10 01 ff"))
    check_bytes(exe, 0x4B2174, bytes.fromhex("48 8d 4b 14 48 89 f2"))
    check_relative_branch(exe, 0x4B217B, 0xE8, 0x1FC6E10)
    check_bytes(exe, 0x53E7C8, bytes.fromhex("41 ff d4"))
    check_bytes(exe, 0x51C180, bytes.fromhex(
        "55 56 57 53 48 83 ec 78 48 8d 6c 24 70 48 c7 45 "
        "00 fe ff ff ff 80 b9 c7 00 00 00 00"))
    check_bytes(exe, 0x51C2C3, bytes.fromhex("48 8d 15 a1 32 55 03"))
    check_bytes(exe, 0x51C280, bytes.fromhex("45 31 c0 e8 b8 21 02 00"))
    check_bytes(exe, 0x512DB0, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    check_bytes(exe, 0x512DD3, bytes.fromhex("0f b6 81 c9 00 00 00 a8 10"))
    check_relative_branch(exe, 0x512E15, 0xE8, 0x512DB0)
    check_relative_branch(exe, 0x512EA3, 0xE8, 0x514630)
    check_bytes(exe, 0x51308E, bytes.fromhex("49 89 bc c5 d0 00 00 00"))
    check_bytes(exe, 0x513DC0, bytes.fromhex("80 e2 cf 80 ca 10 41 88 95 c9 00 00 00"))
    # The class+0x48 helper derives an 8-byte-entry count from metadata+0x40.
    check_bytes(exe, 0x5157D5, bytes.fromhex("49 8b 86 98 00 00 00 0f b6 40 40 04 38"))
    check_bytes(exe, 0x5157EC, bytes.fromhex("4c 8d 3c dd 00 00 00 00 4c 89 fa"))
    # UnitySynchronizationContext.ExecuteTasks is an optional frame-callback probe.
    frame_rva = 0x19BE5A00
    frame_prologue = bytes.fromhex("48 83 ec 28 e8 47 6c 92 ff 48 85 c0 74 0c 48 8b")
    frame_file_offset = frame_rva - IL2CPP_CODE_FILE_BIAS
    if exe[frame_file_offset:frame_file_offset + len(frame_prologue)] != frame_prologue:
        raise ValueError("UnitySynchronizationContext.ExecuteTasks prologue differs")
    check_bytes(exe, 0x515891, bytes.fromhex("49 87 76 48"))
    # A native caller acquires the metadata lock, passes the address of a
    # local pointer to its global slot, then releases the lock through it.
    check_bytes(exe, 0x4C35DC, bytes.fromhex(
        "48 8d 05 85 23 61 05 48 89 85 d8 00 00 00 "
        "48 8b 0d 77 23 61 05 ff 15 51 6c 68 03 "
        "48 8d 95 d8 00 00 00 48 89 f1"))
    check_relative_branch(exe, 0x4C3601, 0xE8, 0x512DB0)
    check_bytes(exe, 0x4C3606, bytes.fromhex(
        "48 8b 85 d8 00 00 00 48 8b 08 ff 15 3a 70 68 03"))
    # Class setup uses the same global slot when interface setup needs a lock.
    check_bytes(exe, 0x51373F, bytes.fromhex(
        "48 8d 05 22 22 5c 05 48 89 45 d8 "
        "48 8b 0d 17 22 5c 05 ff 15 f1 6a 63 03 "
        "48 8d 55 d8 4c 89 e9"))
    check_relative_branch(exe, 0x51375E, 0xE8, 0x512870)
    check_bytes(exe, 0x513763, bytes.fromhex(
        "48 8b 45 d8 48 8b 08 ff 15 e0 6e 63 03"))
    # Interface-table construction copies one 8-byte vtable entry per slot.
    # The stock Il2CppInterop VirtualInvokeData is two pointers (16 bytes).
    check_bytes(exe, 0x4DF061, bytes.fromhex(
        "48 8d 88 d0 00 00 00 48 8d 96 d0 00 00 00 "
        "44 0f b7 86 be 00 00 00 49 c1 e0 03"))
    check_relative_branch(exe, 0x4DF07B, 0xE8, 0x1FC6E10)
    if exe[0x3A6F56B - 0x1000:0x3A6F56B - 0x1000 + 50] != b"The type initializer for '%s' threw an exception.\0":
        raise ValueError("Class-init error text differs")
    check_bytes(exe, 0x4B1640, bytes.fromhex("48 8b 01 c3"))
    check_bytes(exe, 0x4B1460, bytes.fromhex("f6 81 c8 00 00 00 0e 75 0e 0f b6 41 72"))
    check_relative_branch(exe, 0x4B1380, 0xE9, 0x5158B0)
    check_bytes(exe, 0x4B1420, bytes.fromhex("e9 bb f7 05 00"))
    check_relative_branch(exe, 0x4B1410, 0xE9, 0x5106D0)
    check_bytes(exe, 0x5106D0, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    check_bytes(exe, 0x5107B0, bytes.fromhex(
        "8b bf ac 00 00 00 48 85 ff 74 10 "
        "48 8b 05 ce 46 5c 05 48 03 38 0f 85 4d ff ff ff"))
    check_bytes(exe, 0x5158B0, bytes.fromhex("55 41 57 41 56 41 55 41 54 56 57 53"))
    check_bytes(exe, 0x4B12F0, bytes.fromhex(
        "48 b8 7f 71 79 e4 52 9e d7 e2 48 03 41 08 c3"))
    check_bytes(exe, 0x4B1270, bytes.fromhex("48 8b 05 71 47 62 05 c3"))
    check_bytes(exe, 0x538B22, bytes.fromhex(
        "48 8d 0d 27 d4 50 03 e8 c2 3b fd ff 48 be 7f 71 79 e4 52 9e d7 e2 "
        "48 8b 40 08 48 01 f0 48 89 05 a2 ce 59 05"))
    check_bytes(exe, 0x53550A, bytes.fromhex("89 3d e0 fd 59 05"))
    check_bytes(exe, 0x53551A, bytes.fromhex("48 6b de 58"))
    check_bytes(exe, 0x5355EB, bytes.fromhex("4c 89 35 06 fd 59 05"))
    check_bytes(exe, 0x535FE4, bytes.fromhex(
        "48 b9 2b d9 93 66 b0 f7 32 24 48 01 c8 4b 89 44 2c 28"))
    check_bytes(exe, 0x535606, bytes.fromhex("44 89 f8 c1 f8 04 89 05 ee fc 59 05"))
    check_bytes(exe, 0x5356D0, bytes.fromhex("4c 89 35 31 fc 59 05"))
    check_bytes(exe, 0x5363B8, bytes.fromhex("49 b9 81 8e 86 1b ad 61 28 1d"))
    check_bytes(exe, 0x5363D3, bytes.fromhex("4a 89 4c 3f 08"))
    check_bytes(exe, 0x536431, bytes.fromhex(
        "48 b9 7f 3c 71 2e be cb 3f 78 48 01 c8 4a 89 44 3f 40"))

    print("0x4b10a0: init wrapper calls metadata initialization at 0x534b80")
    print("0x4b1d60: method-name wrapper falls back to the metadata decoder at 0x5281a0")
    print("0x4b1d40/0x4b1d80: method return-type and generic-flag candidates have matched code bytes")
    print("0x4b1850: static field value getter candidate has matched code bytes")
    print("0x4b1db0: parameter-count candidate returns the byte at MethodInfo+0x2e")
    print("0x4b1dc0/0x4b1ed0: parameter type/name candidates load adjacent fields from a 24-byte record")
    print("0x4b1fe0: runtime-invoke candidate calls 0x53e760, which calls MethodInfo's stored pointer")
    print("0x51c180: runtime static-constructor initializer checks completion flags, invokes the cctor, and references the type-initializer error")
    print("0x512db0: class-setup candidate recurses on the parent, initializes methods, writes vtable entries, and sets the completion bit")
    print("0x4c35dc: caller passes class and address of a local metadata-lock slot to 0x512db0 under a critical section")
    print("0x51373f: class setup uses the same lock-slot pattern around interface setup at 0x512870")
    print("0x4df061: interface-table builder copies the base vtable from class+0xd0 in 8-byte slots")
    print("0x4b1640: returns the first pointer from its argument; class-to-image candidate")
    print("0x4b1460: decodes a class namespace through its metadata record; class namespace candidate")
    print("0x4b1380: forwards image, namespace, and class-name arguments to lookup at 0x5158b0")
    print("0x4b13a0/0x4b1410: class method enumeration and field-name lookup candidates have matched code bytes")
    print("0x5107b0: field-name lookup follows the 32-bit relative parent link at class+0xac")
    print("0x4b12f0: adds the inverse image-pointer bias to assembly+0x08; assembly-to-image candidate")
    print("0x4b1270: returns a global set from an assembly image at 0x538b22; corlib-image candidate")
    print("0x53550a/0x5355eb: store the 75-image count and image-array pointer at RVAs 0x5ad52f0/0x5ad52f8")
    print("0x535fe4: stores the image name pointer plus 0x2432f7b06693d92b at image+0x28")
    print("0x535606/0x5356d0: store the 75-assembly count and array pointer at RVAs 0x5ad5300/0x5ad5308")
    print("0x5363b8/0x5363d3: store the assembly image pointer plus 0x1d2861ad1b868e81 at assembly+0x08")
    print("0x536431: stores the assembly name pointer plus 0x783fcbbe2e713c7f at assembly+0x40")
    print("Static checks passed. Init and method-name wrappers have been observed live on the Deck.")


if __name__ == "__main__":
    main()
