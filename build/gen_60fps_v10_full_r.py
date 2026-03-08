#!/usr/bin/env python3
"""Generate 60fps R-toggle IPS patch for BIS v1.0.

STANDALONE patch - works on real 3DS hardware, no emulator mods needed.
Hold R button = 30fps (for stability in battles/transitions)
Release R = 60fps

Code cave at 0x1660BC in .text (verified dead function, zero references).
"""

import struct
import os

CODE_BIN = os.path.expanduser("~/projects/bis/tmp/v10_extract/exefs_dir/code.bin")
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "patches", "60fps_v10_full_r.ips")


def make_ips(records):
    buf = b"PATCH"
    for offset, data in sorted(records):
        assert 0 <= offset <= 0xFFFFFF
        assert len(data) <= 0xFFFF
        buf += struct.pack(">I", offset)[1:]
        buf += struct.pack(">H", len(data))
        buf += data
    buf += b"EOF"
    return buf


def main():
    with open(CODE_BIN, "rb") as f:
        code = f.read()

    records = []

    # 1. CODE CAVE at file 0x0660BC (vaddr 0x1660BC), 52 bytes
    cave_foff = 0x0660BC
    cave_vaddr = 0x1660BC

    orig = struct.unpack("<I", code[cave_foff : cave_foff + 4])[0]
    assert orig == 0xE92D4010, f"Expected PUSH at cave, got {orig:#010x}"

    cave = struct.pack(
        "<13I",
        0xE92D400C,  # PUSH {R2,R3,LR}
        0xE59F2024,  # LDR  R2,[PC,#0x24]   ; load &global (0x3F71C0)
        0xE5922000,  # LDR  R2,[R2]          ; deref -> input base
        0xE3520000,  # CMP  R2,#0            ; null check
        0x0A000004,  # BEQ  default_60fps
        0xE2822A61,  # ADD  R2,R2,#0x61000
        0xE2822EC2,  # ADD  R2,R2,#0xC20
        0xE5922008,  # LDR  R2,[R2,#8]       ; load buttons
        0xE3120C01,  # TST  R2,#0x100        ; test R button
        0x13A01001,  # MOVNE R1,#1           ; R pressed -> 30fps
        0x03A01000,  # MOVEQ R1,#0           ; R not pressed -> 60fps
        0xE8BD800C,  # POP  {R2,R3,PC}
        0x003F71C0,  # .word 0x003F71C0
    )
    records.append((cave_foff, cave))

    # 2. Main frame loop: BL to code cave at 0x03E918
    orig = struct.unpack("<I", code[0x03E918 : 0x03E918 + 4])[0]
    assert orig == 0xE5D4103D, f"Expected LDRB R1,[R4,#0x3D] at 0x3E918, got {orig:#010x}"
    # BL encoding
    bl_offset = (cave_vaddr - (0x13E918 + 8)) // 4
    bl_instr = 0xEB000000 | (bl_offset & 0x00FFFFFF)
    records.append((0x03E918, struct.pack("<I", bl_instr)))
    print(f"  Main reader: BL 0x{cave_vaddr:06X} = 0x{bl_instr:08X}")

    # 3. Init-time reader at 0x180A84
    orig = struct.unpack("<I", code[0x180A84 : 0x180A84 + 4])[0]
    assert orig == 0xE5D4003D
    records.append((0x180A84, struct.pack("<I", 0xE3A00000)))

    # 4. FPS setter writers (v1.0 offsets)
    writer_patches = [
        (0x17C24C, 0xE3A00003, 0xE3A00000, "MOV R0,#3 -> #0 (lvl3)"),
        (0x17C260, 0xE3A00002, 0xE3A00000, "MOV R0,#2 -> #0 (lvl2)"),
        (0x17C274, 0xE3A00001, 0xE3A00000, "MOV R0,#1 -> #0 (lvl1)"),
    ]
    for foff, expected, replacement, desc in writer_patches:
        orig = struct.unpack("<I", code[foff : foff + 4])[0]
        assert orig == expected, f"Expected {expected:#010x} at {foff:#x}, got {orig:#010x}"
        records.append((foff, struct.pack("<I", replacement)))
        print(f"  Writer: {desc} at 0x{foff:06X}")

    # 5. Other readers (v1.0 offsets, mapped from v1.2 by context similarity)
    reader_patches = [
        (0x012A28, 0xE5D4203D, 0xE3A02000, "LDRB R2 -> MOV R2,#0"),
        (0x012B84, 0xE5D4203D, 0xE3A02000, "LDRB R2 -> MOV R2,#0"),
        (0x26311C, 0xE5D4003D, 0xE3A00000, "LDRB R0 -> MOV R0,#0"),
        (0x26BFE4, 0xE5D4103D, 0xE3A01000, "LDRB R1 -> MOV R1,#0"),
    ]
    for foff, expected, replacement, desc in reader_patches:
        orig = struct.unpack("<I", code[foff : foff + 4])[0]
        assert orig == expected, f"Expected {expected:#010x} at {foff:#x}, got {orig:#010x}"
        records.append((foff, struct.pack("<I", replacement)))
        print(f"  Reader: {desc} at 0x{foff:06X}")

    # 6. Conditional writer NOP at 0x082900 (v1.0)
    orig1 = struct.unpack("<I", code[0x082900 : 0x082900 + 4])[0]
    orig2 = struct.unpack("<I", code[0x082904 : 0x082904 + 4])[0]
    assert orig1 == 0x15D50181, f"Expected LDRBNE at 0x082900, got {orig1:#010x}"
    assert orig2 == 0x15C4003D, f"Expected STRBNE at 0x082904, got {orig2:#010x}"
    records.append((0x082900, struct.pack("<2I", 0xE1A00000, 0xE1A00000)))
    print(f"  Writer: NOP x2 at 0x082900")

    # Build and write
    ips_data = make_ips(records)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "wb") as f:
        f.write(ips_data)

    print(f"\nGenerated {OUTPUT}")
    print(f"  Size: {len(ips_data)} bytes, {len(records)} records")
    print(f"  Behavior: R released = 60fps, R held = 30fps")


if __name__ == "__main__":
    main()
