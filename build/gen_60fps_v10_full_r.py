#!/usr/bin/env python3
"""Generate 60fps R-toggle IPS patch for BIS v1.0.

STANDALONE patch - works on real 3DS hardware, no emulator mods needed.
Hold R button = 30fps (for stability in battles/transitions)
Release R = 60fps

Code cave at 0x10378C in .text (verified dead via automated save screen test).
Input pointer at 0x3F71C0 (same vaddr in v1.0 and v1.2).
All +0x3D writers NOP'd to prevent game from overriding toggle state.
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

    # 1. CODE CAVE at file 0x00378C (vaddr 0x10378C), 52 bytes
    # Verified dead via NOP + save screen automated test.
    # (0x0660BC was LIVE code — called via vtable during save screen!)
    cave_foff = 0x00378C
    cave_vaddr = 0x10378C

    orig = struct.unpack("<I", code[cave_foff : cave_foff + 4])[0]
    assert orig == 0xE92D4010, f"Expected PUSH at cave, got {orig:#010x}"

    # 8 instructions = 32 bytes.
    # Reads R button directly from HID SharedMemory at fixed address 0x10002000.
    # HID SharedMemory pad state: base + 0x1C (PadData) + 0x10 (current_state.hex)
    # Button bits: active-LOW on 3DS (0 = pressed). Bit 8 = R button.
    cave = struct.pack(
        "<8I",
        0xE92D4004,  # PUSH {R2,LR}
        0xE59F2010,  # LDR  R2,[PC,#0x10]   ; load HID shm+0x2C address
        0xE5922000,  # LDR  R2,[R2]          ; load current pad state
        0xE3120C01,  # TST  R2,#0x100        ; test R button (bit 8, active-high)
        0x13A01001,  # MOVNE R1,#1           ; R pressed (bit=1) -> 30fps
        0x03A01000,  # MOVEQ R1,#0           ; R not pressed (bit=0) -> 60fps
        0xE8BD8004,  # POP  {R2,PC}
        0x1000201C,  # .word 0x1000201C      ; HID SharedMem + 0x1C = current_state
    )
    records.append((cave_foff, cave))

    # 2. Main frame loop: BL to code cave at 0x03E918
    orig = struct.unpack("<I", code[0x03E918 : 0x03E918 + 4])[0]
    assert orig == 0xE5D4103D, f"Expected LDRB R1,[R4,#0x3D] at 0x3E918, got {orig:#010x}"
    bl_offset = (cave_vaddr - (0x13E918 + 8)) // 4
    bl_instr = 0xEB000000 | (bl_offset & 0x00FFFFFF)
    records.append((0x03E918, struct.pack("<I", bl_instr)))
    print(f"  Main reader: BL 0x{cave_vaddr:06X} = 0x{bl_instr:08X}")

    # 3. Init-time reader at 0x180A84: always 60fps during init
    orig = struct.unpack("<I", code[0x180A84 : 0x180A84 + 4])[0]
    assert orig == 0xE5D4003D
    records.append((0x180A84, struct.pack("<I", 0xE3A00000)))

    # 4. FPS setter writers: force MOV R0,#0 (60fps) for all levels
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

    # 5. NOP all STRB [R4,#0x3D] writers to prevent game from overriding toggle
    strb_nops = [
        (0x082900, 2, "conditional LDRB+STRB"),  # LDRBNE + STRBNE pair
        (0x14B474, 1, "init STRB R0"),            # writes 0xFF during init
        (0x17C288, 1, "FPS setter STRB"),          # FPS setter final write
    ]
    for foff, count, desc in strb_nops:
        nop_data = struct.pack(f"<{count}I", *([0xE1A00000] * count))
        records.append((foff, nop_data))
        print(f"  NOP: {desc} at 0x{foff:06X} ({count} instr)")

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
