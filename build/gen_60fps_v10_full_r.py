#!/usr/bin/env python3
"""Generate 60fps R-toggle IPS patch for BIS v1.0.

STANDALONE patch - works on real 3DS hardware, no emulator mods needed.
Hold R button = 30fps (for stability in battles/transitions)
Release R = 60fps

Code cave is in the zero padding at the end of the last .text page
(vaddr 0x389F00; .rodata starts at 0x38A000). Earlier caves overwrote live
code: 0x10378C (v1.2.1 and before) is a CloseHandle used at shutdown, and
0x1047C8 (v1.2.2) is the body of a boot-time sync routine entered at
0x1047C4 (BL from 0x101A24) that waits for a worker thread to set
[0x42A818+0x29C]. Azahar's thread scheduling hid that race.

Button state is read from the game's HID object at 0x42A6C0+4 (same
address in v1.0 and v1.2). Do not hardcode 0x1000201C.
"""

import struct
import os

CODE_BIN = os.environ.get("BIS_V10_CODE_BIN") or os.path.expanduser("~/projects/bis/tmp/v10_extract/exefs_dir/code.bin")
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "patches", "60fps_v10_full_r.ips")

HID_OBJECT = 0x0042A6C0


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

    # 1. CODE CAVE at file 0x289F00 (vaddr 0x389F00), 44 bytes, in the
    # zero padding after the end of .text (last code byte is file 0x2890E7;
    # the 650th text page ends at 0x28A000). Nothing references it.
    cave_foff = 0x289F00
    cave_vaddr = 0x389F00
    assert code[0x2890E8:0x28A000] == bytes(0x28A000 - 0x2890E8), "text tail padding not zero"

    # R is read from the game's HID object at 0x42A6C0+4 (kernel-chosen
    # shm VA). Hardcoding 0x1000201C data-aborts on real hardware.
    # Null-check defaults to 60fps if HID is not yet initialised.
    cave = struct.pack(
        "<11I",
        0xE92D4004,  # PUSH {R2,LR}
        0xE59F201C,  # LDR  R2,[PC,#0x1C]   ; =HID_OBJECT
        0xE5922004,  # LDR  R2,[R2,#4]      ; shm base
        0xE3520000,  # CMP  R2,#0
        0x0A000002,  # BEQ  default_60
        0xE592201C,  # LDR  R2,[R2,#0x1C]   ; current pad
        0xE3120C01,  # TST  R2,#0x100       ; R button (bit 8)
        0x13A01001,  # MOVNE R1,#1          ; R held -> 30fps
        0x03A01000,  # MOVEQ R1,#0          ; default_60 / R released -> 60fps
        0xE8BD8004,  # POP  {R2,PC}
        HID_OBJECT,
    )
    assert len(cave) == 44
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
        (0x17C288, 1, "FPS setter STRB"),          # FPS setter final write
    ]
    for foff, count, desc in strb_nops:
        nop_data = struct.pack(f"<{count}I", *([0xE1A00000] * count))
        records.append((foff, nop_data))
        print(f"  NOP: {desc} at 0x{foff:06X} ({count} instr)")

    # 6. Constructor init of +0x3D: original writes 0xFF (STRB R0). Earlier
    # builds NOPed it, leaving the byte uninitialised heap memory that four
    # unpatched readers (0x112A28, 0x112B84, 0x36311C, 0x36BFE4) still see.
    # Store R5 instead (R5 = 0 since 0x24B454) so it is deterministically 0.
    orig = struct.unpack("<I", code[0x14B474 : 0x14B478])[0]
    assert orig == 0xE5C4003D, f"Expected STRB R0,[R4,#0x3D] at 0x14B474, got {orig:#010x}"
    assert struct.unpack("<I", code[0x14B454 : 0x14B458])[0] == 0xE3A05000, "expected MOV R5,#0"
    records.append((0x14B474, struct.pack("<I", 0xE5C4503D)))  # STRB R5,[R4,#0x3D]
    print("  Init: STRB R5 (=0) at 0x14B474")

    ips_data = make_ips(records)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "wb") as f:
        f.write(ips_data)

    print(f"\nGenerated {OUTPUT}")
    print(f"  Size: {len(ips_data)} bytes, {len(records)} records")
    print(f"  Code cave: 44 bytes at 0x{cave_foff:06X} (HID object 0x42A6C0+4)")
    print(f"  Behavior: R released = 60fps, R held = 30fps")


if __name__ == "__main__":
    main()
