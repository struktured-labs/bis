#!/usr/bin/env python3
"""Generate 60fps R-toggle IPS patch for BIS v1.2.

STANDALONE patch - works on real 3DS hardware, no emulator mods needed.
Hold R button = 30fps (for stability in battles/transitions)
Release R = 60fps

Code cave approach: overwrites a verified-dead function at 0x104810 in .text
with R-button reading logic. Main frame loop BLs to code cave instead of
reading FPS byte directly.

Button state: game stores active-high buttons at [*(0x3F71C0) + 0x61C28].
R button = bit 8 (0x100).
"""

import struct
import sys
import os

CODE_BIN = os.path.expanduser("~/projects/bis/tmp/update_v12/exefs_dir/code.bin")
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "patches", "60fps_v12_full_r.ips")


def make_ips(records):
    """Build IPS file from list of (offset, data) tuples."""
    buf = b"PATCH"
    for offset, data in sorted(records):
        assert 0 <= offset <= 0xFFFFFF, f"Offset {offset:#x} out of range"
        assert len(data) <= 0xFFFF, f"Data too large: {len(data)}"
        buf += struct.pack(">I", offset)[1:]  # 3-byte BE offset
        buf += struct.pack(">H", len(data))  # 2-byte BE size
        buf += data
    buf += b"EOF"
    return buf


def main():
    with open(CODE_BIN, "rb") as f:
        code = f.read()

    records = []

    # =========================================================================
    # 1. CODE CAVE at file offset 0x004810 (vaddr 0x104810) - 52 bytes
    #    Overwrites dead function (verified: zero references in entire binary)
    #    Reads R button state from game's input global, returns FPS mode in R1
    # =========================================================================
    cave = struct.pack(
        "<13I",
        0xE92D400C,  # PUSH {R2,R3,LR}
        0xE59F2024,  # LDR  R2,[PC,#0x24]   ; load &global (0x3F71C0)
        0xE5922000,  # LDR  R2,[R2]          ; deref -> input base
        0xE3520000,  # CMP  R2,#0            ; null check (early init)
        0x0A000004,  # BEQ  default_60fps    ; if null, default to 60fps
        0xE2822A61,  # ADD  R2,R2,#0x61000   ; \
        0xE2822EC2,  # ADD  R2,R2,#0xC20     ;  } R2 += 0x61C20
        0xE5922008,  # LDR  R2,[R2,#8]       ; load buttons (0x61C28 total)
        0xE3120C01,  # TST  R2,#0x100        ; test R button (bit 8)
        0x13A01001,  # MOVNE R1,#1           ; R pressed -> 30fps
        0x03A01000,  # MOVEQ R1,#0           ; R not pressed -> 60fps
        0xE8BD800C,  # POP  {R2,R3,PC}       ; return
        0x003F71C0,  # .word 0x003F71C0      ; global input pointer address
    )
    assert len(cave) == 52
    records.append((0x004810, cave))

    # Verify we're overwriting the expected dead function
    orig = code[0x4810 : 0x4810 + 4]
    assert struct.unpack("<I", orig)[0] == 0xE92D4010, (
        f"Expected PUSH {{R4,LR}} at 0x4810, got {orig.hex()}"
    )

    # =========================================================================
    # 2. MAIN FRAME LOOP READER at 0x03E8E8 (vaddr 0x13E8E8)
    #    Replace: LDRB R1,[R4,#0x3D]  (E5D4103D)
    #    With:    BL   code_cave      (EBFF17C8)
    # =========================================================================
    orig = struct.unpack("<I", code[0x03E8E8 : 0x03E8E8 + 4])[0]
    assert orig == 0xE5D4103D, f"Expected LDRB R1,[R4,#0x3D] at 0x3E8E8, got {orig:#010x}"
    records.append((0x03E8E8, struct.pack("<I", 0xEBFF17C8)))

    # =========================================================================
    # 3. INIT-TIME READER at 0x180A5C (vaddr 0x280A5C)
    #    Replace: LDRB R0,[R4,#0x3D]  (E5D4003D)
    #    With:    MOV  R0,#0          (E3A00000) - always 60fps at init
    # =========================================================================
    orig = struct.unpack("<I", code[0x180A5C : 0x180A5C + 4])[0]
    assert orig == 0xE5D4003D, f"Expected LDRB R0,[R4,#0x3D] at 0x180A5C, got {orig:#010x}"
    records.append((0x180A5C, struct.pack("<I", 0xE3A00000)))

    # =========================================================================
    # 4. FPS SETTER WRITERS - force all levels to 0 (60fps in memory)
    #    The FPS setter at 0x27C124 has 3 MOV R0,#level instructions
    #    that feed into STRB R0,[R4,#0x3D]. Force all to MOV R0,#0.
    # =========================================================================
    writer_patches = [
        (0x17C224, 0xE3A00003, 0xE3A00000, "MOV R0,#3 -> MOV R0,#0 (lvl3)"),
        (0x17C238, 0xE3A00002, 0xE3A00000, "MOV R0,#2 -> MOV R0,#0 (lvl2)"),
        (0x17C24C, 0xE3A00001, 0xE3A00000, "MOV R0,#1 -> MOV R0,#0 (lvl1)"),
    ]
    for foff, expected, replacement, desc in writer_patches:
        orig = struct.unpack("<I", code[foff : foff + 4])[0]
        assert orig == expected, f"Expected {expected:#010x} at {foff:#x}, got {orig:#010x}"
        records.append((foff, struct.pack("<I", replacement)))
        print(f"  Writer: {desc} at file 0x{foff:06X}")

    # =========================================================================
    # 5. OTHER READERS - force to MOV #0 (from v3 comprehensive patch)
    # =========================================================================
    reader_patches = [
        (0x012B54, 0xE5D4203D, 0xE3A02000, "LDRB R2,[R4,#0x3D] -> MOV R2,#0"),
        (0x012CB0, 0xE5D4203D, 0xE3A02000, "LDRB R2,[R4,#0x3D] -> MOV R2,#0"),
        (0x263250, 0xE5D4003D, 0xE3A00000, "LDRB R0,[R4,#0x3D] -> MOV R0,#0"),
        (0x26C114, 0xE5D4103D, 0xE3A01000, "LDRB R1,[R4,#0x3D] -> MOV R1,#0"),
    ]
    for foff, expected, replacement, desc in reader_patches:
        orig = struct.unpack("<I", code[foff : foff + 4])[0]
        assert orig == expected, f"Expected {expected:#010x} at {foff:#x}, got {orig:#010x}"
        records.append((foff, struct.pack("<I", replacement)))
        print(f"  Reader: {desc} at file 0x{foff:06X}")

    # =========================================================================
    # 6. CONDITIONAL WRITER NOP at 0x0828D8 (from v3)
    # =========================================================================
    # LDRBNE R0,[R5,#0x181] + STRBNE R0,[R4,#0x3D] - conditional write of non-zero
    orig1 = struct.unpack("<I", code[0x0828D8 : 0x0828D8 + 4])[0]
    orig2 = struct.unpack("<I", code[0x0828DC : 0x0828DC + 4])[0]
    assert orig1 == 0x15D50181, f"Expected LDRBNE at 0x0828D8, got {orig1:#010x}"
    assert orig2 == 0x15C4003D, f"Expected STRBNE at 0x0828DC, got {orig2:#010x}"
    nop_data = struct.pack("<2I", 0xE1A00000, 0xE1A00000)  # NOP, NOP
    records.append((0x0828D8, nop_data))
    print(f"  Writer: NOP x2 at file 0x0828D8 (was {orig1:08X} {orig2:08X})")

    # Build and write IPS
    ips_data = make_ips(records)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "wb") as f:
        f.write(ips_data)

    print(f"\nGenerated {OUTPUT}")
    print(f"  Size: {len(ips_data)} bytes")
    print(f"  Records: {len(records)}")
    print(f"\nPatch summary:")
    print(f"  Code cave: 52 bytes at 0x004810 (R-button toggle logic)")
    print(f"  Main reader: BL to code cave at 0x03E8E8")
    print(f"  Init reader: MOV R0,#0 at 0x180A5C")
    print(f"  FPS setter writers: 3x MOV R0,#0")
    print(f"  Other readers: 4x MOV Rx,#0")
    print(f"  Conditional writer: 2x NOP at 0x0828D8")
    print(f"\nBehavior:")
    print(f"  R button released: 60fps")
    print(f"  R button held: 30fps")


if __name__ == "__main__":
    main()
