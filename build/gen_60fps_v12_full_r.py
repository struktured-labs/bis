#!/usr/bin/env python3
"""Generate 60fps R-toggle IPS patch for BIS v1.2.

STANDALONE patch - works on real 3DS hardware, no emulator mods needed.
Hold R button = 30fps (for stability in battles/transitions)
Release R = 60fps

Code cave: overwrites an unreferenced wait-loop at 0x104810 in .text
(no B/BL or literal xrefs in code.bin or the game's CRO modules).

Button state is read from the game's HID object at 0x42A6C0+4 (the shared
memory base chosen by the kernel). Do not hardcode 0x1000201C: that
address is Azahar/Citra-only and data-aborts on real hardware.
"""

import struct
import sys
import os

CODE_BIN = os.environ.get("BIS_V12_CODE_BIN", os.path.expanduser("~/projects/bis/tmp/update_v12/exefs_dir/code.bin"))
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "patches", "60fps_v12_full_r.ips")

HID_OBJECT = 0x0042A6C0


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
    # 1. CODE CAVE at file offset 0x004810 (vaddr 0x104810) - 44 bytes
    #    Overwrites an unreferenced wait-loop (no static xrefs).
    # =========================================================================
    # R is read from the game's HID object at 0x42A6C0. Offset +4 is the
    # HID shared-memory base from svcMapMemoryBlock (the game passes addr=0,
    # so the kernel chooses the VA). On Azahar that base is 0x10002000; on
    # real hardware it is a different address. The previous cave loaded
    # 0x1000201C directly; that address is unmapped on a real 3DS and
    # data-aborts at boot (Remillio dump on v1.0; GameBanana #14144835 on
    # v1.2). Null-check defaults to 60fps if HID is not yet initialised.
    # HID shm +0x1C = current pad state; bit 8 (0x100) = R, active-high.
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
    records.append((0x004810, cave))

    # Verify we're overwriting the expected unreferenced function
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
    orig1 = struct.unpack("<I", code[0x0828D8 : 0x0828D8 + 4])[0]
    orig2 = struct.unpack("<I", code[0x0828DC : 0x0828DC + 4])[0]
    assert orig1 == 0x15D50181, f"Expected LDRBNE at 0x0828D8, got {orig1:#010x}"
    assert orig2 == 0x15C4003D, f"Expected STRBNE at 0x0828DC, got {orig2:#010x}"
    nop_data = struct.pack("<2I", 0xE1A00000, 0xE1A00000)  # NOP, NOP
    records.append((0x0828D8, nop_data))
    print(f"  Writer: NOP x2 at file 0x0828D8 (was {orig1:08X} {orig2:08X})")

    ips_data = make_ips(records)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "wb") as f:
        f.write(ips_data)

    print(f"\nGenerated {OUTPUT}")
    print(f"  Size: {len(ips_data)} bytes")
    print(f"  Records: {len(records)}")
    print(f"  Code cave: 44 bytes at 0x004810 (HID object 0x42A6C0+4)")
    print(f"  Behavior: R released = 60fps, R held = 30fps")


if __name__ == "__main__":
    main()
