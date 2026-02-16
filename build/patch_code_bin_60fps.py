#!/usr/bin/env python3
"""
Patch decompressed code.bin to achieve 60fps - MULTI-PATCH approach.

The game has MULTIPLE frame limiters. All must be patched simultaneously.
CTRPF cheat modifies 4 locations for a reason - there are 4 frame limiting mechanisms.

Patch 1: Force 60fps path in main frame sync (42% of WaitSync calls)
  vaddr 0x0012E1EC: beq → nop (skip blocking VBlank wait, take 60fps skip-wait path)
  Flag at 0x3F81B3 controls path; NOP bypasses the check entirely.

Patch 2: Force VBlank loop count to 1 (16.9% of WaitSync calls)
  vaddr 0x0011B3EC: lsr r0, r0, #24 → mov r0, #1
  Loop count extracted from arg; force to 1 = wait 1 VBlank = 60fps.

Patch 3: Change frame state flag from 2 to 1 (24.1% of WaitSync calls)
  vaddr 0x001228D4: mov r0, #2 → mov r0, #1
  Writes to struct offset 0x76 (same offset CRO modules use for FPS).
  Value 2 = 30fps (wait 2 VBlanks), value 1 = 60fps.
"""
import struct
import sys
import os

BASE_ADDR = 0x00100000

PATCHES = {
    "skip_vblank_wait": {
        "vaddr": 0x0012E1EC,
        "old_bytes": struct.pack('<I', 0x0A000005),  # beq #0x12e208 (go to blocking VBlank wait)
        "new_bytes": struct.pack('<I', 0xE1A00000),  # nop (fall through to 60fps skip-wait path)
        "description": "NOP beq to skip blocking VBlank wait -> 60fps path",
    },
    "force_vblank_loop_1": {
        "vaddr": 0x0011B3EC,
        "old_bytes": struct.pack('<I', 0xE1A00C20),  # lsr r0, r0, #24
        "new_bytes": struct.pack('<I', 0xE3A00001),  # mov r0, #1
        "description": "Force VBlank loop count to 1 (was 2 for 30fps)",
    },
    "state_flag_1_not_2": {
        "vaddr": 0x001228D4,
        "old_bytes": struct.pack('<I', 0xE3A00002),  # mov r0, #2
        "new_bytes": struct.pack('<I', 0xE3A00001),  # mov r0, #1
        "description": "Write 1 to struct offset 0x76 instead of 2 (60fps flag)",
    },
}

def main():
    input_path = "tmp/decompressed/code_decompressed.bin"
    output_path = "tmp/decompressed/code_decompressed_60fps.bin"

    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    print(f"Input: {input_path} ({len(data)} bytes)")
    print(f"Virtual range: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + len(data):08X}")
    print()

    applied = 0
    for name, patch in PATCHES.items():
        offset = patch["vaddr"] - BASE_ADDR
        if offset < 0 or offset + len(patch["old_bytes"]) > len(data):
            print(f"SKIP {name}: offset 0x{offset:X} out of range")
            continue

        actual = bytes(data[offset:offset + len(patch["old_bytes"])])
        if actual != patch["old_bytes"]:
            print(f"FAIL {name}: expected {patch['old_bytes'].hex()} at 0x{offset:X}, got {actual.hex()}")
            continue

        data[offset:offset + len(patch["new_bytes"])] = patch["new_bytes"]
        print(f"OK   {name}: 0x{patch['vaddr']:08X} (offset 0x{offset:X})")
        print(f"     {patch['old_bytes'].hex()} → {patch['new_bytes'].hex()}")
        print(f"     {patch['description']}")
        applied += 1

    print(f"\nApplied {applied}/{len(PATCHES)} patches")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(data)
    print(f"Output: {output_path}")

if __name__ == "__main__":
    main()
