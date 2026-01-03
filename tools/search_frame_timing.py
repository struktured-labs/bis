#!/usr/bin/env python3
"""
Search for frame timing patterns in BIS code.bin.

3DS games typically use:
1. GSP service for VSync/frame management
2. A frame counter or skip flag
3. Timer-based frame limiting

The 60fps cheat sets certain bytes to 0 (60fps) or 1 (30fps).
We're looking for initialization or comparison with these values.
"""

import struct
from pathlib import Path


def search_for_init_patterns(code: bytes):
    """
    Search for byte patterns that might initialize fps to 30.

    Common patterns:
    - MOV Rx, #1 followed by STR/STRB
    - LDR of value 1 from literal pool
    """
    print("Searching for potential 30fps initialization patterns...")
    print("=" * 70)

    # In ARM Thumb, MOV Rd, #imm8 is encoded as: 001 00 ddd iiiiiiii
    # For MOV R0, #1: 0010 0000 0000 0001 = 0x2001
    # For MOV R1, #1: 0010 0001 0000 0001 = 0x2101
    # etc.

    thumb_mov_1_patterns = [
        (b'\x01\x20', 'movs r0, #1'),
        (b'\x01\x21', 'movs r1, #1'),
        (b'\x01\x22', 'movs r2, #1'),
        (b'\x01\x23', 'movs r3, #1'),
        (b'\x01\x24', 'movs r4, #1'),
        (b'\x01\x25', 'movs r5, #1'),
        (b'\x01\x26', 'movs r6, #1'),
        (b'\x01\x27', 'movs r7, #1'),
    ]

    # STRB Rd, [Rn, #imm] in Thumb is: 0111 0 iiiii nnn ddd
    # For small offsets like 0x44, 0x64, 0x74...

    print("\nLooking for MOV Rx, #1 instructions and their context...")

    results = []
    for pattern, name in thumb_mov_1_patterns:
        offset = 0
        while True:
            idx = code.find(pattern, offset)
            if idx == -1:
                break
            # Look at surrounding bytes
            context_before = code[max(0, idx-8):idx]
            context_after = code[idx+2:idx+10]

            # Check if followed by STR/STRB (0x70-0x77 for STRB, 0x60-0x67 for STR word)
            if len(context_after) >= 2:
                next_byte = context_after[1] if len(context_after) > 1 else 0
                next_nibble = next_byte >> 4

                # STRB with small offset starts with 0x70-0x77
                if 0x70 <= next_byte <= 0x77:
                    # Extract the offset from the STRB instruction
                    strb_offset = (context_after[0] >> 6) | ((context_after[1] & 0x07) << 2)
                    strb_offset *= 1  # STRB uses byte offset directly
                    results.append((idx, name, f"followed by STRB with offset ~{strb_offset}"))

            offset = idx + 1

    print(f"\nFound {len(results)} MOV #1 -> STRB patterns:")
    for offset, instr, note in results[:50]:
        print(f"  0x{offset:06X}: {instr} ({note})")

    return results


def search_literal_pool(code: bytes):
    """Search for values that might be frame timing constants."""
    print("\n\nSearching for frame timing constants in literal pools...")
    print("=" * 70)

    # Common timing values:
    # 30fps: 33.33ms = 33333us, ~2000000 cycles at 268MHz
    # Frame counter values: 1, 2

    # Look for the value 1 as a 32-bit word (potential frame skip count)
    pattern = b'\x01\x00\x00\x00'
    count = 0
    for i in range(0, len(code) - 4, 4):  # Word-aligned
        if code[i:i+4] == pattern:
            # Check if this looks like a literal pool entry
            # (surrounded by other small values or code)
            count += 1
            if count <= 20:
                context = code[max(0, i-8):i+12]
                print(f"  0x{i:06X}: {context.hex()}")

    print(f"  ... found {count} occurrences of word value 1")


def search_for_comparison_patterns(code: bytes):
    """Search for CMP with 1 or 2 - common in frame skip logic."""
    print("\n\nSearching for CMP Rx, #1 and CMP Rx, #2 patterns...")
    print("=" * 70)

    # CMP Rn, #imm8 in Thumb: 0010 1nnn iiiiiiii
    # CMP R0, #1: 0010 1000 0000 0001 = 0x2801
    # CMP R0, #2: 0010 1000 0000 0010 = 0x2802

    cmp_patterns = [
        (b'\x01\x28', 'cmp r0, #1'),
        (b'\x02\x28', 'cmp r0, #2'),
        (b'\x01\x29', 'cmp r1, #1'),
        (b'\x02\x29', 'cmp r1, #2'),
    ]

    for pattern, name in cmp_patterns:
        count = code.count(pattern)
        print(f"  {name}: {count} occurrences")

        # Show first few with context
        offset = 0
        shown = 0
        while shown < 5:
            idx = code.find(pattern, offset)
            if idx == -1:
                break
            print(f"    0x{idx:06X}: {code[idx:idx+16].hex()}")
            offset = idx + 1
            shown += 1


def search_gsp_patterns(code: bytes):
    """Search for GSP service patterns related to display/vsync."""
    print("\n\nSearching for GSP service strings...")
    print("=" * 70)

    # GSP service name
    patterns = [
        b'gsp::Gpu',
        b'GSP',
        b'vblank',
        b'vsync',
        b'frame',
        b'VRAM',
        b'display',
    ]

    for pattern in patterns:
        idx = code.find(pattern.lower())
        if idx != -1:
            print(f"  Found '{pattern.decode()}' at 0x{idx:06X}")
            context = code[max(0, idx-8):idx+len(pattern)+8]
            print(f"    Context: {context}")

        idx = code.find(pattern)
        if idx != -1:
            print(f"  Found '{pattern.decode()}' at 0x{idx:06X}")


if __name__ == "__main__":
    code_path = Path("/home/struktured/projects/bis/build/extracted/exefs_dir/code.bin")
    code = code_path.read_bytes()

    search_for_init_patterns(code)
    search_literal_pool(code)
    search_for_comparison_patterns(code)
    search_gsp_patterns(code)

    print("\n\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
The 60fps cheat works at RUNTIME by modifying RAM values.
To create a ROM patch, you would need to:

1. Find where the game INITIALIZES the frame timing value to 1 (30fps)
   and change it to 0 (60fps)

OR

2. Find the frame skip CHECK and patch it to always use 60fps path

The cheat addresses (0x30000074, 0x300DA3AC, etc.) are RUNTIME RAM
addresses, not offsets into code.bin directly.

For a static ROM patch, you would need Ghidra or IDA analysis to
trace where these RAM values are written/read.
""")
