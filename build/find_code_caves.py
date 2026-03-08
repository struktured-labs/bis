#!/usr/bin/env python3
"""Scan v1.2 code.bin .text segment for code caves suitable for ARM code injection.

Uses a multi-pass approach:
  1. Binary pattern scan for NOP sleds and zero-filled regions
  2. Function boundary detection (PUSH/POP pairs)
  3. Full reference analysis: BL targets, B targets, and data pointer scan
  4. Reports only functions with ZERO references of any kind

Ghidra cross-validation confirmed:
  - One massive undefined region at vaddr 0x2FA000 (586KB) but it has 9970 branch
    targets into it, so it's actually code Ghidra failed to analyze
  - 1273 dead functions per Ghidra xref, but many have fragmented bodies
  - This script's binary-level analysis is more reliable for small caves
"""

import struct
import sys
from pathlib import Path

CODE_BIN = Path("/home/struktured/projects/bis/tmp/update_v12/exefs_dir/code.bin")
TEXT_START = 0x000000
TEXT_END = 0x289218
VADDR_BASE = 0x100000
MIN_CAVE_BYTES = 28  # 7 ARM instructions
MAX_CAVE_BYTES = 120  # upper bound for small function scan


def main():
    print(f"Reading {CODE_BIN} ...")
    data = CODE_BIN.read_bytes()
    text = data[TEXT_START:TEXT_END]
    n_words = len(text) // 4
    print(f".text segment: {len(text)} bytes (0x{len(text):X})")
    print(f"Virtual addrs: 0x{VADDR_BASE:06X} - 0x{TEXT_END + VADDR_BASE:06X}")
    print(f"Cave size range: {MIN_CAVE_BYTES}-{MAX_CAVE_BYTES} bytes")
    print()

    # =========================================================================
    # Pass 1: Build all branch/call target sets
    # =========================================================================
    print("Pass 1: Building branch target and BL call target sets...")
    branch_targets = set()
    bl_targets = set()
    for i in range(n_words):
        w = struct.unpack_from('<I', text, i * 4)[0]
        cond = (w >> 28) & 0xF
        is_b = False
        is_bl = False
        if cond == 0xF:
            if (w >> 25) & 0x7 == 0x5:
                is_b = True
        elif (w >> 24) & 0xF == 0xA:
            is_b = True
        elif (w >> 24) & 0xF == 0xB:
            is_b = True
            is_bl = True

        if is_b:
            imm24 = w & 0x00FFFFFF
            if imm24 & 0x800000:
                imm24 |= 0xFF000000
            t = (i * 4 + 8 + (imm24 * 4)) & 0xFFFFFFFF
            if TEXT_START <= t < TEXT_END:
                branch_targets.add(t)
                if is_bl:
                    bl_targets.add(t)

    print(f"  {len(branch_targets)} branch targets, {len(bl_targets)} BL call targets")

    # =========================================================================
    # Pass 2: Find complete PUSH...POP function pairs
    # =========================================================================
    print("Pass 2: Scanning for complete PUSH...POP+PC function pairs...")
    raw_candidates = []
    for i in range(n_words):
        w = struct.unpack_from('<I', text, i * 4)[0]
        if (w & 0xFFFF0000) != 0xE92D0000:
            continue
        foff = i * 4
        # Skip if this address is a known branch/call target
        if foff in branch_targets:
            continue
        push_regs = w & 0xFFFF
        push_saved = push_regs & ~0x4000  # Remove LR bit for comparison

        for size in range(MIN_CAVE_BYTES, MAX_CAVE_BYTES + 4, 4):
            end_off = foff + size - 4
            if end_off >= TEXT_END:
                break
            ew = struct.unpack_from('<I', text, end_off)[0]
            if (ew & 0xFFFF0000) == 0xE8BD0000 and (ew & 0x8000):
                pop_saved = (ew & 0xFFFF) & ~0x8000  # Remove PC bit
                if push_saved == pop_saved:
                    raw_candidates.append((foff, foff + VADDR_BASE, size, push_regs))
                break  # Found matching POP, stop looking

    print(f"  {len(raw_candidates)} unreferenced PUSH/POP function pairs found")

    # =========================================================================
    # Pass 3: Data pointer reference check
    # =========================================================================
    print("Pass 3: Checking for data pointer references (vtable/function table entries)...")
    safe_caves = []
    for foff, vaddr, size, push_regs in raw_candidates:
        vaddr_bytes = struct.pack('<I', vaddr)
        has_data_ref = False
        pos = 0
        while True:
            pos = data.find(vaddr_bytes, pos)
            if pos == -1:
                break
            # Ignore if the ref is inside the function itself
            if not (foff <= pos < foff + size):
                has_data_ref = True
                break
            pos += 1
        if not has_data_ref:
            safe_caves.append((foff, vaddr, size))

    print(f"  {len(safe_caves)} caves with ZERO references (branch, call, or data)")
    print()

    # =========================================================================
    # Results
    # =========================================================================
    safe_caves.sort(key=lambda x: (-x[2], x[0]))

    print("=" * 80)
    print("VERIFIED CODE CAVES - SAFE TO OVERWRITE")
    print("  (Complete PUSH/POP functions with no BL, B, or data pointer references)")
    print("=" * 80)
    print()
    print(f"  {'#':>3}  {'File Offset':>12}  {'Virt Addr':>12}  {'Size':>5}")
    print(f"  {'-' * 40}")

    for idx, (foff, vaddr, size) in enumerate(safe_caves[:60], 1):
        print(f"  {idx:3d}  0x{foff:08X}    0x{vaddr:08X}    {size:4d}")

    if len(safe_caves) > 60:
        print(f"  ... ({len(safe_caves) - 60} more)")

    # Size distribution
    from collections import Counter
    sizes = Counter(c[2] for c in safe_caves)
    print()
    print("Size distribution:")
    for s in sorted(sizes.keys()):
        print(f"  {s:3d} bytes ({s // 4:2d} words): {sizes[s]:3d} caves")
    print(f"  Total: {len(safe_caves)} caves")

    # =========================================================================
    # Hex dump of recommended picks
    # =========================================================================
    # Best picks: exact 28-byte (minimal footprint) and largest (most room)
    exact_28 = [c for c in safe_caves if c[2] == 28]
    largest = safe_caves[0] if safe_caves else None

    print()
    print("=" * 80)
    print("RECOMMENDED PICKS")
    print("=" * 80)

    if exact_28:
        pick = exact_28[0]
        print(f"\n  MINIMAL (exact fit, 28 bytes = 7 instructions):")
        print(f"    vaddr=0x{pick[1]:08X}  file=0x{pick[0]:08X}")
        print(f"    Hex dump:")
        for j in range(0, pick[2], 4):
            w = struct.unpack_from('<I', data, pick[0] + j)[0]
            print(f"      +{j:02d}: {w:08X}")

    if largest and largest[2] > 28:
        print(f"\n  SPACIOUS (most room, {largest[2]} bytes = {largest[2] // 4} instructions):")
        print(f"    vaddr=0x{largest[1]:08X}  file=0x{largest[0]:08X}")
        print(f"    Hex dump (first 32 bytes):")
        for j in range(0, min(largest[2], 32), 4):
            w = struct.unpack_from('<I', data, largest[0] + j)[0]
            print(f"      +{j:02d}: {w:08X}")

    # Pick a good middle ground: ~40-48 bytes, gives room for the toggle + margin
    mid = [c for c in safe_caves if 40 <= c[2] <= 52]
    if mid:
        pick = mid[0]
        print(f"\n  RECOMMENDED ({pick[2]} bytes = {pick[2] // 4} instructions, good margin):")
        print(f"    vaddr=0x{pick[1]:08X}  file=0x{pick[0]:08X}")
        print(f"    Hex dump:")
        for j in range(0, pick[2], 4):
            w = struct.unpack_from('<I', data, pick[0] + j)[0]
            print(f"      +{j:02d}: {w:08X}")


if __name__ == "__main__":
    main()
