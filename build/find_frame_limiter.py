#!/usr/bin/env python3
"""
Find frame limiter constants in code.bin
Searches for float 30.0, 60.0 and timing constants
"""

import struct
import sys

def find_all_occurrences(data, pattern):
    """Find all occurrences of pattern in data"""
    offsets = []
    offset = 0
    while True:
        idx = data.find(pattern, offset)
        if idx == -1:
            break
        offsets.append(idx)
        offset = idx + 1
    return offsets

def main():
    code_bin_path = "build/extracted/exefs_dir/code.bin"

    print("=" * 70)
    print("  Frame Limiter Analysis - code.bin")
    print("=" * 70)
    print()

    # Read code.bin
    try:
        with open(code_bin_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"ERROR: {code_bin_path} not found")
        return 1

    print(f"File size: {len(data)} bytes (0x{len(data):X})")
    print()

    # Define search patterns
    float_30 = struct.pack('<f', 30.0)  # 0x0000F041 little-endian
    float_60 = struct.pack('<f', 60.0)  # 0x00007042 little-endian

    # Timing constants (microseconds for delays)
    # 30 FPS = 33333 us = 0x8235 (16-bit) or 0x00008235 (32-bit)
    # 60 FPS = 16666 us = 0x411A (16-bit) or 0x0000411A (32-bit)
    delay_30fps_us = struct.pack('<I', 33333)  # 32-bit
    delay_60fps_us = struct.pack('<I', 16666)  # 32-bit

    print("Search patterns:")
    print(f"  Float 30.0:  {float_30.hex()}")
    print(f"  Float 60.0:  {float_60.hex()}")
    print(f"  Delay 30fps: {delay_30fps_us.hex()} (33333 us)")
    print(f"  Delay 60fps: {delay_60fps_us.hex()} (16666 us)")
    print()

    # Search for each pattern
    print("=" * 70)
    print("  FLOAT 30.0 Locations")
    print("=" * 70)

    offsets_30 = find_all_occurrences(data, float_30)
    if offsets_30:
        for offset in offsets_30[:20]:  # Show first 20
            # Show context (8 bytes before and after)
            start = max(0, offset - 8)
            end = min(len(data), offset + 12)
            context = data[start:end]
            print(f"  0x{offset:08X}: {context.hex(' ')}")
        if len(offsets_30) > 20:
            print(f"  ... and {len(offsets_30) - 20} more")
        print(f"\nTotal: {len(offsets_30)} occurrences")
    else:
        print("  None found")
    print()

    print("=" * 70)
    print("  FLOAT 60.0 Locations")
    print("=" * 70)

    offsets_60 = find_all_occurrences(data, float_60)
    if offsets_60:
        for offset in offsets_60:
            start = max(0, offset - 8)
            end = min(len(data), offset + 12)
            context = data[start:end]
            print(f"  0x{offset:08X}: {context.hex(' ')}")
        print(f"\nTotal: {len(offsets_60)} occurrences")
    else:
        print("  None found")
    print()

    print("=" * 70)
    print("  Delay Constants (33333 us = 30fps)")
    print("=" * 70)

    offsets_delay30 = find_all_occurrences(data, delay_30fps_us)
    if offsets_delay30:
        for offset in offsets_delay30:
            start = max(0, offset - 8)
            end = min(len(data), offset + 12)
            context = data[start:end]
            print(f"  0x{offset:08X}: {context.hex(' ')}")
        print(f"\nTotal: {len(offsets_delay30)} occurrences")
    else:
        print("  None found")
    print()

    print("=" * 70)
    print("  Delay Constants (16666 us = 60fps)")
    print("=" * 70)

    offsets_delay60 = find_all_occurrences(data, delay_60fps_us)
    if offsets_delay60:
        for offset in offsets_delay60:
            start = max(0, offset - 8)
            end = min(len(data), offset + 12)
            context = data[start:end]
            print(f"  0x{offset:08X}: {context.hex(' ')}")
        print(f"\nTotal: {len(offsets_delay60)} occurrences")
    else:
        print("  None found")
    print()

    # Summary
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Float 30.0:     {len(offsets_30)} occurrences")
    print(f"  Float 60.0:     {len(offsets_60)} occurrences")
    print(f"  Delay 33333us:  {len(offsets_delay30)} occurrences")
    print(f"  Delay 16666us:  {len(offsets_delay60)} occurrences")
    print()

    if offsets_30 or offsets_delay30:
        print("✓ Found potential frame limiter locations")
        print("  Next step: Analyze these addresses in Ghidra/IDA")
        print("  Create patches to change 30.0 → 60.0 or 33333 → 16666")
        return 0
    else:
        print("⚠ No obvious frame limiter constants found")
        print("  Frame limiter may use different approach:")
        print("    - Calculated dynamically")
        print("    - Uses VSync")
        print("    - Reads from configuration")
        return 1

if __name__ == "__main__":
    sys.exit(main())
