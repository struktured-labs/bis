#!/usr/bin/env python3
"""
Patch frame limiter in code.bin
Changes float 30.0 -> 60.0 at identified locations
"""

import struct
import sys
import shutil
from pathlib import Path

def patch_float_values(input_path, output_path, offsets_to_patch):
    """Patch float 30.0 to 60.0 at specified offsets"""

    # Read input file
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    float_30 = struct.pack('<f', 30.0)
    float_60 = struct.pack('<f', 60.0)

    patched_count = 0

    for offset in offsets_to_patch:
        # Verify we're actually at a 30.0 value
        if data[offset:offset+4] == float_30:
            data[offset:offset+4] = float_60
            patched_count += 1
            print(f"  ✓ Patched @ 0x{offset:08X}: 30.0 → 60.0")
        else:
            actual = data[offset:offset+4]
            print(f"  ⚠ WARNING @ 0x{offset:08X}: Expected {float_30.hex()} but found {actual.hex()}")

    # Write output file
    with open(output_path, "wb") as f:
        f.write(data)

    return patched_count

def main():
    print("=" * 70)
    print("  Frame Limiter Patcher for code.bin")
    print("=" * 70)
    print()

    input_file = Path("build/extracted/exefs_dir/code.bin")
    output_file = Path("build/extracted/exefs_dir/code_patched.bin")

    if not input_file.exists():
        print(f"ERROR: {input_file} not found")
        return 1

    # Known float 30.0 locations from analysis
    # NOTE: These were found by find_frame_limiter.py
    all_float_30_offsets = [
        0x0007A413,
        0x000C6EE4,
        0x000F2373,
        0x0012C3AA,
        0x00151982,
        0x00154D88,
        0x00161BC6,
        0x0016DD13,
        0x00178A44,
    ]

    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print()
    print(f"Will patch {len(all_float_30_offsets)} locations:")
    print()

    # Option 1: Patch ALL locations (aggressive approach)
    print("=" * 70)
    print("  PATCHING ALL FLOAT 30.0 → 60.0")
    print("=" * 70)
    print()
    print("This patches ALL occurrences of float 30.0 in code.bin.")
    print("May affect unrelated game logic, but ensures frame limiter is caught.")
    print()

    # Create backup
    backup_file = Path("build/extracted/exefs_dir/code.bin.backup")
    if not backup_file.exists():
        shutil.copy(input_file, backup_file)
        print(f"Created backup: {backup_file}")
        print()

    # Apply patches
    patched_count = patch_float_values(input_file, output_file, all_float_30_offsets)

    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Successfully patched: {patched_count} / {len(all_float_30_offsets)} locations")
    print()

    if patched_count == len(all_float_30_offsets):
        print("✅ All patches applied successfully")
        print()
        print("Next steps:")
        print("  1. Rebuild exefs.bin with patched code.bin")
        print("  2. Rebuild ROM with patched exefs")
        print("  3. Test with automated verification script")
        return 0
    else:
        print("⚠️  Some patches failed - check warnings above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
