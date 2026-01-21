#!/usr/bin/env python3
"""
Generate multiple test ROMs with different patch combinations
for automated binary search of working frame limiter patches
"""

import struct
import hashlib
import shutil
from pathlib import Path

def create_patched_rom(patch_indices, output_name):
    """
    Create a ROM with only specific patch indices applied

    Args:
        patch_indices: List of indices (0-8) to patch
        output_name: Output ROM filename
    """

    # All float 30.0 locations found
    all_offsets = [
        0x0007A413,  # 0
        0x000C6EE4,  # 1
        0x000F2373,  # 2
        0x0012C3AA,  # 3
        0x00151982,  # 4
        0x00154D88,  # 5
        0x00161BC6,  # 6
        0x0016DD13,  # 7
        0x00178A44,  # 8
    ]

    # Read original code.bin
    with open("build/extracted/exefs_dir/code.bin.backup", "rb") as f:
        code_data = bytearray(f.read())

    float_30 = struct.pack('<f', 30.0)
    float_60 = struct.pack('<f', 60.0)

    # Apply selected patches
    patched = []
    for idx in patch_indices:
        offset = all_offsets[idx]
        if code_data[offset:offset+4] == float_30:
            code_data[offset:offset+4] = float_60
            patched.append(f"0x{offset:08X}")

    # Calculate hash
    code_hash = hashlib.sha256(code_data).digest()

    # Copy FINAL ROM as base
    shutil.copy("build/Mario_Luigi_BIS_60fps_FINAL.3ds", f"build/{output_name}")

    # Read ROM
    with open(f"build/{output_name}", "rb") as f:
        rom_data = bytearray(f.read())

    # Patch code.bin directly in ROM (offset 0x6E00 = 28160)
    code_offset = 28160
    rom_data[code_offset:code_offset + len(code_data)] = code_data

    # Update exefs hash
    hash_offset = 0x6CA0
    rom_data[hash_offset:hash_offset + 0x20] = code_hash

    # Write patched ROM
    with open(f"build/{output_name}", "wb") as f:
        f.write(rom_data)

    return patched

def main():
    print("=" * 70)
    print("  Automated ROM Test Generation - Conservative Patch Strategy")
    print("=" * 70)
    print()

    # Create output directory for test results
    Path("tmp/test_roms").mkdir(parents=True, exist_ok=True)

    # Test strategy: Binary search approach
    # Start with individual patches, then combinations

    test_configs = [
        # Single patches - identify which individual patches are safe
        ([0], "test_patch_0.3ds"),
        ([1], "test_patch_1.3ds"),
        ([2], "test_patch_2.3ds"),
        ([3], "test_patch_3.3ds"),
        ([4], "test_patch_4.3ds"),

        # First two combinations - often frame limiter is in early code
        ([0, 1], "test_patch_0_1.3ds"),
        ([0, 2], "test_patch_0_2.3ds"),

        # Common patterns - might be related code sections
        ([0, 1, 2], "test_patch_0_1_2.3ds"),
    ]

    print(f"Generating {len(test_configs)} test ROMs...")
    print()

    manifest = []

    for patch_indices, filename in test_configs:
        print(f"Creating {filename}...")
        patched = create_patched_rom(patch_indices, filename)

        manifest.append({
            "filename": filename,
            "indices": patch_indices,
            "offsets": patched,
            "count": len(patched)
        })

        print(f"  ✓ Patched {len(patched)} location(s): {', '.join(patched)}")
        print()

    # Write manifest for automated testing
    with open("tmp/test_roms/manifest.txt", "w") as f:
        f.write("ROM Test Manifest - Automated FPS Verification\n")
        f.write("=" * 70 + "\n\n")

        for item in manifest:
            f.write(f"File: {item['filename']}\n")
            f.write(f"Patches: {item['count']}\n")
            f.write(f"Locations: {', '.join(item['offsets'])}\n")
            f.write("\n")

    print("=" * 70)
    print("  Test ROM Generation Complete")
    print("=" * 70)
    print()
    print(f"Generated {len(test_configs)} test ROMs in build/")
    print("Manifest saved to: tmp/test_roms/manifest.txt")
    print()
    print("Next: Run automated verification agent")
    print()

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
