#!/usr/bin/env python3
"""
Generate Test ROMs for 0x74 Candidates

Strategy: Patch comparisons and moves involving 0x74
- CMP rX, #0x74 → CMP rX, #0x00 (always false)
- MOVS rX, #0x74 → MOVS rX, #0x00 (set to 0 instead)
- ADDS rX, #0x74 → ADDS rX, #0x00 (no-op add)

If 0x74 is used for FPS control, changing it should affect frame rate
"""

import json
import shutil
import struct
from pathlib import Path

def create_test_rom(base_rom, candidate, output_path, test_num):
    """
    Create a test ROM with a specific candidate patched
    """
    # Copy base ROM
    shutil.copy(base_rom, output_path)

    # Calculate offset in ROM
    # code.bin starts at offset 0x6E00 in the ROM
    code_offset = candidate["offset"]
    rom_offset = 0x6E00 + code_offset

    # Read the ROM
    with open(output_path, "rb") as f:
        rom_data = bytearray(f.read())

    # Verify we're at the right location
    expected_bytes = bytes.fromhex(candidate["bytes"])
    actual_bytes = rom_data[rom_offset:rom_offset + len(expected_bytes)]

    if actual_bytes != expected_bytes:
        print(f"WARNING: Candidate #{test_num} byte mismatch!")
        print(f"  Expected: {expected_bytes.hex()}")
        print(f"  Actual: {actual_bytes.hex()}")
        print(f"  Offset: 0x{rom_offset:08X}")
        return False

    # Determine patch strategy based on mnemonic
    mnem = candidate["mnemonic"].lower()
    original_bytes = bytes.fromhex(candidate["bytes"])

    if "cmp" in mnem:
        # CMP rX, #0x74 → CMP rX, #0x00
        # Thumb encoding: 2Dxx for cmp r5, #imm8
        # Change immediate from 0x74 to 0x00
        patched_bytes = bytearray(original_bytes)
        if len(patched_bytes) == 2:
            # Thumb-16: immediate is in lower byte
            patched_bytes[0] = 0x00  # Change immediate to 0
        else:
            print(f"  Candidate #{test_num}: Unexpected CMP encoding length {len(patched_bytes)}")
            return False

    elif "movs" in mnem:
        # MOVS rX, #0x74 → MOVS rX, #0x00
        patched_bytes = bytearray(original_bytes)
        if len(patched_bytes) == 2:
            patched_bytes[0] = 0x00  # Change immediate to 0
        else:
            print(f"  Candidate #{test_num}: Unexpected MOVS encoding length {len(patched_bytes)}")
            return False

    elif "adds" in mnem:
        # ADDS rX, #0x74 → ADDS rX, #0x00
        patched_bytes = bytearray(original_bytes)
        if len(patched_bytes) == 2:
            patched_bytes[0] = 0x00  # Change immediate to 0
        else:
            print(f"  Candidate #{test_num}: Unexpected ADDS encoding length {len(patched_bytes)}")
            return False

    else:
        print(f"  Candidate #{test_num}: Unhandled mnemonic {mnem}")
        return False

    # Apply patch
    rom_data[rom_offset:rom_offset + len(patched_bytes)] = patched_bytes

    # Update ExeFS SHA-256 hash at offset 0x6CA0
    # Calculate hash of ExeFS (from 0x6E00 to 0x6E00 + exefs_size)
    exefs_offset = 0x6C00
    exefs_size = 0x220000  # Approximately, adjust if needed

    import hashlib
    exefs_data = rom_data[exefs_offset:exefs_offset + exefs_size]
    new_hash = hashlib.sha256(exefs_data).digest()

    # Write new hash
    hash_offset = 0x6CA0
    rom_data[hash_offset:hash_offset + 32] = new_hash

    # Write patched ROM
    with open(output_path, "wb") as f:
        f.write(rom_data)

    print(f"✓ Created test ROM #{test_num}")
    print(f"  Patched: {candidate['mnemonic']} {candidate['op_str']} @ 0x{code_offset:06X}")
    print(f"  Original: {original_bytes.hex()} → Patched: {patched_bytes.hex()}")

    return True

def main():
    # Load analysis results
    analysis_path = Path("tmp/0x74_analysis.json")
    if not analysis_path.exists():
        print("ERROR: Run analyze_0x74_usage.py first")
        return

    with open(analysis_path) as f:
        analysis = json.load(f)

    # Get top candidates (HIGH priority first)
    candidates = analysis["high_priority"][:15]
    if len(candidates) < 15:
        candidates.extend(analysis["medium_priority"][:15 - len(candidates)])

    print("=" * 70)
    print("  0x74 Candidate ROM Generation")
    print("=" * 70)
    print()
    print(f"Generating {len(candidates)} test ROMs...")
    print()

    # Base ROM (with CRO patches)
    base_rom = Path("build/Mario_Luigi_BIS_60fps_FINAL.3ds")
    if not base_rom.exists():
        print(f"ERROR: Base ROM not found: {base_rom}")
        return

    # Output directory
    output_dir = Path("tmp/0x74_test_roms")
    output_dir.mkdir(exist_ok=True, parents=True)

    # Generate test ROMs
    manifest = {
        "base_rom": str(base_rom),
        "test_roms": []
    }

    success_count = 0
    for i, candidate in enumerate(candidates, 1):
        output_path = output_dir / f"test_0x74_{i:02d}.3ds"

        if create_test_rom(base_rom, candidate, output_path, i):
            manifest["test_roms"].append({
                "number": i,
                "file": str(output_path),
                "offset": f"0x{candidate['offset']:06X}",
                "instruction": f"{candidate['mnemonic']} {candidate['op_str']}",
                "priority": candidate["priority"],
                "reason": candidate["reason"]
            })
            success_count += 1
        print()

    # Save manifest
    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print("=" * 70)
    print(f"✓ Successfully created {success_count}/{len(candidates)} test ROMs")
    print(f"  Output: {output_dir}")
    print(f"  Manifest: {manifest_path}")
    print("=" * 70)
    print()
    print("Next: Test each ROM for 40 seconds and check FPS")

if __name__ == "__main__":
    main()
