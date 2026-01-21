#!/usr/bin/env python3
"""
Generate Test ROMs for VBlank/SVC Candidates

Strategy: NOP out each svcWaitSynchronization call
- SVC #0x25 (2 bytes: 25DF) → NOP (2 bytes: 00BF or C046 = mov r0, r0)
"""

import json
import shutil
import hashlib
from pathlib import Path

def nop_instruction():
    """Return NOP instruction bytes for Thumb mode"""
    # NOP in Thumb: 00 BF or C0 46 (mov r8, r8)
    return bytes([0x00, 0xBF])

def create_test_rom(base_rom, offset, svc_name, output_path, test_num):
    """Create a test ROM with SVC call NOPed out"""
    # Copy base ROM
    shutil.copy(base_rom, output_path)

    # Calculate offset in ROM
    # code.bin starts at offset 0x6E00 in the ROM
    code_offset = offset
    rom_offset = 0x6E00 + code_offset

    # Read the ROM
    with open(output_path, "rb") as f:
        rom_data = bytearray(f.read())

    # Verify we're at the right location (should be SVC instruction)
    # SVC #0x25 in file: 25 DF (little endian)
    # SVC #0x24 in file: 24 DF
    actual_bytes = rom_data[rom_offset:rom_offset + 2]

    expected_0x25 = bytes([0x25, 0xDF])
    expected_0x24 = bytes([0x24, 0xDF])

    if actual_bytes != expected_0x25 and actual_bytes != expected_0x24:
        print(f"WARNING: Candidate #{test_num} byte mismatch!")
        print(f"  Expected SVC instruction, got: {actual_bytes.hex()}")
        print(f"  Offset: 0x{rom_offset:08X} (code: 0x{code_offset:06X})")
        return False

    # Replace with NOP
    nop_bytes = nop_instruction()
    rom_data[rom_offset:rom_offset + 2] = nop_bytes

    # Update ExeFS SHA-256 hash
    exefs_offset = 0x6C00
    exefs_size = 0x220000
    exefs_data = rom_data[exefs_offset:exefs_offset + exefs_size]
    new_hash = hashlib.sha256(exefs_data).digest()
    hash_offset = 0x6CA0
    rom_data[hash_offset:hash_offset + 32] = new_hash

    # Write patched ROM
    with open(output_path, "wb") as f:
        f.write(rom_data)

    print(f"✓ Created test ROM #{test_num}")
    print(f"  NOPed: {svc_name} @ 0x{code_offset:06X}")
    print(f"  Original: {actual_bytes.hex()} → Patched: {nop_bytes.hex()}")

    return True

def main():
    # Load analysis results
    analysis_path = Path("tmp/svc_analysis.json")
    if not analysis_path.exists():
        print("ERROR: Run scan_svc_calls.py first")
        return

    with open(analysis_path) as f:
        analysis = json.load(f)

    candidates = analysis["vblank_candidates"]

    print("=" * 70)
    print("  VBlank/SVC Candidate ROM Generation")
    print("=" * 70)
    print()
    print(f"Generating {len(candidates)} test ROMs...")
    print()

    # Base ROM
    base_rom = Path("build/Mario_Luigi_BIS_60fps_FINAL.3ds")
    if not base_rom.exists():
        print(f"ERROR: Base ROM not found: {base_rom}")
        return

    # Output directory
    output_dir = Path("tmp/vblank_test_roms")
    output_dir.mkdir(exist_ok=True, parents=True)

    # Generate test ROMs
    manifest = {
        "base_rom": str(base_rom),
        "strategy": "NOP out svcWaitSynchronization calls",
        "test_roms": []
    }

    success_count = 0
    for i, candidate in enumerate(candidates, 1):
        output_path = output_dir / f"test_vblank_{i:02d}.3ds"

        if create_test_rom(
            base_rom,
            candidate["offset"],
            candidate["svc_name"],
            output_path,
            i
        ):
            manifest["test_roms"].append({
                "number": i,
                "file": str(output_path),
                "offset": f"0x{candidate['offset']:06X}",
                "svc_name": candidate["svc_name"],
                "priority": candidate["priority"],
                "in_loop": candidate["in_loop"],
                "has_count": candidate["has_count"]
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
    print()
    print("HIGH priority candidate is #4 (0x14DB7A)")

if __name__ == "__main__":
    main()
