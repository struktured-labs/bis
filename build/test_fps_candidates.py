#!/usr/bin/env python3
"""
Automated FPS Candidate Testing

Tests all 15 candidate locations by:
1. Creating test patches (NOP or value change)
2. Building test ROMs
3. Recording which patches affect behavior
"""

import struct
import shutil
from pathlib import Path
import subprocess
import json

# The 15 high-priority candidates
CANDIDATES = [
    {'id': 1, 'address': 0x00002482, 'desc': 'adds r3, #0x75', 'priority': 'MEDIUM'},
    {'id': 2, 'address': 0x00012588, 'desc': 'movs r1, #0x75', 'priority': 'HIGH'},
    {'id': 3, 'address': 0x00013518, 'desc': 'adds r1, #0x75', 'priority': 'LOW'},
    {'id': 4, 'address': 0x0001A14C, 'desc': 'adds r0, #0x75', 'priority': 'LOW'},
    {'id': 5, 'address': 0x00022BDA, 'desc': 'movs r0, #0x75', 'priority': 'LOW'},
    {'id': 6, 'address': 0x00026CCE, 'desc': 'movs r1, #0x75', 'priority': 'MEDIUM'},
    {'id': 7, 'address': 0x000280CA, 'desc': 'movs r0, #0x75', 'priority': 'HIGH'},
    {'id': 8, 'address': 0x000404AA, 'desc': 'movs r0, #0x75', 'priority': 'HIGH'},
    {'id': 9, 'address': 0x00042A38, 'desc': 'movs r0, #0x75', 'priority': 'MEDIUM'},
    {'id': 10, 'address': 0x00047A8C, 'desc': 'movs r4, #0x75', 'priority': 'MEDIUM'},
    {'id': 11, 'address': 0x0004A5D4, 'desc': 'adds r3, #0x75', 'priority': 'HIGH'},
    {'id': 12, 'address': 0x000574EE, 'desc': 'movs r2, #0x75', 'priority': 'MEDIUM'},
    {'id': 13, 'address': 0x000588F2, 'desc': 'movs r2, #0x75', 'priority': 'HIGH'},
    {'id': 14, 'address': 0x0005A8AC, 'desc': 'adds r1, #0x75', 'priority': 'HIGH'},
    {'id': 15, 'address': 0x0005C298, 'desc': 'movs r0, #0x75', 'priority': 'HIGH'},
]

# Sort by priority: HIGH first
priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
CANDIDATES.sort(key=lambda x: (priority_order[x['priority']], x['id']))

print("=" * 70)
print("  FPS Candidate Testing - Automated")
print("=" * 70)
print()
print(f"Total candidates: {len(CANDIDATES)}")
print()

# Read original code.bin
code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, 'rb') as f:
    original_code = bytearray(f.read())

# Base ROM for patching
base_rom = Path("build/Mario_Luigi_BIS_60fps_FINAL.3ds")
test_roms_dir = Path("tmp/fps_candidate_roms")
test_roms_dir.mkdir(parents=True, exist_ok=True)

# Results
results = []

print("Creating test patches...")
print()

for cand in CANDIDATES:
    cand_id = cand['id']
    addr = cand['address']
    priority = cand['priority']

    print(f"Candidate #{cand_id}: {cand['desc']} @ 0x{addr:08X} ({priority})")

    # Create patched code.bin
    patched_code = bytearray(original_code)

    # Read original instruction (2 bytes for Thumb)
    orig_bytes = struct.unpack('<H', patched_code[addr:addr+2])[0]

    # Create two types of patches:
    # Patch A: Change 0x75 to 0x00
    # Patch B: NOP the instruction (movs r0, #0 or similar)

    # For MOVs rX, #0x75 (Thumb encoding: 00100 rrr iiiiiiii)
    # Change immediate from 0x75 to 0x00
    patch_a = bytearray(patched_code)
    patch_b = bytearray(patched_code)

    # Thumb MOVS encoding: 0010 0ddd iiii iiii
    # Where ddd = dest register (0-7), iiii iiii = immediate
    if (orig_bytes & 0xF800) == 0x2000:  # MOVS rX, #imm
        # Change immediate to 0
        new_bytes_a = (orig_bytes & 0xFF00)  # Keep register, zero immediate
        struct.pack_into('<H', patch_a, addr, new_bytes_a)

        # NOP (movs r0, r0 = 0x4600 in Thumb)
        struct.pack_into('<H', patch_b, addr, 0x46C0)  # NOP

    # Thumb ADDS encoding: various formats
    # For now, just try NOPing it
    else:
        struct.pack_into('<H', patch_a, addr, 0x46C0)  # NOP
        struct.pack_into('<H', patch_b, addr, 0x46C0)  # NOP

    # Save patched code.bin variants
    patch_a_path = test_roms_dir / f"code_cand{cand_id:02d}_a.bin"
    patch_b_path = test_roms_dir / f"code_cand{cand_id:02d}_b.bin"

    with open(patch_a_path, 'wb') as f:
        f.write(patch_a)
    with open(patch_b_path, 'wb') as f:
        f.write(patch_b)

    # Calculate offset in ROM (code.bin offset 0x6E00 + candidate address)
    rom_offset_a = 0x6E00 + addr
    rom_offset_b = 0x6E00 + addr

    # Create test ROM A (value change)
    rom_a = test_roms_dir / f"test_cand{cand_id:02d}_a.3ds"
    shutil.copy(base_rom, rom_a)

    with open(rom_a, 'r+b') as f:
        f.seek(rom_offset_a)
        f.write(patch_a[addr:addr+2])

    # Update exefs hash for ROM A
    subprocess.run([
        'python3', '-c',
        f"""
import struct
import hashlib
from pathlib import Path

rom = Path('{rom_a}')
with open(rom, 'r+b') as f:
    # Read exefs (at 0x6C00, size 0x200000)
    f.seek(0x6C00)
    exefs_data = f.read(0x200000)

    # Calculate hash
    h = hashlib.sha256(exefs_data).digest()

    # Write hash at 0x6CA0
    f.seek(0x6CA0)
    f.write(h)
"""
    ], check=True, capture_output=True)

    results.append({
        'id': cand_id,
        'address': f"0x{addr:08X}",
        'instruction': cand['desc'],
        'priority': priority,
        'rom_a': str(rom_a),
        'patch_type_a': 'value_to_zero',
        'rom_b': str(rom_a).replace('_a.3ds', '_b.3ds'),
        'patch_type_b': 'nop'
    })

    print(f"  Created: {rom_a.name}")

print()
print(f"Created {len(results)} test ROM variants in {test_roms_dir}")
print()

# Save manifest
manifest = {
    'candidates': results,
    'base_rom': str(base_rom),
    'code_offset_in_rom': '0x6E00',
    'instructions': 'Test each ROM to see which affects FPS behavior'
}

manifest_path = test_roms_dir / "manifest.json"
with open(manifest_path, 'w') as f:
    json.dump(manifest, f, indent=2)

print(f"Manifest saved to: {manifest_path}")
print()
print("=" * 70)
print("  NEXT: Manual Testing Required")
print("=" * 70)
print()
print("Test each ROM by:")
print("  1. Launch with working emulator")
print("  2. Observe behavior (crash, FPS change, normal)")
print("  3. Note results for each candidate")
print()
print("Or use automated FPS measurement if emulator stable")
