#!/usr/bin/env python3
"""
Direct patch of 0x20DA3AD in code.bin
The cheat writes 0x00 to this address, so let's just set it to 0x00 statically
"""

import shutil
import hashlib
from pathlib import Path

base_rom = Path("build/Mario_Luigi_BIS_60fps_FINAL.3ds")
output_rom = Path("tmp/test_direct_0x20DA3AD.3ds")

# Copy ROM
shutil.copy(base_rom, output_rom)

# Read ROM
with open(output_rom, "rb") as f:
    rom_data = bytearray(f.read())

# Offset in ROM: 0x6E00 (code.bin start) + 0x20DA3AD (offset in code)
# Wait, 0x20DA3AD is way too large for code.bin offset
# code.bin is only ~1.9MB = 0x1D0000 bytes

# Let me try a different interpretation: maybe it's 0x0DA3AD offset in code
code_offset = 0x0DA3AD
rom_offset = 0x6E00 + code_offset

print(f"Patching offset 0x{code_offset:08X} in code.bin")
print(f"ROM offset: 0x{rom_offset:08X}")
print(f"ROM size: {len(rom_data)} bytes")

if rom_offset < len(rom_data):
    print(f"Current value at offset: 0x{rom_data[rom_offset]:02X}")
    rom_data[rom_offset] = 0x00
    print(f"Patched to: 0x00")

    # Update hash
    exefs_offset = 0x6C00
    exefs_size = 0x220000
    exefs_data = rom_data[exefs_offset:exefs_offset + exefs_size]
    new_hash = hashlib.sha256(exefs_data).digest()
    hash_offset = 0x6CA0
    rom_data[hash_offset:hash_offset + 32] = new_hash

    # Write
    with open(output_rom, "wb") as f:
        f.write(rom_data)

    print(f"\n✓ Created: {output_rom}")
else:
    print(f"ERROR: Offset 0x{rom_offset:08X} exceeds ROM size")
