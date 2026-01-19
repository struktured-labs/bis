#!/usr/bin/env python3
"""
Conservative frame limiter patch - only patch most likely locations
"""

import struct
from pathlib import Path

# Read original code.bin
with open("build/extracted/exefs_dir/code.bin.backup", "rb") as f:
    data = bytearray(f.read())

float_30 = struct.pack('<f', 30.0)
float_60 = struct.pack('<f', 60.0)

# All locations found
all_offsets = [
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

print("Testing conservative patch strategy...")
print("Only patching the FIRST occurrence (most likely frame limiter)")
print()

# Strategy: Only patch the FIRST occurrence - most likely to be frame limiter
conservative_offsets = [all_offsets[0]]  # Just 0x0007A413

for offset in conservative_offsets:
    if data[offset:offset+4] == float_30:
        data[offset:offset+4] = float_60
        print(f"  ✓ Patched @ 0x{offset:08X}: 30.0 → 60.0")

# Write conservative patch
with open("build/extracted/exefs_dir/code_conservative.bin", "wb") as f:
    f.write(data)

print()
print("✓ Created code_conservative.bin (1 patch only)")
