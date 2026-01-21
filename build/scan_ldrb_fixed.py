#!/usr/bin/env python3
"""
Fixed LDRB Scanner - Find FPS Control Read Instructions
"""

from capstone import *
from capstone.arm import *
import struct
from pathlib import Path
import json

# Load code.bin
code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, "rb") as f:
    code_data = f.read()

print("=" * 70)
print("  LDRB Scanner (Fixed) - FPS Control Finder")
print("=" * 70)
print()
print(f"Code size: {len(code_data):,} bytes")
print()

# Find constant pool entries
FPS_BASE = 0x30000000
constant_pool_locations = []

for offset in range(0, len(code_data) - 4, 4):
    value = struct.unpack('<I', code_data[offset:offset+4])[0]
    if value == FPS_BASE:
        constant_pool_locations.append(offset)

print(f"Constant pool entries for 0x{FPS_BASE:08X}: {len(constant_pool_locations)}")
for loc in constant_pool_locations:
    print(f"  - 0x{loc:08X}")
print()

# Try ARM mode first (code.bin starts with ARM code)
print("=" * 70)
print("Scanning ARM Mode...")
print("=" * 70)
print()

md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md.detail = True

ldrb_candidates = []
ldr_pool_candidates = []
ldrb_total = 0
ldr_total = 0
instructions_decoded = 0

# Scan in chunks to avoid memory issues
CHUNK_SIZE = 100000
offset = 0

while offset < len(code_data):
    chunk_end = min(offset + CHUNK_SIZE, len(code_data))
    chunk = code_data[offset:chunk_end]

    try:
        for inst in md.disasm(chunk, offset):
            instructions_decoded += 1

            if instructions_decoded % 50000 == 0:
                print(f"  Decoded {instructions_decoded:,} instructions...")

            # LDRB instructions
            if 'ldrb' in inst.mnemonic:
                ldrb_total += 1

                # Check operands for offset
                if len(inst.operands) >= 2:
                    op2 = inst.operands[1]
                    if op2.type == ARM_OP_MEM:
                        disp = op2.mem.disp
                        # Look for offsets near 0x75
                        if 0x70 <= disp <= 0x78:
                            ldrb_candidates.append({
                                'address': inst.address,
                                'instruction': f"{inst.mnemonic} {inst.op_str}",
                                'offset': disp,
                                'base_reg': inst.reg_name(op2.mem.base) if op2.mem.base else 'none',
                                'bytes': inst.bytes.hex()
                            })

            # LDR instructions
            elif inst.mnemonic == 'ldr':
                ldr_total += 1

                # Check if loading from constant pool
                if len(inst.operands) >= 2:
                    op2 = inst.operands[1]
                    if op2.type == ARM_OP_MEM:
                        # PC-relative load
                        if op2.mem.base != 0:  # Has base register
                            # Calculate effective address for PC-relative
                            if inst.reg_name(op2.mem.base) == 'pc':
                                # ARM PC is instruction address + 8
                                eff_addr = inst.address + 8 + op2.mem.disp
                                # Align to 4 bytes
                                eff_addr = (eff_addr // 4) * 4

                                # Check if this points to our constant pool
                                if eff_addr in constant_pool_locations:
                                    ldr_pool_candidates.append({
                                        'address': inst.address,
                                        'instruction': f"{inst.mnemonic} {inst.op_str}",
                                        'pool_address': eff_addr,
                                        'dest_reg': inst.reg_name(inst.operands[0].reg) if inst.operands[0].type == ARM_OP_REG else 'unknown',
                                        'bytes': inst.bytes.hex()
                                    })

    except CsError as e:
        print(f"  Warning: Disassembly error at offset 0x{offset:08X}: {e}")

    offset = chunk_end

print()
print(f"Total instructions decoded: {instructions_decoded:,}")
print(f"Total LDRB: {ldrb_total}")
print(f"Total LDR: {ldr_total}")
print()

print("=" * 70)
print(f"  CANDIDATES FOUND")
print("=" * 70)
print()
print(f"LDRB with offset 0x70-0x78: {len(ldrb_candidates)}")
print(f"LDR loading 0x30000000:      {len(ldr_pool_candidates)}")
print()

if ldrb_candidates:
    print("=" * 70)
    print("  TOP LDRB CANDIDATES (offset 0x75 priority)")
    print("=" * 70)
    print()

    # Sort by offset (0x75 first)
    ldrb_candidates.sort(key=lambda x: abs(x['offset'] - 0x75))

    for i, cand in enumerate(ldrb_candidates[:30]):
        print(f"#{i+1}:")
        print(f"  Address:  0x{cand['address']:08X}")
        print(f"  Inst:     {cand['instruction']}")
        print(f"  Offset:   0x{cand['offset']:02X} {'<-- EXACT MATCH' if cand['offset'] == 0x75 else ''}")
        print(f"  Base:     {cand['base_reg']}")
        print()

    if len(ldrb_candidates) > 30:
        print(f"... and {len(ldrb_candidates) - 30} more")
        print()

if ldr_pool_candidates:
    print("=" * 70)
    print("  LDR FROM 0x30000000 CONSTANT POOL")
    print("=" * 70)
    print()

    for i, cand in enumerate(ldr_pool_candidates):
        print(f"#{i+1}:")
        print(f"  Address:  0x{cand['address']:08X}")
        print(f"  Inst:     {cand['instruction']}")
        print(f"  Pool:     0x{cand['pool_address']:08X}")
        print(f"  Into Reg: {cand['dest_reg']}")
        print()

        # Look for nearby LDRB using this register
        dest_reg = cand['dest_reg']
        for ldrb in ldrb_candidates[:10]:
            if ldrb['base_reg'] == dest_reg:
                # Check if close enough
                dist = abs(ldrb['address'] - cand['address'])
                if dist < 100:  # Within 100 bytes
                    print(f"  *** MATCH: LDRB at 0x{ldrb['address']:08X} uses {dest_reg} ***")
                    print(f"      {ldrb['instruction']}")
                    print(f"      Distance: {dist} bytes")
                    print()

# Save results
output = {
    'ldrb_candidates': ldrb_candidates,
    'ldr_pool_candidates': ldr_pool_candidates,
    'stats': {
        'total_instructions': instructions_decoded,
        'total_ldrb': ldrb_total,
        'total_ldr': ldr_total
    }
}

output_file = Path("tmp/ldrb_scan_fixed.json")
with open(output_file, 'w') as f:
    json.dump(output, f, indent=2)

print("=" * 70)
print(f"Results saved to: {output_file}")
print("=" * 70)
