#!/usr/bin/env python3
"""
Comprehensive LDRB Scanner - Find FPS Control Read Instructions

Scans entire code.bin for:
1. LDRB instructions (byte loads)
2. Patterns that could access offset 0x75 from base address
3. Instructions near constant pool entries of 0x30000000

This is the automated approach to find frame limiter without GDB.
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
print("  LDRB Instruction Scanner - FPS Control Finder")
print("=" * 70)
print()
print(f"Code size: {len(code_data):,} bytes ({len(code_data)/1024:.1f} KB)")
print()

# Find all occurrences of 0x30000000 in code.bin (constant pool entries)
FPS_BASE = 0x30000000
constant_pool_locations = []

for offset in range(0, len(code_data) - 4, 4):
    value = struct.unpack('<I', code_data[offset:offset+4])[0]
    if value == FPS_BASE:
        constant_pool_locations.append(offset)

print(f"Found {len(constant_pool_locations)} constant pool entries for 0x{FPS_BASE:08X}:")
for loc in constant_pool_locations:
    print(f"  - 0x{loc:08X}")
print()

# Scan in both ARM and Thumb modes
candidates = []

for mode_val, mode_name in [(CS_MODE_THUMB, "Thumb"), (CS_MODE_ARM, "ARM")]:
    print("=" * 70)
    print(f"Scanning in {mode_name} mode...")
    print("=" * 70)
    print()

    md = Cs(CS_ARCH_ARM, mode_val)
    md.detail = True

    ldrb_count = 0
    ldr_to_pool_count = 0

    # Scan entire code.bin
    try:
        for inst in md.disasm(code_data, 0):
            # Look for LDRB instructions (byte load)
            if inst.mnemonic == 'ldrb':
                ldrb_count += 1

                # Check if this LDRB uses an offset that could be 0x75
                for op in inst.operands:
                    if op.type == ARM_OP_MEM:
                        # Check if displacement is 0x75 or related
                        if op.mem.disp in [0x75, 0x74, 0x76, 0x70, 0x78]:
                            candidates.append({
                                'mode': mode_name,
                                'type': 'LDRB_WITH_OFFSET',
                                'address': inst.address,
                                'instruction': f"{inst.mnemonic} {inst.op_str}",
                                'offset': op.mem.disp,
                                'base_reg': inst.reg_name(op.mem.base) if op.mem.base else None,
                                'bytes': inst.bytes.hex()
                            })

            # Look for LDR instructions that load from constant pool
            elif inst.mnemonic == 'ldr':
                for op in inst.operands:
                    if op.type == ARM_OP_IMM:
                        # Check if immediate points to a constant pool location
                        if op.imm in constant_pool_locations:
                            ldr_to_pool_count += 1
                            candidates.append({
                                'mode': mode_name,
                                'type': 'LDR_FROM_POOL',
                                'address': inst.address,
                                'instruction': f"{inst.mnemonic} {inst.op_str}",
                                'pool_address': op.imm,
                                'dest_reg': inst.reg_name(inst.operands[0].reg) if inst.operands[0].type == ARM_OP_REG else None,
                                'bytes': inst.bytes.hex()
                            })

    except CsError as e:
        print(f"Warning: Disassembly error in {mode_name} mode: {e}")

    print(f"  Total LDRB instructions: {ldrb_count}")
    print(f"  Total LDR from constant pool: {ldr_to_pool_count}")
    print()

print("=" * 70)
print(f"  CANDIDATES FOUND: {len(candidates)}")
print("=" * 70)
print()

# Separate by type
ldrb_candidates = [c for c in candidates if c['type'] == 'LDRB_WITH_OFFSET']
ldr_pool_candidates = [c for c in candidates if c['type'] == 'LDR_FROM_POOL']

print(f"LDRB with FPS-related offset (0x70-0x78): {len(ldrb_candidates)}")
print(f"LDR loading 0x30000000 from pool: {len(ldr_pool_candidates)}")
print()

if ldrb_candidates:
    print("=" * 70)
    print("  LDRB CANDIDATES (Most Likely)")
    print("=" * 70)
    print()

    for i, cand in enumerate(ldrb_candidates[:50]):  # Show first 50
        print(f"Candidate #{i+1}:")
        print(f"  Address:     0x{cand['address']:08X}")
        print(f"  Mode:        {cand['mode']}")
        print(f"  Instruction: {cand['instruction']}")
        print(f"  Offset:      0x{cand['offset']:02X}")
        print(f"  Base Reg:    {cand['base_reg']}")
        print(f"  Bytes:       {cand['bytes']}")
        print()

    if len(ldrb_candidates) > 50:
        print(f"... and {len(ldrb_candidates) - 50} more")
        print()

if ldr_pool_candidates:
    print("=" * 70)
    print("  LDR FROM CONSTANT POOL CANDIDATES")
    print("=" * 70)
    print()

    for i, cand in enumerate(ldr_pool_candidates[:20]):  # Show first 20
        print(f"Candidate #{i+1}:")
        print(f"  Address:     0x{cand['address']:08X}")
        print(f"  Mode:        {cand['mode']}")
        print(f"  Instruction: {cand['instruction']}")
        print(f"  Pool Addr:   0x{cand['pool_address']:08X}")
        print(f"  Dest Reg:    {cand['dest_reg']}")
        print(f"  Bytes:       {cand['bytes']}")
        print()

    if len(ldr_pool_candidates) > 20:
        print(f"... and {len(ldr_pool_candidates) - 20} more")
        print()

# Save full results to JSON
output_file = Path("tmp/ldrb_candidates.json")
output_file.parent.mkdir(exist_ok=True)
with open(output_file, 'w') as f:
    json.dump(candidates, f, indent=2)

print("=" * 70)
print("  NEXT STEPS")
print("=" * 70)
print()
print(f"Full results saved to: {output_file}")
print()
print("Strategy:")
print("  1. Look for LDR instructions loading 0x30000000 into a register")
print("  2. Find nearby LDRB instructions using that register + offset 0x75")
print("  3. These are the most likely FPS control read locations")
print()
print("To find matches:")
print("  - Check if any LDR_FROM_POOL candidates have LDRB nearby")
print("  - Priority: LDRB with offset exactly 0x75")
print("  - Create test patches for top candidates")
