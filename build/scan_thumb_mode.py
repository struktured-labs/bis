#!/usr/bin/env python3
"""
Thumb Mode Scanner - 3DS primarily uses Thumb instructions
"""

from capstone import *
from capstone.arm import *
import struct
from pathlib import Path
import json

code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, 'rb') as f:
    code_data = f.read()

print("=" * 70)
print("  Thumb Mode Scanner - FPS Control Finder")
print("=" * 70)
print()

# Scan in Thumb mode (3DS uses Thumb extensively)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True  # Skip invalid bytes and continue

ldrb_with_offset = []
ldr_instructions = []
movw_mov_instructions = []  # MOVW/MOV can load immediate values

total_inst = 0
ldrb_count = 0

print("Scanning in Thumb mode (with skipdata)...")
print()

# Scan entire file
for inst in md.disasm(code_data, 0):
    total_inst += 1

    if total_inst % 100000 == 0:
        print(f"  {total_inst:,} instructions...")

    # LDRB with memory operand
    if 'ldrb' in inst.mnemonic:
        ldrb_count += 1

        if len(inst.operands) >= 2:
            op2 = inst.operands[1]
            if op2.type == ARM_OP_MEM and op2.mem.base != 0:
                offset = op2.mem.disp
                # Any offset (we'll filter later)
                ldrb_with_offset.append({
                    'address': inst.address,
                    'instruction': f"{inst.mnemonic} {inst.op_str}",
                    'offset': offset,
                    'base_reg': inst.reg_name(op2.mem.base),
                    'bytes': inst.bytes.hex()
                })

    # LDR instructions (all of them - we'll analyze later)
    elif inst.mnemonic == 'ldr':
        ldr_instructions.append({
            'address': inst.address,
            'instruction': f"{inst.mnemonic} {inst.op_str}",
            'bytes': inst.bytes.hex()
        })

    # MOVW/MOV with immediate (can load parts of 0x30000000)
    elif inst.mnemonic in ['movw', 'mov', 'movt']:
        if len(inst.operands) >= 2 and inst.operands[1].type == ARM_OP_IMM:
            imm = inst.operands[1].imm
            # Check for suspicious immediates
            if imm == 0x3000 or imm == 0x30000000 or imm == 0x0000 or (0x70 <= imm <= 0x78):
                movw_mov_instructions.append({
                    'address': inst.address,
                    'instruction': f"{inst.mnemonic} {inst.op_str}",
                    'immediate': imm,
                    'bytes': inst.bytes.hex()
                })

print()
print(f"Total instructions: {total_inst:,}")
print(f"Total LDRB: {ldrb_count}")
print(f"LDRB with offset: {len(ldrb_with_offset)}")
print(f"LDR instructions: {len(ldr_instructions)}")
print(f"MOVW/MOV/MOVT relevant: {len(movw_mov_instructions)}")
print()

# Filter LDRB for FPS-relevant offsets
fps_ldrb = [x for x in ldrb_with_offset if 0x70 <= x['offset'] <= 0x78]

print("=" * 70)
print(f"  LDRB WITH OFFSET 0x70-0x78: {len(fps_ldrb)}")
print("=" * 70)
print()

if fps_ldrb:
    # Sort by offset (0x75 first)
    fps_ldrb.sort(key=lambda x: (abs(x['offset'] - 0x75), x['address']))

    for i, cand in enumerate(fps_ldrb[:50]):
        marker = "*** EXACT 0x75 ***" if cand['offset'] == 0x75 else ""
        print(f"#{i+1}: 0x{cand['address']:08X}  {cand['instruction']:<30s}  {marker}")

    if len(fps_ldrb) > 50:
        print(f"\n... and {len(fps_ldrb) - 50} more")

print()
print("=" * 70)
print(f"  MOVW/MOV/MOVT WITH RELEVANT IMMEDIATES: {len(movw_mov_instructions)}")
print("=" * 70)
print()

if movw_mov_instructions:
    for i, cand in enumerate(movw_mov_instructions[:30]):
        print(f"#{i+1}: 0x{cand['address']:08X}  {cand['instruction']:<35s}  imm=0x{cand['immediate']:X}")

    if len(movw_mov_instructions) > 30:
        print(f"\n... and {len(movw_mov_instructions) - 30} more")

# Save results
output = {
    'ldrb_fps_offsets': fps_ldrb,
    'ldrb_all': ldrb_with_offset[:1000],  # Limit to first 1000
    'movw_mov': movw_mov_instructions,
    'stats': {
        'total_instructions': total_inst,
        'total_ldrb': ldrb_count,
        'ldrb_with_offset_70_78': len(fps_ldrb)
    }
}

output_file = Path("tmp/thumb_scan_results.json")
with open(output_file, 'w') as f:
    json.dump(output, f, indent=2)

print()
print(f"Results saved to: {output_file}")
