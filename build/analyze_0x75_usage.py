#!/usr/bin/env python3
"""
Analyze all uses of 0x75 immediate and check for nearby memory access
"""

from capstone import *
from capstone.arm import *
from pathlib import Path
import json

code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, 'rb') as f:
    code_data = f.read()

print("=" * 70)
print("  Analyzing 0x75 Immediate Usage Patterns")
print("=" * 70)
print()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

# First pass: find all 0x75 immediates
fps_offset_insts = []

for inst in md.disasm(code_data, 0):
    if inst.mnemonic in ['mov', 'movs', 'add', 'adds', 'sub', 'subs']:
        for op in inst.operands:
            if op.type == ARM_OP_IMM and op.imm == 0x75:
                fps_offset_insts.append(inst.address)
                break

print(f"Found {len(fps_offset_insts)} instructions using 0x75")
print()

# Second pass: analyze context around each
promising_candidates = []

for target_addr in fps_offset_insts[:100]:  # Analyze first 100
    # Get 20 instructions after
    start = target_addr
    end = min(target_addr + 60, len(code_data))  # ~30 Thumb instructions

    instructions = []
    for inst in md.disasm(code_data[start:end], start):
        instructions.append(inst)
        if len(instructions) >= 20:
            break

    if not instructions:
        continue

    target_inst = instructions[0]

    # Check what register receives 0x75
    dest_reg = None
    if len(target_inst.operands) >= 1:
        if target_inst.operands[0].type == ARM_OP_REG:
            dest_reg = target_inst.reg_name(target_inst.operands[0].reg)

    # Look for memory access in next 10 instructions
    has_memory_access = False
    uses_dest_reg = False

    for inst in instructions[1:11]:
        # Skip data instructions from skipdata mode
        try:
            # Check for memory operands
            for op in inst.operands:
                if op.type == ARM_OP_MEM:
                    has_memory_access = True
                    # Check if it uses our destination register
                    if dest_reg and op.mem.base != 0:
                        base_reg_name = inst.reg_name(op.mem.base)
                        if base_reg_name == dest_reg:
                            uses_dest_reg = True
        except CsError:
            # Skip data/invalid instructions
            continue

    if has_memory_access:
        promising_candidates.append({
            'address': target_addr,
            'instruction': f"{target_inst.mnemonic} {target_inst.op_str}",
            'dest_reg': dest_reg,
            'uses_in_memory': uses_dest_reg,
            'context': [f"{inst.mnemonic} {inst.op_str}" for inst in instructions[:10]]
        })

print(f"Candidates with nearby memory access: {len(promising_candidates)}")
print()

# Show top candidates where dest_reg is used in memory access
priority = [c for c in promising_candidates if c['uses_in_memory']]

print("=" * 70)
print(f"  HIGH PRIORITY: 0x75 register used in memory access ({len(priority)})")
print("=" * 70)
print()

for i, cand in enumerate(priority[:20]):
    print(f"Candidate #{i+1}:")
    print(f"  Address: 0x{cand['address']:08X}")
    print(f"  {cand['instruction']:40s} (dest={cand['dest_reg']})")
    print(f"  Context:")
    for j, ctx_inst in enumerate(cand['context']):
        marker = ">>>" if j == 0 else "   "
        print(f"    {marker} {ctx_inst}")
    print()

if len(priority) > 20:
    print(f"... and {len(priority) - 20} more")
    print()

# Show other candidates
other = [c for c in promising_candidates if not c['uses_in_memory']]

print("=" * 70)
print(f"  OTHER: 0x75 with nearby memory (register not directly used) ({len(other)})")
print("=" * 70)
print()

for i, cand in enumerate(other[:10]):
    print(f"#{i+1}: 0x{cand['address']:08X}  {cand['instruction']}")

if len(other) > 10:
    print(f"... and {len(other) - 10} more")

# Save results
output = {
    'high_priority': priority[:50],
    'other': other[:50]
}

output_file = Path("tmp/0x75_analysis.json")
with open(output_file, 'w') as f:
    json.dump(output, f, indent=2)

print()
print(f"Results saved to: {output_file}")
