#!/usr/bin/env python3
"""
Analyze the 6 locations that caused crashes when patched
These are definitely executed code - understanding them might reveal patterns
"""

from capstone import *
from capstone.arm import *
from pathlib import Path

code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, 'rb') as f:
    code_data = f.read()

# The 6 crash locations
CRASH_LOCATIONS = [
    {'id': 1, 'address': 0x00002482, 'instruction': 'adds r3, #0x75'},
    {'id': 3, 'address': 0x00013518, 'instruction': 'adds r1, #0x75'},
    {'id': 4, 'address': 0x0001A14C, 'instruction': 'adds r0, #0x75'},
    {'id': 11, 'address': 0x0004A5D4, 'instruction': 'adds r3, #0x75'},
    {'id': 12, 'address': 0x000574EE, 'instruction': 'movs r2, #0x75'},
    {'id': 14, 'address': 0x0005A8AC, 'instruction': 'adds r1, #0x75'},
]

print("=" * 70)
print("  Crash Location Analysis")
print("=" * 70)
print()
print("These 6 locations caused 'Illegal instruction' crashes when patched.")
print("This means they are DEFINITELY executed during game startup/title screen.")
print()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

for crash in CRASH_LOCATIONS:
    cid = crash['id']
    addr = crash['address']

    print("=" * 70)
    print(f"Candidate #{cid}: 0x{addr:08X}")
    print(f"Instruction: {crash['instruction']}")
    print("=" * 70)
    print()

    # Disassemble 50 instructions before and after
    start = max(0, addr - 100)
    end = min(len(code_data), addr + 100)

    instructions = []
    for inst in md.disasm(code_data[start:end], start):
        instructions.append(inst)

    # Find target instruction
    target_idx = None
    for idx, inst in enumerate(instructions):
        if inst.address == addr:
            target_idx = idx
            break

    if target_idx is None:
        print("Could not disassemble at this location")
        print()
        continue

    # Show 20 before, target, 20 after
    show_start = max(0, target_idx - 20)
    show_end = min(len(instructions), target_idx + 21)

    print("Disassembly (40 instructions):")
    print()

    for idx in range(show_start, show_end):
        inst = instructions[idx]

        if idx == target_idx:
            marker = ">>>"
            print(f"{marker} 0x{inst.address:08X}:  {inst.mnemonic:10s} {inst.op_str:30s}  *** CRASH HERE ***")
        else:
            marker = "   "
            print(f"{marker} 0x{inst.address:08X}:  {inst.mnemonic:10s} {inst.op_str}")

    print()

    # Analyze what happens after the target instruction
    print("Next 10 instructions after crash point:")
    print()

    for idx in range(target_idx + 1, min(target_idx + 11, len(instructions))):
        inst = instructions[idx]
        print(f"    0x{inst.address:08X}:  {inst.mnemonic:10s} {inst.op_str}")

        # Look for memory access
        try:
            for op in inst.operands:
                if op.type == ARM_OP_MEM:
                    print(f"        → Memory access detected")
                    if op.mem.base != 0:
                        base_reg = inst.reg_name(op.mem.base)
                        print(f"        → Base register: {base_reg}")
                        if op.mem.disp != 0:
                            print(f"        → Offset: {op.mem.disp}")
        except:
            pass

    print()

    # Pattern analysis
    print("Pattern Analysis:")
    print()

    # Check if this is in a loop
    has_branch_back = False
    for idx in range(target_idx + 1, min(target_idx + 15, len(instructions))):
        inst = instructions[idx]
        if inst.mnemonic.startswith('b') and len(inst.operands) > 0:
            if inst.operands[0].type == ARM_OP_IMM:
                branch_target = inst.operands[0].imm
                if branch_target < addr:
                    has_branch_back = True
                    print(f"  - Found backward branch to 0x{branch_target:08X} (possible loop)")

    # Check for function calls nearby
    has_bl = False
    for idx in range(max(0, target_idx - 5), min(target_idx + 5, len(instructions))):
        inst = instructions[idx]
        if inst.mnemonic in ['bl', 'blx']:
            has_bl = True
            print(f"  - Function call nearby: {inst.mnemonic} {inst.op_str}")

    # Check for comparisons
    for idx in range(target_idx + 1, min(target_idx + 10, len(instructions))):
        inst = instructions[idx]
        if inst.mnemonic.startswith('cmp') or inst.mnemonic.startswith('tst'):
            print(f"  - Comparison found: {inst.mnemonic} {inst.op_str}")

    if not has_branch_back and not has_bl:
        print("  - Linear code (no loops or calls nearby)")

    print()

print("=" * 70)
print("  SUMMARY")
print("=" * 70)
print()
print("All 6 crash locations use ADDS or MOVS to work with 0x75.")
print("Changing these values causes illegal instruction crashes.")
print()
print("Possible reasons:")
print("  1. These calculate critical addresses (changing causes bad memory access)")
print("  2. They're part of initialization code (wrong values break startup)")
print("  3. They're unrelated to FPS (coincidental use of 0x75 for other purposes)")
print()
print("Key insight: The crashes prove static patching 0x75 immediate values")
print("              doesn't work for FPS control. Need runtime analysis (GDB).")
