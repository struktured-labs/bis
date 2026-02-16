#!/usr/bin/env python3
"""
Disassemble ARM code around FPS control base address references
Uses capstone for proper ARM/Thumb disassembly
"""

from capstone import *
from capstone.arm import *
import struct
from pathlib import Path

# Load code.bin
code_path = Path("build/extracted/exefs_dir/code.bin.backup")
with open(code_path, "rb") as f:
    code_data = f.read()

# Offsets where 0x30000000 base address appears
TARGET_OFFSETS = [0x000B7CA0, 0x0016C61B]

print("=" * 70)
print("  ARM/Thumb Disassembly - FPS Control Base Address")
print("=" * 70)
print()

for offset in TARGET_OFFSETS:
    print("=" * 70)
    print(f"Offset: 0x{offset:08X}")
    print("=" * 70)
    print()

    # Try both ARM and Thumb modes
    for mode_val, mode_name in [(CS_MODE_ARM, "ARM"), (CS_MODE_THUMB, "Thumb")]:
        print(f"--- {mode_name} Mode ---")
        print()

        # Disassemble 200 bytes before and after
        start = max(0, offset - 200)
        end = min(len(code_data), offset + 200)

        # Align to instruction boundaries
        if mode_val == CS_MODE_ARM:
            start = (start // 4) * 4
        else:
            start = (start // 2) * 2

        code_chunk = code_data[start:end]

        md = Cs(CS_ARCH_ARM, mode_val)
        md.detail = True

        instructions = []
        for inst in md.disasm(code_chunk, start):
            instructions.append(inst)

        # Find instruction containing our offset
        target_inst_idx = None
        for idx, inst in enumerate(instructions):
            if inst.address <= offset < inst.address + inst.size:
                target_inst_idx = idx
                break

        if target_inst_idx is None:
            print(f"Could not find instruction at offset 0x{offset:08X}")
            print()
            continue

        # Show 20 instructions before and after
        start_idx = max(0, target_inst_idx - 20)
        end_idx = min(len(instructions), target_inst_idx + 21)

        print("Disassembly (40 instructions around target):")
        print()

        for idx in range(start_idx, end_idx):
            inst = instructions[idx]
            marker = ">>>>" if idx == target_inst_idx else "    "

            # Format with operands
            print(f"{marker} 0x{inst.address:08X}:  {inst.mnemonic:8s} {inst.op_str:30s}")

            # Show detailed info for target instruction
            if idx == target_inst_idx:
                print()
                print("     *** TARGET INSTRUCTION ***")
                print(f"     Bytes: {inst.bytes.hex()}")
                print(f"     Size: {inst.size}")

                if inst.operands:
                    print("     Operands:")
                    for op in inst.operands:
                        if op.type == ARM_OP_IMM:
                            print(f"       - Immediate: 0x{op.imm:08X} ({op.imm})")
                        elif op.type == ARM_OP_REG:
                            print(f"       - Register: {inst.reg_name(op.reg)}")
                        elif op.type == ARM_OP_MEM:
                            base_reg = inst.reg_name(op.mem.base) if op.mem.base else "none"
                            index_reg = inst.reg_name(op.mem.index) if op.mem.index else "none"
                            print(f"       - Memory: base={base_reg}, index={index_reg}, disp=0x{op.mem.disp:X}")
                print()

        print()

    # Check if this looks like data or code
    value = struct.unpack('<I', code_data[offset:offset+4])[0]
    print(f"Raw value at offset: 0x{value:08X}")
    if value == 0x30000000:
        print("  → This is the literal value 0x30000000 (plugin base address)")
    print()

print("=" * 70)
print("  ANALYSIS SUMMARY")
print("=" * 70)
print()
print("These are the locations where 0x30000000 appears as a 4-byte value.")
print("The actual FPS control logic likely:")
print("  1. Loads this value into a register (LDR rX, =0x30000000)")
print("  2. Adds offset 0x75 to access the FPS byte")
print("  3. Reads the byte (LDRB rY, [rX, #0x75])")
print("  4. Branches based on the value (CMP, BEQ, etc.)")
print()
print("To find the FPS control code, we need to:")
print("  - Find instructions that load 0x30000000 into a register")
print("  - Then look for byte reads with offset 0x75 nearby")
print("  - Or use GDB watchpoint to catch runtime access")
