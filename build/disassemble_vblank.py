#!/usr/bin/env python3
"""
Disassemble around the HIGH priority VBlank candidate
to understand the loop structure and find patch points
"""

from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

def disassemble_around(offset, before=50, after=50):
    """Disassemble instructions around a specific offset"""
    code_path = Path("build/extracted/exefs_dir/code.bin")
    with open(code_path, "rb") as f:
        code_data = f.read()

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    # Calculate byte range (approximate)
    start_offset = max(0, offset - before * 2)  # Thumb instructions are 2 or 4 bytes
    end_offset = min(len(code_data), offset + after * 2)

    chunk = code_data[start_offset:end_offset]

    print("=" * 70)
    print(f"  Disassembly around 0x{offset:06X}")
    print("=" * 70)
    print()

    for inst in md.disasm(chunk, start_offset):
        marker = " >>> " if inst.address == offset else "     "
        print(f"{marker}0x{inst.address:06X}:  {inst.mnemonic:10s} {inst.op_str}")

        # Show extra detail for the target instruction
        if inst.address == offset:
            print(f"     Bytes: {inst.bytes.hex()}")
            print(f"     Size: {inst.size}")
            print()

# Analyze the HIGH priority candidate
target_offset = 0x14DB7A

print("HIGH PRIORITY VBlank Candidate Analysis")
print()
disassemble_around(target_offset, before=40, after=40)

print()
print("=" * 70)
print("ANALYSIS")
print("=" * 70)
print()
print("Look for:")
print("1. Loop start (label or branch target)")
print("2. Counter initialization (movs rX, #1 or #2)")
print("3. Counter decrement (subs rX, #1)")
print("4. Conditional branch back (bne, beq, etc.)")
print()
print("Patch strategies:")
print("A. NOP out the SVC call (replace with movs r0, r0)")
print("B. Change counter init (2 → 1) if waiting for 2 VBlanks")
print("C. Change branch condition to skip wait")
print()
