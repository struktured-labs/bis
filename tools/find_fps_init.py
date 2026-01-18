#!/usr/bin/env python3
"""
Find FPS initialization code in BIS code.bin.

The game sets 30fps by writing 0x01 to specific memory locations.
We're looking for code that initializes these values.
"""

import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

def disasm_region(code: bytes, offset: int, length: int, base_addr: int, mode='thumb'):
    """Disassemble a region of code."""
    if mode == 'thumb':
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    else:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    region = code[offset:offset + length]
    result = []
    for i in md.disasm(region, base_addr + offset):
        result.append(f"  0x{i.address:08X}: {i.mnemonic:8s} {i.op_str}")
    return result


def find_strb_patterns(code: bytes, base_addr: int = 0x100000):
    """Find STRB (store byte) instructions that might set FPS flags."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    print("Searching for STRB instructions that store #1 (30fps value)...")
    print("=" * 70)

    count = 0
    interesting = []

    for i in md.disasm(code, base_addr):
        if i.mnemonic.lower() == 'strb':
            # Look for patterns storing immediate 1
            interesting.append((i.address - base_addr, i.address, f"{i.mnemonic} {i.op_str}"))
            count += 1

    print(f"Found {count} STRB instructions")
    print("\nShowing first 100:")
    for offset, addr, instr in interesting[:100]:
        print(f"  0x{offset:06X} (0x{addr:08X}): {instr}")

    return interesting


def search_for_mov_1(code: bytes, base_addr: int = 0x100000):
    """Find MOV instructions that load #1 (potential fps flag value)."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    print("\n\nSearching for MOV Rx, #1 followed by store...")
    print("=" * 70)

    instructions = list(md.disasm(code, base_addr))

    for i, inst in enumerate(instructions):
        if inst.mnemonic.lower() in ['mov', 'movs'] and '#1' in inst.op_str and '#1' == inst.op_str.split(',')[-1].strip():
            # Look at next few instructions for a store
            context_start = max(0, i - 2)
            context_end = min(len(instructions), i + 5)
            context = instructions[context_start:context_end]

            has_store = any('str' in x.mnemonic.lower() for x in context[i-context_start:])
            if has_store:
                print(f"\n--- Potential FPS init at 0x{inst.address:X} ---")
                for j, ctx_inst in enumerate(context):
                    marker = ">>>" if ctx_inst == inst else "   "
                    print(f"{marker} 0x{ctx_inst.address:08X}: {ctx_inst.mnemonic:8s} {ctx_inst.op_str}")


def examine_around_offset(code: bytes, offset: int, base_addr: int = 0x100000, context: int = 64):
    """Examine code around a specific offset."""
    print(f"\n\nExamining code around offset 0x{offset:X}...")
    print("=" * 70)

    # Try Thumb mode
    print("\n[Thumb mode]")
    lines = disasm_region(code, max(0, offset - context), context * 2, base_addr, 'thumb')
    for line in lines:
        print(line)

    # Also try ARM mode
    print("\n[ARM mode]")
    lines = disasm_region(code, max(0, offset - context), context * 2, base_addr, 'arm')
    for line in lines:
        print(line)


def search_vblank(code: bytes, base_addr: int = 0x100000):
    """Search for vblank wait patterns - common in fps limiting code."""
    print("\n\nSearching for potential VBlank/frame sync code...")
    print("=" * 70)

    # The 3DS uses GSP (Graphics System Processor) for display
    # Common syscalls: svcWaitSynchronization, svcArbitrateAddress

    # Also look for common loop patterns with fixed wait values

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    # Search for bl (branch with link) that might call wait functions
    # and svc (supervisor call) for kernel functions

    svc_found = []
    for i in md.disasm(code, base_addr):
        if i.mnemonic.lower() == 'svc':
            svc_found.append((i.address, i.op_str))

    print(f"Found {len(svc_found)} SVC instructions")
    if svc_found:
        print("First 50 SVC calls:")
        for addr, op in svc_found[:50]:
            print(f"  0x{addr:08X}: svc {op}")


if __name__ == "__main__":
    code_path = Path("/home/struktured/projects/bis/build/extracted/exefs_dir/code.bin")
    code = code_path.read_bytes()

    print(f"Code size: {len(code)} bytes")
    print(f"Load address: 0x100000")
    print()

    # Search patterns
    # find_strb_patterns(code)
    # search_for_mov_1(code)

    # Look at specific offsets from the cheat
    # The cheat modifies 0x30000000 + 0xDA3AC
    # If code is loaded at 0x100000, then 0xDA3AC is at 0x1DA3AC in our address space
    examine_around_offset(code, 0xDA3AC, context=128)

    search_vblank(code)
