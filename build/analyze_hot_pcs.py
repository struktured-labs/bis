#!/usr/bin/env python3
"""
Disassemble code around the hot WaitSynchronization PCs.
"""
import struct
import sys

try:
    from capstone import *
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "capstone"])
    from capstone import *

CODE_BIN = "build/v3_extract/exefs_dir/code.bin"
BASE_ADDR = 0x00100000

# Hot PCs from the SVC profiler
HOT_PCS = [
    (0x0012E44C, 2118, "Primary frame wait (42.4%)"),
    (0x001227E4, 1184, "Secondary frame wait (23.7%)"),
    (0x0011B52C, 839, "Third wait (16.8%)"),
    (0x0011B734, 838, "Fourth wait (16.8%)"),
    (0x00287C58, 11, "Occasional wait (0.2%)"),
]

def read_code():
    with open(CODE_BIN, "rb") as f:
        return f.read()

def disassemble_both_modes(data, pc, before=200, after=80):
    """Try both ARM and Thumb disassembly around a PC"""
    file_offset = pc - BASE_ADDR
    start_offset = max(0, file_offset - before)
    end_offset = min(len(data), file_offset + after)
    region = data[start_offset:end_offset]

    for mode_name, arch_mode in [("THUMB", CS_MODE_THUMB), ("ARM", CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, arch_mode)
        md.detail = True

        start_addr = BASE_ADDR + start_offset
        instructions = list(md.disasm(region, start_addr))

        # Check if we get any SVC within 16 bytes of the PC
        has_svc_nearby = any(
            abs(insn.address - pc) <= 16 and insn.mnemonic == 'svc'
            for insn in instructions
        )

        if has_svc_nearby or mode_name == "THUMB":
            yield mode_name, instructions

def main():
    data = read_code()
    print(f"Code size: {len(data)} bytes")
    print()

    for pc, count, desc in HOT_PCS:
        file_offset = pc - BASE_ADDR
        if file_offset >= len(data):
            print(f"PC 0x{pc:08X} is outside code.bin (maybe CRO module)")
            continue

        print("=" * 80)
        print(f"PC 0x{pc:08X} (file offset 0x{file_offset:X}) - {desc}")
        print(f"  Call count: {count}")
        print("=" * 80)

        for mode_name, instructions in disassemble_both_modes(data, pc, before=200, after=80):
            print(f"\n  [{mode_name} mode]")
            for insn in instructions:
                marker = ""
                if insn.address == pc:
                    marker = "  <<<<< PC HERE"
                elif abs(insn.address - pc) <= 4:
                    marker = "  <-- near PC"

                # Highlight SVC
                if insn.mnemonic == 'svc':
                    marker += " ===== SVC CALL ====="

                # Highlight interesting constants
                if insn.mnemonic in ['mov', 'movs', 'movw', 'movt']:
                    for c in ['#2', '#1,', '#1\n', '#0x1e', '#0x3c', '#30', '#60']:
                        if c.strip() in insn.op_str:
                            marker += f" *** CONST"
                            break
                if insn.mnemonic in ['cmp', 'cmn']:
                    for c in ['#2', '#1', '#30', '#60', '#0x1e', '#0x3c']:
                        if c in insn.op_str:
                            marker += f" *** CMP"
                            break
                if insn.mnemonic in ['sub', 'subs'] and ('#1' in insn.op_str or '#2' in insn.op_str):
                    marker += " *** DEC"
                if insn.mnemonic in ['b', 'bne', 'beq', 'bgt', 'bge', 'blt', 'ble', 'bhi', 'bls', 'bcc', 'bcs', 'bl', 'blx']:
                    op = insn.op_str.strip()
                    if op.startswith('#'):
                        try:
                            target = int(op[1:], 0)
                            if target < pc and abs(target - pc) < 300:
                                marker += f" *** BACKWARD BRANCH (loop?)"
                        except ValueError:
                            pass

                print(f"    0x{insn.address:08X}:  {insn.mnemonic:8s} {insn.op_str:40s}{marker}")
            print()
            break  # Only show first matching mode

if __name__ == "__main__":
    main()
