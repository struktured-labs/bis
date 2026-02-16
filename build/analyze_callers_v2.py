#!/usr/bin/env python3
"""
Disassemble around WaitSynchronization callers.
Try both ARM and Thumb mode, start from LR and work backwards to find function.
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

CALLERS = [
    (0x0012E210, 0x0012E44C, "Main frame wait caller (42.0%)"),
    (0x001228F4, 0x001227E4, "Secondary wait caller (24.1%)"),
    (0x0011B668, 0x0011B734, "Third wait caller (16.9%)"),
]

def read_code():
    with open(CODE_BIN, "rb") as f:
        return f.read()

def try_disassemble(data, start_addr, length, mode):
    """Try to disassemble a region"""
    file_offset = start_addr - BASE_ADDR
    if file_offset < 0 or file_offset >= len(data):
        return []
    end = min(file_offset + length, len(data))
    region = data[file_offset:end]

    arch_mode = CS_MODE_THUMB if mode == "thumb" else CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, arch_mode)
    md.detail = True
    return list(md.disasm(region, start_addr))

def score_disassembly(instructions):
    """Score how 'good' a disassembly looks (higher = more likely correct)"""
    score = 0
    for insn in instructions:
        # Good signs: known instruction patterns
        if insn.mnemonic in ['push', 'pop', 'ldr', 'str', 'mov', 'add', 'sub',
                              'cmp', 'bl', 'blx', 'bx', 'b', 'stmdb', 'ldmia',
                              'stm', 'ldm', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble']:
            score += 1
        if insn.mnemonic == 'push' and 'lr' in insn.op_str:
            score += 5  # Function prologue
        if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
            score += 5  # Function epilogue
        if insn.mnemonic == 'svc':
            score += 3
        if insn.mnemonic == 'bl' or insn.mnemonic == 'blx':
            score += 2
        # Bad signs: unusual instructions
        if 'invalid' in insn.mnemonic or insn.mnemonic.startswith('.'):
            score -= 3
        if insn.mnemonic in ['bkpt', 'udf']:
            score -= 2
    return score

def main():
    data = read_code()
    print(f"Code size: {len(data)} bytes")
    print(f"Text segment: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + len(data):08X}")
    print()

    # First, verify code.bin starts with ARM
    first_word = struct.unpack_from('<I', data, 0)[0]
    print(f"First word: 0x{first_word:08X}")
    if (first_word & 0x0F000000) == 0x0B000000:
        print("  -> ARM BL instruction (code starts in ARM mode)")
    print()

    for lr_addr, svc_pc, desc in CALLERS:
        file_offset = lr_addr - BASE_ADDR
        if file_offset >= len(data) or file_offset < 0:
            print(f"LR 0x{lr_addr:08X} outside code.bin!")
            continue

        print("=" * 90)
        print(f"LR=0x{lr_addr:08X} → calls SVC wrapper at 0x{svc_pc:08X}")
        print(f"  {desc}")
        print("=" * 90)

        # Try both modes and pick the best one
        best_mode = None
        best_score = -999
        best_instructions = None

        for mode in ["arm", "thumb"]:
            # Disassemble a window around LR
            window_start = lr_addr - 128
            insns = try_disassemble(data, window_start, 256, mode)
            s = score_disassembly(insns)
            if s > best_score:
                best_score = s
                best_mode = mode
                best_instructions = insns

        if best_instructions is None:
            print("  Could not disassemble")
            continue

        print(f"\n  [Best mode: {best_mode.upper()}, score={best_score}]")
        print()

        # Now do a wider disassembly in the best mode
        window_start = lr_addr - 256
        instructions = try_disassemble(data, window_start, 512, best_mode)

        for insn in instructions:
            marker = ""

            if insn.address == lr_addr:
                marker = "  <<<<< LR (return from WaitSync call)"
            elif insn.address + insn.size == lr_addr:
                marker = "  ===== CALL TO WAITSYNC WRAPPER ====="

            if insn.mnemonic == 'svc':
                marker += " [SVC]"
            if insn.mnemonic == 'push' and 'lr' in insn.op_str:
                marker += "  [FUNCTION START]"
            if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
                marker += "  [FUNCTION END]"

            # Constants
            op = insn.op_str
            if insn.mnemonic in ['mov', 'movs', 'movw', 'movt']:
                for val in [1, 2, 3, 30, 60]:
                    if f'#{val}' == op.split(',')[-1].strip() or f'#0x{val:x}' == op.split(',')[-1].strip():
                        marker += f"  *** CONST {val}"
            if insn.mnemonic in ['cmp', 'cmn']:
                for val in [1, 2, 3, 30, 60]:
                    if f'#{val}' in op or f'#0x{val:x}' in op:
                        marker += f"  *** CMP {val}"
            if insn.mnemonic in ['sub', 'subs'] and ('#1' in op or '#2' in op):
                marker += "  *** DEC"

            print(f"    0x{insn.address:08X}:  {insn.mnemonic:10s} {insn.op_str:45s}{marker}")

        print()

if __name__ == "__main__":
    main()
