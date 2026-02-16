#!/usr/bin/env python3
"""
Disassemble around WaitSynchronization callers using DECOMPRESSED code.bin.
"""
import struct
import sys

try:
    from capstone import *
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "capstone"])
    from capstone import *

CODE_BIN = "tmp/decompressed/code_decompressed.bin"
BASE_ADDR = 0x00100000

# LR → SVC_PC pairs from profiler
CALLERS = [
    (0x0012E210, 0x0012E44C, 5039, "Main frame wait caller (42.0%)"),
    (0x001228F4, 0x001227E4, 2892, "Secondary wait caller (24.1%)"),
    (0x0011B668, 0x0011B734, 2023, "Third wait caller (16.9%)"),
    (0x0011B52C, 0x0011B52C, 2022, "Fourth wait caller (16.9%) - LR=0x0042D668 (CRO)"),
]

def read_code():
    with open(CODE_BIN, "rb") as f:
        return f.read()

def disasm(data, addr, length, mode="thumb"):
    """Disassemble region"""
    offset = addr - BASE_ADDR
    if offset < 0 or offset >= len(data):
        return []
    end = min(offset + length, len(data))
    region = data[offset:end]
    arch_mode = CS_MODE_THUMB if mode == "thumb" else CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, arch_mode)
    md.detail = True
    return list(md.disasm(region, addr))

def find_function_bounds(data, addr, mode="thumb"):
    """Find the function containing addr by searching for push/pop patterns"""
    # Search backwards for function start (push {... lr})
    func_start = None
    step = 2 if mode == "thumb" else 4
    for back in range(0, 1024, step):
        test_addr = addr - back
        offset = test_addr - BASE_ADDR
        if offset < 0:
            break
        insns = disasm(data, test_addr, step * 2, mode)
        for insn in insns:
            if insn.mnemonic == 'push' and 'lr' in insn.op_str:
                func_start = insn.address
                break
            # ARM mode: stmdb sp!, {..., lr}
            if insn.mnemonic in ['stmdb', 'stm', 'push'] and 'lr' in insn.op_str:
                func_start = insn.address
                break
        if func_start:
            break

    return func_start

def main():
    data = read_code()
    print(f"Decompressed code size: {len(data)} bytes (0x{len(data):X})")
    print(f"Virtual range: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + len(data):08X}")
    print()

    for lr_addr, svc_pc, count, desc in CALLERS:
        lr_offset = lr_addr - BASE_ADDR
        if lr_offset >= len(data):
            print(f"LR 0x{lr_addr:08X} outside code.bin (CRO module)")
            print()
            continue

        print("=" * 90)
        print(f"LR=0x{lr_addr:08X} → SVC at 0x{svc_pc:08X}, {count} calls")
        print(f"  {desc}")
        print("=" * 90)

        # Try both modes, score them
        for mode in ["arm", "thumb"]:
            # Find function start
            func_start = find_function_bounds(data, lr_addr, mode)

            if func_start:
                start = func_start
            else:
                start = lr_addr - 128

            # Disassemble the function
            insns = disasm(data, start, lr_addr - start + 128, mode)

            # Score: count valid-looking instructions
            good = sum(1 for i in insns if i.mnemonic in [
                'push', 'pop', 'ldr', 'str', 'mov', 'movs', 'add', 'adds',
                'sub', 'subs', 'cmp', 'bl', 'blx', 'bx', 'b', 'beq', 'bne',
                'ldrb', 'strb', 'ldrh', 'strh', 'and', 'orr', 'eor', 'tst',
                'stmdb', 'ldmia', 'cbz', 'cbnz', 'movw', 'movt', 'it',
                'ite', 'itt', 'lsl', 'lsr', 'asr', 'mul', 'mla',
            ])
            total = len(insns) if insns else 1

            if good / total < 0.5:
                continue  # Skip bad mode

            print(f"\n  [{mode.upper()} mode] (func start: {'0x{:08X}'.format(func_start) if func_start else 'unknown'})")
            print(f"  Quality: {good}/{total} ({100*good//total}%)")
            print()

            for insn in insns:
                marker = ""

                if insn.address == lr_addr:
                    marker = "  <<<<< LR (return from WaitSync)"
                elif insn.mnemonic in ['bl', 'blx'] and insn.address + insn.size == lr_addr:
                    marker = "  ===== CALL TO WAITSYNC ====="

                if insn.mnemonic == 'push' and 'lr' in insn.op_str:
                    marker += "  [FUNC START]"
                if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
                    marker += "  [FUNC END]"
                if insn.mnemonic == 'svc':
                    marker += " [SVC!]"

                # Constants
                op = insn.op_str
                if insn.mnemonic in ['mov', 'movs', 'movw']:
                    # Check for small constants
                    parts = op.split(',')
                    if len(parts) >= 2:
                        val_str = parts[-1].strip()
                        if val_str.startswith('#'):
                            try:
                                val = int(val_str[1:], 0)
                                if val in [1, 2, 3, 30, 60]:
                                    marker += f"  *** CONST={val}"
                            except ValueError:
                                pass
                if insn.mnemonic in ['cmp', 'cmn']:
                    parts = op.split(',')
                    if len(parts) >= 2:
                        val_str = parts[-1].strip()
                        if val_str.startswith('#'):
                            try:
                                val = int(val_str[1:], 0)
                                if val in [1, 2, 3, 30, 60]:
                                    marker += f"  *** CMP={val}"
                            except ValueError:
                                pass
                if insn.mnemonic in ['sub', 'subs']:
                    if '#1' in op:
                        marker += "  *** DEC1"
                    if '#2' in op:
                        marker += "  *** DEC2"

                # Backward branches (loops)
                if insn.mnemonic.startswith('b') and insn.mnemonic not in ['bl', 'blx', 'bx']:
                    target = insn.op_str.strip()
                    if target.startswith('#'):
                        try:
                            t = int(target[1:], 0)
                            if t < insn.address:
                                marker += f"  *** LOOP→0x{t:08X}"
                        except ValueError:
                            pass

                print(f"    0x{insn.address:08X}:  {insn.mnemonic:10s} {insn.op_str:45s}{marker}")
            print()
            break  # Show best mode only

if __name__ == "__main__":
    main()
