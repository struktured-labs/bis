#!/usr/bin/env python3
"""
Disassemble code around the WaitSynchronization CALLERS (LR values).
These are the actual game code functions that control frame pacing.
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

# Callers from the SVC profiler (LR values)
CALLERS = [
    (0x0012E210, "Main frame wait caller (42.0%) - calls 0x0012E44C"),
    (0x001228F4, "Secondary wait caller (24.1%) - calls 0x001227E4"),
    (0x0011B668, "Third wait caller (16.9%) - calls 0x0011B734"),
    # 0x0042D668 is in CRO module, not in code.bin
]

def read_code():
    with open(CODE_BIN, "rb") as f:
        return f.read()

def disassemble_region(data, addr, before=256, after=128):
    """Disassemble in both ARM and Thumb modes"""
    file_offset = addr - BASE_ADDR
    if file_offset < 0 or file_offset >= len(data):
        return []

    start_offset = max(0, file_offset - before)
    end_offset = min(len(data), file_offset + after)
    region = data[start_offset:end_offset]

    results = []
    for mode_name, arch_mode in [("THUMB", CS_MODE_THUMB), ("ARM", CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, arch_mode)
        md.detail = True
        start_addr = BASE_ADDR + start_offset
        instructions = list(md.disasm(region, start_addr))

        # Sanity check: look for BL/BLX instructions near the LR address
        # LR points to the instruction AFTER the BL, so look for BL at LR-4 or LR-2
        has_bl_nearby = any(
            insn.mnemonic in ['bl', 'blx'] and abs((insn.address + insn.size) - addr) <= 4
            for insn in instructions
        )

        # Also check for PUSH at function start and POP at function end
        has_push = any(insn.mnemonic == 'push' for insn in instructions[:20])

        if has_bl_nearby:
            results.append((mode_name, instructions, True))
        elif has_push and mode_name == "THUMB":
            results.append((mode_name, instructions, False))

    if not results:
        # Fallback: show both
        for mode_name, arch_mode in [("THUMB", CS_MODE_THUMB)]:
            md = Cs(CS_ARCH_ARM, arch_mode)
            start_addr = BASE_ADDR + start_offset
            instructions = list(md.disasm(region, start_addr))
            results.append((mode_name, instructions, False))

    return results

def main():
    data = read_code()
    code_end = BASE_ADDR + len(data)
    print(f"Code size: {len(data)} bytes (0x{BASE_ADDR:08X} - 0x{code_end:08X})")
    print()

    for addr, desc in CALLERS:
        file_offset = addr - BASE_ADDR
        if file_offset >= len(data):
            print(f"0x{addr:08X} is OUTSIDE code.bin (CRO module?)")
            continue

        print("=" * 90)
        print(f"LR=0x{addr:08X} (file offset 0x{file_offset:X})")
        print(f"  {desc}")
        print("=" * 90)

        results = disassemble_region(data, addr, before=256, after=128)

        for mode_name, instructions, has_bl in results:
            print(f"\n  [{mode_name} mode] {'(BL found)' if has_bl else ''}")

            for insn in instructions:
                marker = ""

                # Mark the LR return point
                if insn.address == addr:
                    marker = "  <<<<< LR RETURN POINT (after BL)"
                elif abs(insn.address - addr) <= 4:
                    marker = "  <-- near LR"

                # Mark the BL call that led to WaitSync
                if insn.mnemonic in ['bl', 'blx']:
                    next_addr = insn.address + insn.size
                    if abs(next_addr - addr) <= 4:
                        marker += "  ===== THIS IS THE CALL TO WAITSYNC ====="

                # Highlight SVC
                if insn.mnemonic == 'svc':
                    marker += " ===== SVC ====="

                # Highlight frame-related constants
                op = insn.op_str
                if insn.mnemonic in ['mov', 'movs', 'movw']:
                    for val, name in [(2, "FRAME_COUNT?"), (1, "SINGLE_FRAME?"),
                                      (30, "30FPS?"), (60, "60FPS?"), (0x1e, "30?"), (0x3c, "60?")]:
                        if f'#{val}' in op or f'#0x{val:x}' in op:
                            marker += f"  *** {name}"
                if insn.mnemonic in ['cmp', 'cmn']:
                    for val, name in [(2, "CMP 2?"), (1, "CMP 1?"), (30, "CMP 30?"), (60, "CMP 60?")]:
                        if f'#{val}' in op:
                            marker += f"  *** {name}"
                if insn.mnemonic in ['sub', 'subs']:
                    if '#1' in op or '#2' in op:
                        marker += "  *** DECREMENT"
                if insn.mnemonic == 'push':
                    marker += "  [FUNC START]"
                if insn.mnemonic == 'pop' and 'pc' in op:
                    marker += "  [FUNC END]"

                # Loop detection
                if insn.mnemonic.startswith('b') and insn.mnemonic not in ['bl', 'blx', 'bx']:
                    target = insn.op_str.strip()
                    if target.startswith('#'):
                        try:
                            t = int(target[1:], 0)
                            if t < insn.address and abs(t - addr) < 300:
                                marker += f"  *** BACKWARD BRANCH → 0x{t:08X}"
                        except ValueError:
                            pass

                print(f"    0x{insn.address:08X}:  {insn.mnemonic:8s} {insn.op_str:40s}{marker}")
            print()
            break  # Show first matching mode

if __name__ == "__main__":
    main()
