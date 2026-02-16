#!/usr/bin/env python3
"""
Memory Scanner - Find what's writing to FPS control address
Uses Citra's memory dump to trace writes to 0x30000075
"""

import time
import subprocess
import sys
from pathlib import Path

def monitor_fps_address():
    """
    Monitor 0x30000075 and detect changes
    This simulates a watchpoint without GDB
    """

    print("=" * 70)
    print("  FPS Address Monitor - Finding Frame Limiter")
    print("=" * 70)
    print()
    print("Strategy: Since CTRPF cheat writes to 0x30000075 every frame,")
    print("we need to find the code that reads/writes this address.")
    print()
    print("Approach: Analyze the disassembly around float constants")
    print("and look for memory operations to 0x30000075")
    print()

    # Load code.bin
    with open("build/extracted/exefs_dir/code.bin.backup", "rb") as f:
        code_data = f.read()

    print("Searching code.bin for address references...")
    print()

    # The address 0x30000075 might appear as:
    # - 0x30000075 (direct)
    # - 0x30000074 + 1 (base + offset)
    # - 0x30000000 + 0x75 (base + offset)

    # Search for the base address 0x30000000
    import struct

    target_addrs = [
        0x30000075,  # Direct
        0x30000074,  # One byte before
        0x30000000,  # Base address
    ]

    for addr in target_addrs:
        addr_bytes = struct.pack('<I', addr)
        offset = 0
        found = []

        while True:
            idx = code_data.find(addr_bytes, offset)
            if idx == -1:
                break
            found.append(f"0x{idx:08X}")
            offset = idx + 1

        if found:
            print(f"Address 0x{addr:08X} found at offsets:")
            for loc in found[:20]:  # Show first 20
                print(f"  {loc}")
            if len(found) > 20:
                print(f"  ... and {len(found) - 20} more")
            print()

    print("=" * 70)
    print("  ANALYSIS")
    print("=" * 70)
    print()
    print("The CTRPF cheat code writes to 0x30000075:")
    print("  D3000000 30000000  # Set base address to 0x30000000")
    print("  50000074 01000101  # If [0x74] == 0x01 (30fps check)")
    print("  20000075 00000000  # Write 0x00 to [0x75] (set 60fps)")
    print()
    print("This means:")
    print("  - Byte at 0x30000075 controls FPS")
    print("  - 0x00 = 60 FPS")
    print("  - 0x01 = 30 FPS")
    print("  - Code checks byte 0x74 first, then writes to 0x75")
    print()
    print("Next step: Find the code that:")
    print("  1. Reads from 0x30000075")
    print("  2. Uses that value to set frame delay")
    print()

if __name__ == "__main__":
    monitor_fps_address()
