#!/usr/bin/env python3
"""
Analyze code.bin to find FPS control code.

The 60fps cheat modifies RAM at these offsets (base 0x30000000):
- 0x74/0x75: FPS timing register
- 0xDA3AC/0xDA3AD: Primary FPS control
- 0x64/0x65: FPS timing register
- 0x44/0x45: FPS timing register

Values:
- 0x00 = 60 FPS
- 0x01 = 30 FPS

We're looking for code that initializes or checks these values.
"""

import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

def analyze_code(code_path: Path, base_addr: int = 0x100000):
    """Analyze ARM code for FPS-related patterns."""

    code = code_path.read_bytes()

    # Try both ARM and Thumb modes (3DS games often use Thumb)
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md_arm.detail = True
    md_thumb.detail = True

    # Key offsets from cheat codes (relative to 0x30000000 runtime base)
    # But in code.bin, we need to find what sets these values
    target_offsets = [0x44, 0x45, 0x64, 0x65, 0x74, 0x75, 0xDA3AC, 0xDA3AD]

    print(f"Analyzing {code_path} ({len(code)} bytes)")
    print(f"Base address: 0x{base_addr:X}")
    print()

    # Search for instructions that might reference frame timing
    # Look for patterns like:
    # - MOV Rx, #1 or MOV Rx, #2 (frame skip count)
    # - STR to low offsets that match our targets
    # - CMP with 1 or 2

    results = []

    # Search in chunks (code.bin might have mixed ARM/Thumb)
    # Most 3DS games use Thumb for main code
    print("Searching for FPS-related patterns in Thumb mode...")

    interesting_addrs = []

    for i in md_thumb.disasm(code, base_addr):
        # Look for instructions that might set frame timing
        mnemonic = i.mnemonic.lower()
        op_str = i.op_str.lower()

        # Pattern 1: Store byte with small immediate offset matching our targets
        if mnemonic in ['strb', 'str'] and any(f'#{off}' in op_str or f', {off}]' in op_str for off in ['0x44', '0x64', '0x74', '#68', '#100', '#116']):
            interesting_addrs.append((i.address, f"{i.mnemonic} {i.op_str}"))

        # Pattern 2: Instructions referencing DA3AC-ish values (might be in different format)
        if '0xda3a' in op_str or '894892' in op_str:  # 0xDA3AC = 894892
            interesting_addrs.append((i.address, f"{i.mnemonic} {i.op_str}"))

        # Pattern 3: VBlank/VSync wait patterns
        if 'vblank' in op_str or 'vsync' in op_str or 'frame' in op_str:
            interesting_addrs.append((i.address, f"{i.mnemonic} {i.op_str}"))

    if interesting_addrs:
        print(f"\nFound {len(interesting_addrs)} potentially interesting instructions:")
        for addr, instr in interesting_addrs[:50]:
            print(f"  0x{addr:X}: {instr}")

    # Also search for raw byte patterns that match the cheat comparison values
    # The cheat compares against 0x01000101 and 0x01000001
    print("\n\nSearching for cheat pattern bytes in binary...")

    pattern_60fps = bytes([0x01, 0x01, 0x00, 0x01])  # 01000101 little-endian
    pattern_30fps = bytes([0x01, 0x00, 0x00, 0x01])  # 01000001 little-endian

    for name, pattern in [("60fps pattern", pattern_60fps), ("30fps pattern", pattern_30fps)]:
        offset = 0
        while True:
            idx = code.find(pattern, offset)
            if idx == -1:
                break
            print(f"  {name} found at offset 0x{idx:X} (addr 0x{base_addr + idx:X})")
            offset = idx + 1
            if offset > len(code):
                break

    # Search for vblank syscall patterns (svc instructions)
    print("\n\nSearching for SVC (system call) instructions that might be vblank waits...")
    svc_count = 0
    for i in md_thumb.disasm(code, base_addr):
        if i.mnemonic.lower() == 'svc':
            if svc_count < 20:
                print(f"  0x{i.address:X}: {i.mnemonic} {i.op_str}")
            svc_count += 1
    print(f"  ... found {svc_count} total SVC instructions")

    # Look for specific 3DS kernel calls related to timing
    # WaitSynchronization1 = 0x24, WaitSynchronization = 0x25
    print("\n\nLooking for timing-related kernel calls (SVC #0x24, #0x25, #0x32)...")
    for i in md_thumb.disasm(code, base_addr):
        if i.mnemonic.lower() == 'svc' and i.op_str in ['#0x24', '#0x25', '#0x32', '0x24', '0x25', '0x32', '#36', '#37', '#50']:
            print(f"  0x{i.address:X}: {i.mnemonic} {i.op_str}")


if __name__ == "__main__":
    code_path = Path("/home/struktured/projects/bis/build/extracted/exefs_dir/code.bin")
    if not code_path.exists():
        print(f"Error: {code_path} not found")
        sys.exit(1)

    analyze_code(code_path)
