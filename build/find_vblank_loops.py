#!/usr/bin/env python3
"""
Find VBlank wait loops in 3DS code.bin
Looks for SVC 0x24/0x25 (WaitSynchronization) calls and analyzes
the surrounding code for frame counting patterns.
"""
import struct
import sys

CODE_BIN = "build/v3_extract/exefs_dir/code.bin"
BASE_ADDR = 0x00100000  # 3DS code base address

def read_code():
    with open(CODE_BIN, "rb") as f:
        return f.read()

def decode_thumb16(hw):
    """Decode a 16-bit Thumb instruction"""
    return hw

def find_svc_calls(data):
    """Find all SVC instructions in Thumb code"""
    results = []
    for i in range(0, len(data) - 1, 2):
        hw = struct.unpack_from('<H', data, i)[0]
        # SVC in Thumb: 0xDFxx where xx is the SVC number
        if (hw >> 8) == 0xDF:
            svc_num = hw & 0xFF
            results.append((i, svc_num))
    return results

def find_arm_svc_calls(data):
    """Find all SVC instructions in ARM code"""
    results = []
    for i in range(0, len(data) - 3, 4):
        word = struct.unpack_from('<I', data, i)[0]
        # SVC in ARM: 0xEFxxxxxx (condition always) or 0x_Fxxxxxx
        if (word & 0x0F000000) == 0x0F000000:
            cond = (word >> 28) & 0xF
            if cond <= 0xE:  # Valid condition
                svc_num = word & 0xFFFFFF
                results.append((i, svc_num))
    return results

def analyze_context(data, offset, window=64):
    """Analyze code around an SVC call for loop patterns"""
    start = max(0, offset - window)
    end = min(len(data), offset + window)

    context = []

    # Look for interesting patterns in Thumb code near the SVC
    for i in range(start, end, 2):
        if i + 1 >= len(data):
            break
        hw = struct.unpack_from('<H', data, i)[0]

        addr = BASE_ADDR + i

        # MOV Rd, #imm (Thumb: 001_0_0_xxx_xxxxxxxx)
        if (hw >> 11) == 0x04:  # MOV Rd, #imm8
            rd = (hw >> 8) & 0x7
            imm = hw & 0xFF
            if imm in [1, 2, 3, 30, 60]:
                context.append(f"  0x{addr:08X} (+{i-offset:+d}): MOV R{rd}, #{imm}")

        # CMP Rn, #imm (Thumb: 00101_xxx_xxxxxxxx)
        if (hw >> 11) == 0x05:  # CMP Rn, #imm8
            rn = (hw >> 8) & 0x7
            imm = hw & 0xFF
            if imm in [1, 2, 3, 30, 60]:
                context.append(f"  0x{addr:08X} (+{i-offset:+d}): CMP R{rn}, #{imm}")

        # SUB Rd, #imm (Thumb: 00111_xxx_xxxxxxxx)
        if (hw >> 11) == 0x07:  # SUB Rn, #imm8
            rd = (hw >> 8) & 0x7
            imm = hw & 0xFF
            if imm in [1, 2]:
                context.append(f"  0x{addr:08X} (+{i-offset:+d}): SUB R{rd}, #{imm}")

        # Branch instructions (loops)
        if (hw >> 12) == 0xD:  # Conditional branch
            cond = (hw >> 8) & 0xF
            if cond != 0xF:  # Not SVC
                offset_val = hw & 0xFF
                if offset_val & 0x80:
                    offset_val -= 256
                target = i + 4 + offset_val * 2
                cond_names = ['EQ','NE','CS','CC','MI','PL','VS','VC',
                             'HI','LS','GE','LT','GT','LE','AL','NV']
                if abs(target - offset) < window:
                    context.append(f"  0x{addr:08X} (+{i-offset:+d}): B{cond_names[cond]} -> 0x{BASE_ADDR+target:08X} (loop?)")

    return context

def analyze_arm_context(data, offset, window=64):
    """Analyze ARM code around an SVC call"""
    start = max(0, offset - window)
    end = min(len(data), offset + window)

    context = []

    for i in range(start, end, 4):
        if i + 3 >= len(data):
            break
        word = struct.unpack_from('<I', data, i)[0]
        addr = BASE_ADDR + i

        # MOV Rd, #imm (ARM data processing immediate)
        if (word & 0x0FE00000) == 0x03A00000:  # MOV
            rd = (word >> 12) & 0xF
            imm = word & 0xFF
            rotate = ((word >> 8) & 0xF) * 2
            if rotate == 0:
                if imm in [1, 2, 3, 30, 60]:
                    context.append(f"  0x{addr:08X} (+{i-offset:+d}): MOV R{rd}, #{imm}")

        # CMP Rn, #imm
        if (word & 0x0FE00000) == 0x03500000:  # CMP immediate
            rn = (word >> 16) & 0xF
            imm = word & 0xFF
            rotate = ((word >> 8) & 0xF) * 2
            if rotate == 0:
                if imm in [1, 2, 3, 30, 60]:
                    context.append(f"  0x{addr:08X} (+{i-offset:+d}): CMP R{rn}, #{imm}")

        # SUB Rd, Rn, #imm
        if (word & 0x0FE00000) == 0x02400000:  # SUB immediate
            rd = (word >> 12) & 0xF
            rn = (word >> 16) & 0xF
            imm = word & 0xFF
            if imm in [1, 2]:
                context.append(f"  0x{addr:08X} (+{i-offset:+d}): SUB R{rd}, R{rn}, #{imm}")

        # Branch
        if (word & 0x0E000000) == 0x0A000000:
            cond = (word >> 28) & 0xF
            offset_val = word & 0x00FFFFFF
            if offset_val & 0x800000:
                offset_val -= 0x1000000
            target = i + 8 + offset_val * 4
            if abs(target - offset) < window * 2:
                cond_names = ['EQ','NE','CS','CC','MI','PL','VS','VC',
                             'HI','LS','GE','LT','GT','LE','AL','NV']
                if cond < 15:
                    context.append(f"  0x{addr:08X} (+{i-offset:+d}): B{cond_names[cond]} -> 0x{BASE_ADDR+target:08X} (loop?)")

    return context

def hexdump_region(data, offset, before=32, after=32):
    """Hex dump a region around an offset"""
    start = max(0, offset - before)
    end = min(len(data), offset + after)

    lines = []
    for i in range(start, end, 16):
        hex_bytes = ' '.join(f'{data[j]:02X}' for j in range(i, min(i+16, end)))
        addr = BASE_ADDR + i
        marker = " <-- SVC" if start <= offset < end and i <= offset < i + 16 else ""
        lines.append(f"  0x{addr:08X}: {hex_bytes}{marker}")
    return lines

def main():
    print("=== VBlank Loop Finder for 3DS code.bin ===")
    print(f"Reading {CODE_BIN}...")

    data = read_code()
    print(f"Code size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")
    print()

    # Find Thumb SVC calls
    print("Scanning for Thumb SVC calls...")
    thumb_svcs = find_svc_calls(data)

    # Find ARM SVC calls
    print("Scanning for ARM SVC calls...")
    arm_svcs = find_arm_svc_calls(data)

    # Filter for WaitSynchronization
    wait_sync_thumb = [(off, num) for off, num in thumb_svcs if num in [0x24, 0x25]]
    wait_sync_arm = [(off, num) for off, num in arm_svcs if num in [0x24, 0x25]]

    print(f"\nTotal Thumb SVCs: {len(thumb_svcs)}")
    print(f"Total ARM SVCs: {len(arm_svcs)}")
    print(f"WaitSynchronization (Thumb): {len(wait_sync_thumb)}")
    print(f"WaitSynchronization (ARM): {len(wait_sync_arm)}")

    print("\n" + "="*80)
    print("THUMB WaitSynchronization Sites:")
    print("="*80)

    for offset, svc_num in wait_sync_thumb:
        addr = BASE_ADDR + offset
        svc_name = "WaitSynchronization1" if svc_num == 0x24 else "WaitSynchronizationN"
        print(f"\n--- SVC 0x{svc_num:02X} ({svc_name}) at 0x{addr:08X} (file offset 0x{offset:X}) ---")

        context = analyze_context(data, offset, window=80)
        if context:
            print("Interesting instructions nearby:")
            for line in context:
                print(line)

        print("Hex dump:")
        for line in hexdump_region(data, offset, 48, 16):
            print(line)

    print("\n" + "="*80)
    print("ARM WaitSynchronization Sites:")
    print("="*80)

    for offset, svc_num in wait_sync_arm:
        addr = BASE_ADDR + offset
        svc_name = "WaitSynchronization1" if svc_num == 0x24 else "WaitSynchronizationN"
        print(f"\n--- SVC 0x{svc_num:02X} ({svc_name}) at 0x{addr:08X} (file offset 0x{offset:X}) ---")

        context = analyze_arm_context(data, offset, window=80)
        if context:
            print("Interesting instructions nearby:")
            for line in context:
                print(line)

        print("Hex dump:")
        for line in hexdump_region(data, offset, 48, 16):
            print(line)

    # Also look for all SVC calls to understand the distribution
    print("\n" + "="*80)
    print("SVC Call Distribution (Thumb):")
    print("="*80)
    svc_counts = {}
    for _, num in thumb_svcs:
        svc_counts[num] = svc_counts.get(num, 0) + 1
    for num, count in sorted(svc_counts.items()):
        svc_names = {
            0x01: "ControlMemory", 0x02: "QueryMemory", 0x03: "ExitProcess",
            0x08: "CreateThread", 0x09: "ExitThread", 0x0A: "SleepThread",
            0x17: "CreateEvent", 0x18: "SignalEvent", 0x19: "ClearEvent",
            0x1E: "CreateMutex", 0x1F: "ReleaseMutex",
            0x21: "CreateSemaphore", 0x22: "ReleaseSemaphore",
            0x23: "CreateTimer", 0x24: "WaitSynchronization1",
            0x25: "WaitSynchronizationN", 0x27: "DuplicateHandle",
            0x2D: "ConnectToPort", 0x32: "SendSyncRequest",
            0x2E: "GetSystemTick", 0x35: "GetProcessId",
            0x37: "GetThreadId", 0x38: "GetResourceLimit",
            0x3D: "OutputDebugString",
        }
        name = svc_names.get(num, f"Unknown_0x{num:02X}")
        print(f"  SVC 0x{num:02X} ({name}): {count} calls")

    print("\n" + "="*80)
    print("SVC Call Distribution (ARM):")
    print("="*80)
    svc_counts = {}
    for _, num in arm_svcs:
        if num < 0x100:  # Only valid SVC numbers
            svc_counts[num] = svc_counts.get(num, 0) + 1
    for num, count in sorted(svc_counts.items()):
        svc_names = {
            0x01: "ControlMemory", 0x02: "QueryMemory", 0x03: "ExitProcess",
            0x08: "CreateThread", 0x09: "ExitThread", 0x0A: "SleepThread",
            0x17: "CreateEvent", 0x18: "SignalEvent", 0x19: "ClearEvent",
            0x1E: "CreateMutex", 0x1F: "ReleaseMutex",
            0x21: "CreateSemaphore", 0x22: "ReleaseSemaphore",
            0x23: "CreateTimer", 0x24: "WaitSynchronization1",
            0x25: "WaitSynchronizationN", 0x27: "DuplicateHandle",
            0x2D: "ConnectToPort", 0x32: "SendSyncRequest",
            0x2E: "GetSystemTick", 0x35: "GetProcessId",
            0x37: "GetThreadId", 0x38: "GetResourceLimit",
            0x3D: "OutputDebugString",
        }
        name = svc_names.get(num, f"Unknown_0x{num:02X}")
        print(f"  SVC 0x{num:02X} ({name}): {count} calls")

if __name__ == "__main__":
    main()
