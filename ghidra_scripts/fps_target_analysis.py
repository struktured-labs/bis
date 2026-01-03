# FPS Target Analysis - Find exact code that controls frame timing
# @category Analysis

"""
Target addresses from cheat codes (offsets from 0x30000000 base):
- 0x74/0x75: Frame timing flag 1
- 0x64/0x65: Frame timing flag 2
- 0x44/0x45: Frame timing flag 3
- 0xDA3AC/0xDA3AD: Primary FPS control

Cheat writes byte 0x00 for 60fps, 0x01 for 30fps at the odd addresses.
The conditional checks look for 0x01000101 (byte pattern) vs 0x01000001.

This script finds code that accesses these offsets from any base register.
"""

from ghidra.util.task import ConsoleTaskMonitor

def find_str_to_low_offsets():
    """Find STR/STRB instructions that write to low offsets (0x44-0x78)"""
    results = []
    listing = currentProgram.getListing()

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()
        if 'str' in mnem:
            instr_str = instr.toString().lower()
            # Look for [Rx, #0x44], [Rx, #0x64], [Rx, #0x74], etc.
            for offset in ['#0x44]', '#0x45]', '#0x64]', '#0x65]', '#0x74]', '#0x75]']:
                if offset in instr_str:
                    func = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress())
                    func_name = func.getName() if func else "unknown"
                    results.append((str(instr.getAddress()), instr.toString(), func_name))
                    break
        if len(results) > 100:
            break
    return results

def find_ldr_from_low_offsets():
    """Find LDR instructions that read from low offsets"""
    results = []
    listing = currentProgram.getListing()

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()
        if 'ldr' in mnem:
            instr_str = instr.toString().lower()
            for offset in ['#0x44]', '#0x45]', '#0x64]', '#0x65]', '#0x74]', '#0x75]']:
                if offset in instr_str:
                    func = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress())
                    func_name = func.getName() if func else "unknown"
                    results.append((str(instr.getAddress()), instr.toString(), func_name))
                    break
        if len(results) > 100:
            break
    return results

def analyze_offset_0xDA3AC():
    """Analyze code at and around offset 0xDA3AC"""
    results = []
    listing = currentProgram.getListing()
    base = currentProgram.getMinAddress()

    # 0xDA3AC is about 894,892 bytes into the file
    target = base.add(0xDA3AC)

    # Check if this is code or data
    instr = listing.getInstructionAt(target)
    data = listing.getDataAt(target)

    if instr:
        results.append(("Instruction at 0xDA3AC", instr.toString()))
    if data:
        results.append(("Data at 0xDA3AC", str(data)))

    # Look at surrounding context
    for offset in range(-64, 64, 4):
        addr = base.add(0xDA3AC + offset)
        instr = listing.getInstructionAt(addr)
        if instr:
            results.append(("+%d" % offset, str(addr) + ": " + instr.toString()))

    return results

def find_frame_init_patterns():
    """Find patterns that might initialize frame control (MOV Rx, #1 followed by STR)"""
    results = []
    listing = currentProgram.getListing()

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()

        # Look for MOV with immediate 1
        if mnem in ['mov', 'movs']:
            if '#0x1' in instr.toString() or ', #1' in instr.toString():
                # Look at next few instructions for STR to our target offsets
                next_instr = instr.getNext()
                for _ in range(5):
                    if next_instr:
                        next_str = next_instr.toString().lower()
                        if 'str' in next_str:
                            for offset in ['#0x44]', '#0x64]', '#0x74]']:
                                if offset in next_str:
                                    func = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress())
                                    func_name = func.getName() if func else "unknown"
                                    results.append((str(instr.getAddress()),
                                                   instr.toString() + " -> " + next_instr.toString(),
                                                   func_name))
                                    break
                        next_instr = next_instr.getNext()
        if len(results) > 50:
            break
    return results

def search_gspu_references():
    """Search for GSPU/GSP (GPU service) related code"""
    results = []
    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    # Common GPU/GSP related strings
    patterns = [b"gsp", b"GSP", b"gpu", b"GPU", b"frame", b"vsync", b"vblank"]

    for pattern in patterns:
        addr = memory.findBytes(currentProgram.getMinAddress(), pattern, None, True, monitor)
        count = 0
        while addr and count < 5:
            results.append((pattern.decode(), str(addr)))
            addr = memory.findBytes(addr.add(1), pattern, None, True, monitor)
            count += 1

    return results

def main():
    print("="*70)
    print("FPS Target Analysis for Mario & Luigi BIS+BJJ")
    print("="*70)

    report = []
    report.append("FPS Target Analysis Report")
    report.append("="*70)
    report.append("")
    report.append("Target offsets: 0x44, 0x64, 0x74, 0xDA3AC")
    report.append("FPS value: 0x00=60fps, 0x01=30fps")
    report.append("")

    # 1. Find STR to low offsets
    print("\n[1] Finding STR instructions to target offsets...")
    str_results = find_str_to_low_offsets()
    report.append("\n=== STR to target offsets ===")
    for addr, instr, func in str_results:
        line = "%s: %s [%s]" % (addr, instr, func)
        report.append(line)
        print("  " + line)

    # 2. Find LDR from low offsets
    print("\n[2] Finding LDR instructions from target offsets...")
    ldr_results = find_ldr_from_low_offsets()
    report.append("\n=== LDR from target offsets ===")
    for addr, instr, func in ldr_results[:30]:
        line = "%s: %s [%s]" % (addr, instr, func)
        report.append(line)
        print("  " + line)

    # 3. Analyze 0xDA3AC area
    print("\n[3] Analyzing area around offset 0xDA3AC...")
    da3ac_results = analyze_offset_0xDA3AC()
    report.append("\n=== Code/Data at 0xDA3AC ===")
    for label, info in da3ac_results[:40]:
        line = "%s: %s" % (label, info)
        report.append(line)
        print("  " + line)

    # 4. Find frame init patterns
    print("\n[4] Finding potential FPS init patterns (MOV #1 -> STR)...")
    init_results = find_frame_init_patterns()
    report.append("\n=== Potential FPS init patterns ===")
    for addr, pattern, func in init_results:
        line = "%s: %s [%s]" % (addr, pattern, func)
        report.append(line)
        print("  " + line)

    # 5. Search for GSP/GPU references
    print("\n[5] Searching for GSP/GPU string references...")
    gsp_results = search_gspu_references()
    report.append("\n=== GSP/GPU references ===")
    for pattern, addr in gsp_results:
        line = "'%s' at %s" % (pattern, addr)
        report.append(line)
        print("  " + line)

    # Write report
    output = "/workspace/build/fps_target_report.txt"
    with open(output, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "="*70)
    print("Report saved to: " + output)
    print("="*70)

if __name__ == "__main__":
    main()
