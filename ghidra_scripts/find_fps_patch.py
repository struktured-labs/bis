# Find FPS patch locations for ROM modification
# @category Analysis

"""
Find the exact code locations that need to be patched in code.bin
to change FPS from 30 to 60.
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

def set_thumb_mode(addr):
    """Set Thumb mode for an address"""
    try:
        tmode = currentProgram.getRegister("TMode")
        if tmode:
            val = RegisterValue(tmode, BigInteger.ONE)
            currentProgram.getProgramContext().setRegisterValue(addr, addr, val)
    except:
        pass

def force_thumb_disassemble(start_offset, length):
    """Force Thumb mode disassembly"""
    base = currentProgram.getMinAddress()
    start = base.add(start_offset)
    end = base.add(start_offset + length)

    # Set Thumb mode
    set_thumb_mode(start)

    addr_set = AddressSet(start, end)
    cmd = DisassembleCommand(addr_set, None, True)
    cmd.applyTo(currentProgram, ConsoleTaskMonitor())

def analyze_address(offset, context_size=64):
    """Analyze code at a specific offset"""
    base = currentProgram.getMinAddress()
    listing = currentProgram.getListing()

    # Disassemble region as Thumb
    force_thumb_disassemble(offset - context_size, context_size * 3)

    results = []
    addr = base.add(offset - context_size)
    end = base.add(offset + context_size)

    while addr.compareTo(end) < 0:
        instr = listing.getInstructionAt(addr)
        if instr:
            is_target = (addr.getOffset() - base.getOffset()) == offset
            results.append((addr.getOffset() - base.getOffset(),
                          instr.toString(),
                          is_target))
            addr = instr.getNext().getAddress() if instr.getNext() else addr.add(2)
        else:
            addr = addr.add(2)

    return results

def search_for_vblank_wait():
    """Search for gspWaitForVBlank or similar patterns"""
    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    patterns = [
        (b"gspWaitForVBlank", "gspWaitForVBlank string"),
        (b"WaitForVBlank", "WaitForVBlank string"),
        (b"frameSkip", "frameSkip string"),
        (b"FrameRate", "FrameRate string"),
    ]

    results = []
    for pattern, name in patterns:
        addr = memory.findBytes(currentProgram.getMinAddress(), pattern, None, True, monitor)
        if addr:
            results.append((addr.getOffset() - currentProgram.getMinAddress().getOffset(), name))

    return results

def find_mov_2_strb_patterns():
    """Find MOV Rx, #2 followed by store - potential frame skip setting"""
    listing = currentProgram.getListing()
    base = currentProgram.getMinAddress()
    results = []

    # First disassemble as Thumb
    print("[*] Disassembling as Thumb code...")
    force_thumb_disassemble(0, 0x50000)  # First ~300KB
    force_thumb_disassemble(0x50000, 0x50000)
    force_thumb_disassemble(0xA0000, 0x50000)
    force_thumb_disassemble(0xF0000, 0x50000)
    force_thumb_disassemble(0x140000, 0x50000)
    force_thumb_disassemble(0x190000, 0x50000)

    print("[*] Searching for frame timing patterns...")

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString()
        instr_str = str(instr)

        # Look for MOV with #2 (frame skip count for 30fps)
        if 'mov' in mnem.lower() and '#0x2' in instr_str.lower():
            # Check next instructions for store
            next_instr = instr.getNext()
            for _ in range(5):
                if next_instr:
                    next_mnem = next_instr.getMnemonicString().lower()
                    if 'str' in next_mnem:
                        offset = instr.getAddress().getOffset() - base.getOffset()
                        results.append((offset, instr_str, next_instr.toString()))
                        break
                    next_instr = next_instr.getNext()

        if len(results) > 100:
            break

    return results

def main():
    print("="*70)
    print("FPS ROM Patch Finder - Mario & Luigi BIS+BJJ")
    print("="*70)

    report = []
    report.append("FPS ROM PATCH ANALYSIS")
    report.append("="*70)
    report.append("")
    report.append("File: code.bin (in ExeFS)")
    report.append("")

    # Search for relevant strings
    print("\n[1] Searching for frame timing strings...")
    vblank_refs = search_for_vblank_wait()
    report.append("=== Frame timing strings ===")
    for offset, name in vblank_refs:
        line = "0x%06X: %s" % (offset, name)
        report.append(line)
        print("  " + line)

    # Find MOV #2 patterns
    print("\n[2] Finding MOV #2 -> STR patterns (30fps frame skip)...")
    mov_patterns = find_mov_2_strb_patterns()
    report.append("\n=== MOV #2 -> STR patterns ===")
    for offset, mov, store in mov_patterns[:50]:
        line = "0x%06X: %s -> %s" % (offset, mov, store)
        report.append(line)
        print("  " + line)

    # Analyze key candidates
    print("\n[3] Analyzing key candidates...")

    # Known CMP #2 locations from previous analysis
    key_offsets = [
        0x087704,  # CMP R5, #2
        0x143260,  # CMP R5, #2
        0x19EF02,  # CMP R5, #2
    ]

    report.append("\n=== Key candidate analysis ===")
    for offset in key_offsets:
        print("\n  Analyzing 0x%06X..." % offset)
        instrs = analyze_address(offset, 32)
        report.append("\n--- 0x%06X ---" % offset)
        for off, instr, is_target in instrs:
            marker = " <<<" if is_target else ""
            line = "  0x%06X: %s%s" % (off, instr, marker)
            report.append(line)
            if is_target or abs(off - offset) < 16:
                print("  " + line)

    # Write report
    output = "/workspace/build/fps_patch_report.txt"
    report.append("\n" + "="*70)
    report.append("RECOMMENDED PATCH LOCATIONS:")
    report.append("To change from 30fps to 60fps, look for:")
    report.append("1. MOV Rx, #2 instructions that set frame skip")
    report.append("2. Change #2 to #1 (or #0 for uncapped)")
    report.append("="*70)

    with open(output, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "="*70)
    print("Report saved to: " + output)
    print("="*70)

if __name__ == "__main__":
    main()
