# Deep FPS control analysis for Mario & Luigi: BIS+BJJ
# @category Analysis
# @author Claude

"""
Deep analysis to find FPS control code.
Forces disassembly and searches for patterns.
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.mem import MemoryAccessException

def disassemble_all():
    """Force disassembly of all executable memory."""
    print("[*] Running aggressive disassembly...")

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    # Get all memory blocks
    blocks = memory.getBlocks()
    total_disasm = 0

    for block in blocks:
        if block.isExecute():
            print("  Disassembling block: %s" % block.getName())
            start = block.getStart()
            end = block.getEnd()

            # Create address set for the block
            addr_set = AddressSet(start, end)

            # Disassemble
            cmd = DisassembleCommand(addr_set, None, True)
            cmd.applyTo(currentProgram, monitor)

            # Count instructions
            instr_count = 0
            for instr in listing.getInstructions(start, True):
                if instr.getAddress().compareTo(end) > 0:
                    break
                instr_count += 1

            total_disasm += instr_count
            print("    Disassembled %d instructions" % instr_count)

    print("  Total instructions: %d" % total_disasm)
    return total_disasm


def search_for_byte_pattern(pattern_bytes, name):
    """Search for a byte pattern in memory."""
    results = []
    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    min_addr = currentProgram.getMinAddress()
    max_addr = currentProgram.getMaxAddress()

    addr = memory.findBytes(min_addr, pattern_bytes, None, True, monitor)
    while addr is not None and addr.compareTo(max_addr) <= 0:
        results.append(addr)
        addr = memory.findBytes(addr.add(1), pattern_bytes, None, True, monitor)
        if len(results) > 100:
            break

    return results


def find_all_strb_instructions():
    """Find all STRB instructions."""
    results = []
    listing = currentProgram.getListing()

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()
        if 'strb' in mnem:
            results.append((str(instr.getAddress()), instr.toString()))
            if len(results) > 500:
                break

    return results


def find_references_to_offset(offset_hex):
    """Find instructions that reference a specific offset."""
    results = []
    listing = currentProgram.getListing()

    patterns = [
        "#0x%x]" % offset_hex,
        "#%d]" % offset_hex,
        ", 0x%x]" % offset_hex,
    ]

    for instr in listing.getInstructions(True):
        ops = instr.toString().lower()
        for pat in patterns:
            if pat.lower() in ops:
                results.append((str(instr.getAddress()), instr.toString()))
                break
        if len(results) > 200:
            break

    return results


def analyze_gsp_references():
    """Analyze code around GSP string references."""
    results = []
    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()
    monitor = ConsoleTaskMonitor()

    # Find GSP string
    gsp_bytes = "gsp".encode()
    addr = memory.findBytes(currentProgram.getMinAddress(), gsp_bytes, None, True, monitor)

    if addr:
        print("  GSP string at: %s" % str(addr))

        # Get references to this address
        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            results.append(("GSP ref from", str(from_addr)))

            # Get the function containing this reference
            func_mgr = currentProgram.getFunctionManager()
            func = func_mgr.getFunctionContaining(from_addr)
            if func:
                results.append(("  in function", func.getName() + " at " + str(func.getEntryPoint())))

    return results


def search_frame_timing_patterns():
    """Search for common frame timing patterns."""
    results = []
    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    # Patterns from the cheat code comparison values
    patterns = [
        (bytearray([0x01, 0x01, 0x00, 0x01]), "60fps check pattern (01000101)"),
        (bytearray([0x01, 0x00, 0x00, 0x01]), "30fps check pattern (01000001)"),
    ]

    for pattern, name in patterns:
        addrs = search_for_byte_pattern(pattern, name)
        for addr in addrs[:20]:
            results.append((name, str(addr)))

    return results


def main():
    print("=" * 70)
    print("Deep FPS Control Analysis for Mario & Luigi: BIS+BJJ")
    print("=" * 70)

    report = []
    report.append("Deep FPS Control Analysis Report")
    report.append("=" * 70)
    report.append("")
    report.append("Binary: " + str(currentProgram.getExecutablePath()))

    # 1. Force disassembly
    print("")
    print("[1] Forcing disassembly of all code...")
    total_instr = disassemble_all()
    report.append("")
    report.append("Total instructions disassembled: %d" % total_instr)

    # 2. Find all STRB instructions
    print("")
    print("[2] Finding all STRB instructions...")
    strb_results = find_all_strb_instructions()
    report.append("")
    report.append("STRB instructions found: %d" % len(strb_results))
    for addr, instr in strb_results[:100]:
        report.append("  %s: %s" % (addr, instr))

    # 3. Find references to target offsets
    print("")
    print("[3] Finding references to offsets 0x44, 0x64, 0x74...")
    for offset in [0x44, 0x64, 0x74]:
        offset_results = find_references_to_offset(offset)
        report.append("")
        report.append("References to offset 0x%x: %d" % (offset, len(offset_results)))
        for addr, instr in offset_results[:50]:
            report.append("  %s: %s" % (addr, instr))
            print("  %s: %s" % (addr, instr))

    # 4. Analyze GSP references
    print("")
    print("[4] Analyzing GSP service references...")
    gsp_results = analyze_gsp_references()
    report.append("")
    report.append("GSP analysis:")
    for name, info in gsp_results:
        report.append("  %s: %s" % (name, info))
        print("  %s: %s" % (name, info))

    # 5. Search for frame timing patterns
    print("")
    print("[5] Searching for frame timing byte patterns...")
    pattern_results = search_frame_timing_patterns()
    report.append("")
    report.append("Frame timing patterns found: %d" % len(pattern_results))
    for name, addr in pattern_results:
        report.append("  %s at %s" % (name, addr))
        print("  %s at %s" % (name, addr))

    # Write report
    output_path = "/workspace/build/deep_fps_analysis_report.txt"
    print("")
    print("[*] Writing report to: " + output_path)
    report.append("")
    report.append("=" * 70)

    with open(output_path, 'w') as f:
        f.write('\n'.join(report))

    print("")
    print("=" * 70)
    print("Deep analysis complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
