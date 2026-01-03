# Find FPS control code in Mario & Luigi: BIS+BJJ
# @category Analysis
# @author Claude

"""
This script searches for code that might control the FPS limit.

The 60fps cheat modifies RAM at:
- 0x30000074/75 - Timing register 1
- 0x30000064/65 - Timing register 2
- 0x30000044/45 - Timing register 3
- 0x300DA3AC/AD - Primary FPS control

Values: 0x00 = 60fps, 0x01 = 30fps

We're looking for:
1. Code that initializes these values to 1
2. Code that compares/branches based on these values
3. GSP/display timing related code
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os


def find_mov_1_strb_patterns():
    """Find MOV Rx, #1 followed by STRB - potential fps init."""
    results = []
    listing = currentProgram.getListing()

    # Iterate through all instructions
    instr = listing.getInstructionAt(currentProgram.getMinAddress())

    while instr is not None:
        mnemonic = instr.getMnemonicString().lower()

        # Look for MOV with immediate 1
        if mnemonic in ['mov', 'movs']:
            ops = instr.toString()
            if '#0x1' in ops or ', #1' in ops:
                # Check next instruction for STRB
                next_instr = instr.getNext()
                if next_instr:
                    next_mnem = next_instr.getMnemonicString().lower()
                    if 'strb' in next_mnem or 'str' in next_mnem:
                        results.append((instr.getAddress(), instr.toString(), next_instr.toString()))

        instr = instr.getNext()

        # Limit search to prevent hanging
        if len(results) > 200:
            break

    return results


def find_gsp_related_code():
    """Find GSP service related code."""
    results = []

    # Search for "gsp" string references
    memory = currentProgram.getMemory()

    # Search memory for "gsp" pattern
    min_addr = currentProgram.getMinAddress()

    search_bytes = "gsp".encode()
    addr = memory.findBytes(min_addr, search_bytes, None, True, monitor)

    while addr is not None:
        results.append(("GSP string", addr))
        addr = memory.findBytes(addr.add(1), search_bytes, None, True, monitor)
        if len(results) > 20:
            break

    return results


def find_offset_instructions():
    """Find instructions with offsets 0x44, 0x64, 0x74."""
    listing = currentProgram.getListing()
    offset_results = []

    instr = listing.getInstructionAt(currentProgram.getMinAddress())
    count = 0
    while instr is not None and count < 500000:
        ops = instr.toString().lower()
        if '#0x44]' in ops or '#0x64]' in ops or '#0x74]' in ops:
            offset_results.append((instr.getAddress(), instr.toString()))
        instr = instr.getNext()
        count += 1

    return offset_results


def find_frame_functions():
    """Find functions that might be frame handlers."""
    func_mgr = currentProgram.getFunctionManager()
    frame_funcs = []

    for func in func_mgr.getFunctions(True):
        name = func.getName().lower()
        if 'frame' in name or 'vblank' in name or 'vsync' in name or 'display' in name:
            frame_funcs.append((func.getEntryPoint(), func.getName()))

    return frame_funcs


def main():
    print("=" * 70)
    print("FPS Control Analysis for Mario & Luigi: BIS+BJJ")
    print("=" * 70)

    output_path = "/workspace/build/fps_analysis_report.txt"

    report = []
    report.append("FPS Control Analysis Report")
    report.append("=" * 70)

    # 1. Find GSP related code
    print("\n[1] Searching for GSP service references...")
    gsp_results = find_gsp_related_code()
    report.append("\nGSP references found: {}".format(len(gsp_results)))
    for name, addr in gsp_results[:20]:
        report.append("  {}: {}".format(addr, name))
        print("  {}: {}".format(addr, name))

    # 2. Find MOV #1 -> STRB patterns
    print("\n[2] Searching for MOV #1 -> STRB patterns...")
    mov_patterns = find_mov_1_strb_patterns()
    report.append("\nMOV #1 -> STRB patterns found: {}".format(len(mov_patterns)))
    for addr, mov_instr, strb_instr in mov_patterns[:50]:
        report.append("  {}: {} ; {}".format(addr, mov_instr, strb_instr))
        print("  {}: {}".format(addr, mov_instr))

    # 3. Look for specific offset patterns (0x44, 0x64, 0x74)
    print("\n[3] Searching for instructions with offsets 0x44, 0x64, 0x74...")
    offset_results = find_offset_instructions()

    report.append("\nInstructions with target offsets: {}".format(len(offset_results)))
    for addr, instr_str in offset_results[:100]:
        report.append("  {}: {}".format(addr, instr_str))
        print("  {}: {}".format(addr, instr_str))

    # 4. Search for vblank/frame timing patterns
    print("\n[4] Searching for potential frame timing code...")
    frame_funcs = find_frame_functions()

    report.append("\nPotential frame-related functions: {}".format(len(frame_funcs)))
    for addr, name in frame_funcs:
        report.append("  {}: {}".format(addr, name))
        print("  {}: {}".format(addr, name))

    # Write report
    print("\n[*] Writing report to: {}".format(output_path))
    report.append("\n" + "=" * 70)
    report.append("Analysis complete.")

    with open(output_path, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "=" * 70)
    print("Analysis complete. Check fps_analysis_report.txt")
    print("=" * 70)


if __name__ == "__main__":
    monitor = ConsoleTaskMonitor()
    main()
