# Analyze specific functions that write to FPS control offsets
# @category Analysis

"""
Key addresses found that write to FPS control offsets:
- 0x013B20: STRB to [Rx, #0x75]
- 0x013B24: STRB to [Rx, #0x75]
- 0x01DB6C: STRB to [Rx, #0x64]
- 0x01C900: STRB to [Rx, #0x74]
"""

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet

def force_disassemble(start, length):
    """Force disassembly of a region"""
    base = currentProgram.getMinAddress()
    start_addr = base.add(start)
    end_addr = base.add(start + length)
    addr_set = AddressSet(start_addr, end_addr)
    cmd = DisassembleCommand(addr_set, None, True)
    cmd.applyTo(currentProgram, ConsoleTaskMonitor())

def analyze_function(offset):
    """Analyze function containing the given offset"""
    base = currentProgram.getMinAddress()
    addr = base.add(offset)

    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(addr)

    if not func:
        # Try to create function
        from ghidra.app.cmd.function import CreateFunctionCmd
        # First disassemble
        force_disassemble(offset - 0x100, 0x300)
        func = func_mgr.getFunctionContaining(addr)

    return func

def decompile_function(func):
    """Get decompiled view"""
    if not func:
        return None
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def get_disassembly(offset, count=40):
    """Get disassembly listing"""
    base = currentProgram.getMinAddress()
    listing = currentProgram.getListing()

    # Disassemble first
    force_disassemble(offset - 0x40, count * 4 + 0x80)

    lines = []
    addr = base.add(offset - 0x40)
    for i in range(count):
        instr = listing.getInstructionAt(addr)
        if instr:
            lines.append("%s: %s" % (str(addr), instr.toString()))
            addr = instr.getNext().getAddress() if instr.getNext() else addr.add(4)
        else:
            # Try as data
            addr = addr.add(4)
    return lines

def main():
    print("="*70)
    print("FPS Function Analysis - Mario & Luigi BIS+BJJ")
    print("="*70)

    # Key addresses that write to FPS offsets
    key_addresses = [
        (0x013B20, "STRB to #0x75"),
        (0x013B24, "STRB to #0x75"),
        (0x01DB6C, "STRB to #0x64"),
        (0x01C900, "STRB to #0x74"),
        (0x0DA3AC, "Primary FPS area")
    ]

    report = []
    report.append("FPS Function Analysis Report")
    report.append("="*70)

    for offset, desc in key_addresses:
        print("\n" + "="*70)
        print("Analyzing 0x%X: %s" % (offset, desc))
        print("="*70)

        report.append("\n\n=== 0x%X: %s ===" % (offset, desc))

        # Get disassembly
        print("\nDisassembly around 0x%X:" % offset)
        disasm = get_disassembly(offset, 30)
        for line in disasm:
            print("  " + line)
            report.append(line)

        # Try to get function
        func = analyze_function(offset)
        if func:
            print("\nFunction: %s at %s" % (func.getName(), func.getEntryPoint()))
            report.append("\nFunction: %s at %s" % (func.getName(), func.getEntryPoint()))

            # Decompile
            decomp = decompile_function(func)
            if decomp:
                print("\nDecompiled:")
                trunc = decomp[:1500] if len(decomp) > 1500 else decomp
                print(trunc)
                report.append("\nDecompiled:")
                report.append(trunc)
        else:
            print("\nNo function found at this location")
            report.append("No function found")

    # Write report
    output = "/workspace/build/fps_function_report.txt"
    with open(output, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "="*70)
    print("Report saved to: %s" % output)
    print("="*70)

if __name__ == "__main__":
    main()
