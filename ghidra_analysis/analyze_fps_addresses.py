# Analyze specific addresses where 0x30000000 base address is found
# @category Analysis

from ghidra.program.model.address import AddressSet
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Addresses where 0x30000000 was found
TARGET_OFFSETS = [0x000B7CA0, 0x0016C61B]

print("=" * 70)
print("  Analyzing FPS Control Addresses")
print("=" * 70)
print()

# Get current program
program = getCurrentProgram()
monitor = ConsoleTaskMonitor()

# Initialize decompiler
decompiler = DecompInterface()
decompiler.openProgram(program)

for offset in TARGET_OFFSETS:
    print("-" * 70)
    print("Offset: 0x{:08X}".format(offset))
    print("-" * 70)
    print()

    # Get address
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    # Get instruction at this address
    instruction = getInstructionAt(addr)
    if instruction:
        print("Instruction: {}".format(instruction))
        print()
    else:
        print("No instruction at this address (might be data)")
        print()

    # Get 20 bytes of context around this location
    print("Raw bytes:")
    for i in range(-16, 16):
        context_addr = addr.add(i)
        byte_val = getByte(context_addr)
        print("  0x{:08X}: 0x{:02X}".format(context_addr.getOffset(), byte_val & 0xFF))
    print()

    # Try to find the function containing this address
    func = getFunctionContaining(addr)
    if func:
        print("Function: {}".format(func.getName()))
        print("Function start: 0x{:08X}".format(func.getEntryPoint().getOffset()))
        print("Function end: 0x{:08X}".format(func.getBody().getMaxAddress().getOffset()))
        print()

        # Get disassembly around this location (50 instructions before and after)
        print("Disassembly context (20 instructions):")
        listing = program.getListing()
        context_addr = addr.subtract(40)  # Start 40 bytes before
        for i in range(20):
            inst = getInstructionAfter(context_addr)
            if inst:
                marker = " >>> " if inst.getAddress().equals(addr) else "     "
                print("{} 0x{:08X}: {}".format(marker, inst.getAddress().getOffset(), inst))
                context_addr = inst.getAddress()
        print()

        # Try to decompile the function
        print("Decompiled code:")
        results = decompiler.decompileFunction(func, 30, monitor)
        if results and results.decompileCompleted():
            decomp_source = results.getDecompiledFunction().getC()
            print(decomp_source)
        else:
            print("  [Decompilation failed]")
        print()
    else:
        print("Not in a function - might be data or unanalyzed code")
        print()

        # Try to show instructions anyway
        print("Nearby instructions:")
        context_addr = addr.subtract(40)
        for i in range(20):
            inst = getInstructionAt(context_addr)
            if inst:
                marker = " >>> " if inst.getAddress().equals(addr) else "     "
                print("{} 0x{:08X}: {}".format(marker, inst.getAddress().getOffset(), inst))
                context_addr = inst.getAddress().add(inst.getLength())
            else:
                context_addr = context_addr.add(1)
        print()

print("=" * 70)
print("Analysis complete")
print("=" * 70)

decompiler.dispose()
