# Find instructions that read from 0x30000000 memory region (FPS control)
# @category Analysis

from ghidra.program.model.address import AddressSet
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

print("=" * 70)
print("  Finding FPS Control Read Instructions")
print("=" * 70)
print()
print("Target: Instructions that read from 0x30000000-0x30000100")
print("This is the plugin memory region where FPS control byte lives")
print()

# Get current program
program = getCurrentProgram()
listing = program.getListing()
memory = program.getMemory()
monitor = ConsoleTaskMonitor()

# Target memory region
FPS_REGION_START = 0x30000000
FPS_REGION_END = 0x30000100
FPS_CONTROL_BYTE = 0x30000075

reads_found = []

# Scan all instructions
print("Scanning all instructions for memory reads...")
print()

instruction_iter = listing.getInstructions(True)
count = 0

for instruction in instruction_iter:
    count += 1
    if count % 100000 == 0:
        print("Scanned {} instructions...".format(count))

    # Check operands for memory references
    for i in range(instruction.getNumOperands()):
        refs = instruction.getOperandReferences(i)
        for ref in refs:
            if ref.isMemoryReference():
                to_addr = ref.getToAddress()
                if to_addr:
                    to_offset = to_addr.getOffset()
                    # Check if reading from FPS region
                    if FPS_REGION_START <= to_offset < FPS_REGION_END:
                        reads_found.append({
                            'addr': instruction.getAddress().getOffset(),
                            'inst': str(instruction),
                            'target': to_offset,
                            'ref_type': str(ref.getReferenceType())
                        })

print("Scan complete. Analyzed {} instructions".format(count))
print()

# Report findings
print("=" * 70)
print("  RESULTS")
print("=" * 70)
print()

if len(reads_found) == 0:
    print("No direct references to 0x30000000 region found!")
    print()
    print("This means:")
    print("  1. The address is computed dynamically (register-based)")
    print("  2. The base address (0x30000000) is loaded into a register")
    print("  3. Then offset is added at runtime")
    print()
    print("Looking for 0x30000000 constant loads instead...")
    print()

    # Search for LDR instructions that load 0x30000000
    instruction_iter = listing.getInstructions(True)
    for instruction in instruction_iter:
        inst_str = str(instruction).lower()
        # Look for MOV or LDR with 0x30000000
        if ('ldr' in inst_str or 'mov' in inst_str) and ('0x30000000' in inst_str or '#0x30000000' in inst_str):
            print("0x{:08X}: {}".format(instruction.getAddress().getOffset(), instruction))

            # Try to find function
            func = getFunctionContaining(instruction.getAddress())
            if func:
                print("  Function: {}".format(func.getName()))

else:
    print("Found {} instructions that read from FPS region:".format(len(reads_found)))
    print()

    for read in reads_found:
        print("-" * 70)
        print("Address: 0x{:08X}".format(read['addr']))
        print("Instruction: {}".format(read['inst']))
        print("Reads from: 0x{:08X}".format(read['target']))
        print("Type: {}".format(read['ref_type']))

        # Check if this is the exact FPS control byte
        if read['target'] == FPS_CONTROL_BYTE:
            print("*** THIS IS THE FPS CONTROL BYTE! ***")

        # Find containing function
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(read['addr'])
        func = getFunctionContaining(addr)
        if func:
            print("Function: {}".format(func.getName()))
            print("Function range: 0x{:08X} - 0x{:08X}".format(
                func.getEntryPoint().getOffset(),
                func.getBody().getMaxAddress().getOffset()
            ))

        print()

print("=" * 70)
print("Analysis complete")
print("=" * 70)
