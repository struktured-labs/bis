# @category Analysis
# Analyze context around FPS STRB instructions

from ghidra.program.model.address import AddressFactory
from ghidra.app.cmd.disassemble import DisassembleCommand

print("=" * 60)
print("Context Analysis for FPS STRB Instructions")
print("=" * 60)

addr_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

# Key STRB locations
strb_locations = [
    (0x013B20, "strbeq r0,[r4,#0x75]"),
    (0x013B24, "strbne r5,[r4,#0x75]"),
    (0x01DB6C, "strbeq r5,[r4,#0x64]"),
]

for addr_val, desc in strb_locations:
    print("\n" + "=" * 50)
    print("Analyzing: 0x{:06X} - {}".format(addr_val, desc))
    print("=" * 50)
    
    # Disassemble a range before this instruction
    start_addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val - 0x40)
    end_addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val + 0x10)
    
    # Force disassembly of the range
    cmd = DisassembleCommand(start_addr, None, True)
    cmd.applyTo(currentProgram)
    
    # Print instructions
    print("\nCode context:")
    addr = start_addr
    while addr.compareTo(end_addr) <= 0:
        inst = listing.getInstructionAt(addr)
        if inst:
            marker = " <-- TARGET" if addr.getOffset() == addr_val else ""
            # Look for key instructions
            inst_str = str(inst).lower()
            if 'mov' in inst_str and ('r0' in inst_str or 'r5' in inst_str):
                marker += " <-- MOV R0/R5"
            if 'ldr' in inst_str and ('r0' in inst_str or 'r5' in inst_str):
                marker += " <-- LDR R0/R5"
            if 'cmp' in inst_str or 'tst' in inst_str:
                marker += " <-- CMP/TST"
            print("  {}: {}{}".format(addr, inst, marker))
            addr = addr.add(inst.getLength())
        else:
            # Try to get undefined data
            data = listing.getDataAt(addr)
            if data:
                print("  {}: [data] {}".format(addr, data))
                addr = addr.add(data.getLength())
            else:
                addr = addr.add(4)

print("\n" + "=" * 60)
print("Analysis complete")
