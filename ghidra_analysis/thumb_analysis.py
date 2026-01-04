# @category Analysis  
# Force Thumb mode disassembly at key locations

from ghidra.program.model.address import AddressFactory
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.disassemble import Disassembler
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

print("=" * 60)
print("Thumb Mode Analysis")
print("=" * 60)

addr_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()

# Get the TMode register for setting Thumb mode
language = currentProgram.getLanguage()
tmode_reg = language.getRegister("TMode")

# Key locations to analyze (as Thumb)
thumb_locations = [
    0x013B00,  # Before first STRB
    0x01DB40,  # Before second STRB  
    0x040D00,  # Near SVC location
]

for addr_val in thumb_locations:
    print("\n--- Attempting Thumb disassembly at 0x{:06X} ---".format(addr_val))
    
    addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)
    end_addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val + 0x60)
    
    # Try to set Thumb mode and disassemble
    if tmode_reg:
        # Create a context with TMode=1 (Thumb)
        context = currentProgram.getProgramContext()
        try:
            thumb_value = RegisterValue(tmode_reg, BigInteger.ONE)
            context.setRegisterValue(addr, end_addr, thumb_value)
            print("  Set TMode=1 for range")
        except Exception as e:
            print("  Could not set TMode: {}".format(e))
    
    # Clear existing instructions
    listing.clearCodeUnits(addr, end_addr, False)
    
    # Disassemble in Thumb mode
    disassembler = Disassembler.getDisassembler(currentProgram, monitor, None)
    result = disassembler.disassemble(addr, None, True)
    print("  Disassembled {} instructions".format(result.getNumAddressesDisassembled()))
    
    # Print the disassembly
    print("\n  Code:")
    current = addr
    while current.compareTo(end_addr) <= 0:
        inst = listing.getInstructionAt(current)
        if inst:
            marker = ""
            inst_str = str(inst).lower()
            if 'strb' in inst_str:
                marker = " <-- STRB"
            elif 'ldrb' in inst_str:
                marker = " <-- LDRB"
            elif 'cmp' in inst_str or 'tst' in inst_str:
                marker = " <-- CMP/TST"
            elif 'mov' in inst_str and ('#0x0' in inst_str or '#0x1' in inst_str or ', #0]' in inst_str or ', #1]' in inst_str):
                marker = " <-- MOV #0 or #1"
            print("    {}: {}{}".format(current, inst, marker))
            current = current.add(inst.getLength())
        else:
            # Skip undefined
            current = current.add(2)

print("\n" + "=" * 60)
