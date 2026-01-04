# @category Analysis
# Deep context analysis of FPS-related STRB instructions

from ghidra.program.model.address import AddressFactory
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.listing import CodeUnit

print("=" * 60)
print("FPS STRB Context Analysis")
print("=" * 60)

addr_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
func_mgr = currentProgram.getFunctionManager()

# The key STRB addresses from previous analysis
key_addresses = [
    (0x013B20, "strbeq r0,[r4,#0x75]"),
    (0x013B24, "strbne r5,[r4,#0x75]"),
    (0x01DB6C, "strbeq r5,[r4,#0x64]"),
    (0x1028E4, "strb r6,[r0,#0x74]"),
    (0x15B0D4, "strb r5,[r4,#0x64]"),
    (0x184BE8, "strbeq r0,[r4,#0x64]"),
]

for addr_val, expected_inst in key_addresses:
    print("\n" + "=" * 60)
    print("Analyzing: 0x{:06X} - {}".format(addr_val, expected_inst))
    print("=" * 60)

    addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)

    # Check what function this belongs to
    func = func_mgr.getFunctionContaining(addr)
    if func:
        print("  In function: {} at 0x{:X}".format(func.getName(), func.getEntryPoint().getOffset()))
        print("  Function range: 0x{:X} - 0x{:X}".format(
            func.getBody().getMinAddress().getOffset(),
            func.getBody().getMaxAddress().getOffset()))
    else:
        print("  Not in any defined function")

        # Try to find nearby functions
        nearby_funcs = []
        for offset in range(-0x200, 0x200, 4):
            check_addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val + offset)
            f = func_mgr.getFunctionContaining(check_addr)
            if f and f not in nearby_funcs:
                nearby_funcs.append(f)

        if nearby_funcs:
            print("  Nearby functions:")
            for f in nearby_funcs[:5]:
                print("    {} at 0x{:X}".format(f.getName(), f.getEntryPoint().getOffset()))

    # Check the instruction at this address
    inst = listing.getInstructionAt(addr)
    if inst:
        print("\n  Instruction: {}".format(inst))
        print("  Length: {} bytes".format(inst.getLength()))
        print("  Is ARM: {}".format(inst.getLength() == 4))

        # Get references TO this address
        refs_to = currentProgram.getReferenceManager().getReferencesTo(addr)
        ref_count = 0
        for ref in refs_to:
            if ref_count < 5:
                print("  Referenced from: 0x{:X}".format(ref.getFromAddress().getOffset()))
            ref_count += 1
        if ref_count > 5:
            print("  ... and {} more references".format(ref_count - 5))

        # Get context: previous 16 instructions
        print("\n  Previous 16 instructions:")
        current = addr
        prev_insts = []
        for _ in range(32):  # Go back up to 32 slots
            current = current.subtract(2)  # Minimum instruction size
            if current.getOffset() < 0:
                break
            inst = listing.getInstructionAt(current)
            if inst:
                prev_insts.append((current.getOffset(), str(inst)))
                current = current.subtract(inst.getLength() - 2)  # Adjust for instruction length
                if len(prev_insts) >= 16:
                    break

        for inst_addr, inst_str in reversed(prev_insts[-16:]):
            marker = ""
            inst_lower = inst_str.lower()
            if 'mov' in inst_lower and ('#0x0' in inst_lower or '#0x1' in inst_lower or ', #0]' in inst_lower or ', #1]' in inst_lower):
                marker = " <-- MOV #0 or #1"
            elif 'cmp' in inst_lower or 'tst' in inst_lower:
                marker = " <-- CMP/TST"
            print("    0x{:06X}: {}{}".format(inst_addr, inst_str, marker))
    else:
        print("  No instruction at this address!")
        print("  Raw bytes: {:02X} {:02X} {:02X} {:02X}".format(
            currentProgram.getMemory().getByte(addr) & 0xFF,
            currentProgram.getMemory().getByte(addr.add(1)) & 0xFF,
            currentProgram.getMemory().getByte(addr.add(2)) & 0xFF,
            currentProgram.getMemory().getByte(addr.add(3)) & 0xFF))

print("\n" + "=" * 60)
print("Analysis complete")
print("=" * 60)
