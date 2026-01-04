# @category Analysis
# Force disassembly at known code locations

from ghidra.program.model.address import AddressFactory
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.listing import CodeUnit

print("=" * 60)
print("Force Disassembly Analysis")
print("=" * 60)

addr_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

# Known code locations (STRB instructions we found earlier)
code_addresses = [
    0x013B20, 0x013B24, 0x01DB6C, 0x184BE8, 0x15B0D4, 0x1028E4,  # STRB to FPS offsets
    0x040D2E, 0x0E5398, 0x14DB7A, 0x19ADE7, 0x1A8E0A, 0x1BE5DD,  # SVC #0x25 locations
]

# Disassemble at each location
for addr_val in code_addresses:
    addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)
    
    # Check if already disassembled
    inst = listing.getInstructionAt(addr)
    if inst is None:
        # Force disassembly
        cmd = DisassembleCommand(addr, None, True)
        cmd.applyTo(currentProgram)
        print("Disassembled at 0x{:06X}".format(addr_val))
    else:
        print("Already disassembled at 0x{:06X}: {}".format(addr_val, inst))

# Now search for patterns
print("\n--- Searching for FPS-related patterns ---")
target_offsets = [0x44, 0x45, 0x64, 0x65, 0x74, 0x75]

# Get all instructions
inst_iter = listing.getInstructions(True)
results = {'strb': [], 'ldrb': [], 'cmp': []}

while inst_iter.hasNext():
    inst = inst_iter.next()
    mnemonic = inst.getMnemonicString().lower()
    inst_str = str(inst).lower()
    
    # Check for STRB/LDRB with target offsets
    for key in ['strb', 'ldrb']:
        if key in mnemonic:
            for offset in target_offsets:
                hex_off = "#0x{:x}".format(offset)
                if hex_off in inst_str:
                    results[key].append({
                        'addr': inst.getAddress(),
                        'inst': str(inst),
                        'offset': offset
                    })
                    break
    
    # Look for CMP #1 or CMP #2
    if 'cmp' in mnemonic and ('#0x1' in inst_str or '#0x2' in inst_str or ', #1' in inst_str or ', #2' in inst_str):
        results['cmp'].append({
            'addr': inst.getAddress(),
            'inst': str(inst)
        })

print("\nSTRB with FPS offsets: {}".format(len(results['strb'])))
for r in results['strb'][:20]:
    print("  {}: {}".format(r['addr'], r['inst']))

print("\nLDRB with FPS offsets: {}".format(len(results['ldrb'])))
for r in results['ldrb'][:20]:
    print("  {}: {}".format(r['addr'], r['inst']))

print("\nCMP #1 or #2: {}".format(len(results['cmp'])))
for r in results['cmp'][:20]:
    print("  {}: {}".format(r['addr'], r['inst']))

print("\n" + "=" * 60)
