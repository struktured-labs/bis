# @category Analysis
# Find FPS control patterns in Mario & Luigi BIS

from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI

api = FlatProgramAPI(currentProgram)
listing = currentProgram.getListing()

print("=" * 60)
print("FPS Control Analysis for Mario & Luigi BIS")
print("=" * 60)

# Search for instructions with specific offsets
target_offsets = [0x44, 0x45, 0x64, 0x65, 0x74, 0x75]

# Iterate through all instructions
inst_iter = listing.getInstructions(True)
results = {'strb': [], 'ldrb': []}

count = 0
while inst_iter.hasNext():
    inst = inst_iter.next()
    count += 1
    
    mnemonic = inst.getMnemonicString().lower()
    inst_str = str(inst).lower()
    
    # Check for STRB/LDRB with target offsets
    if 'strb' in mnemonic or 'ldrb' in mnemonic:
        for offset in target_offsets:
            hex_off = "#0x{:x}".format(offset)
            dec_off = "#{}".format(offset)
            if hex_off in inst_str or dec_off + "]" in inst_str or dec_off + "!" in inst_str:
                key = 'strb' if 'strb' in mnemonic else 'ldrb'
                results[key].append({
                    'addr': inst.getAddress(),
                    'inst': str(inst),
                    'offset': offset
                })
                break

print("\nTotal instructions analyzed: {}".format(count))

print("\n--- STRB instructions with target offsets ---")
for r in results['strb']:
    print("  {}: {} (offset 0x{:x})".format(r['addr'], r['inst'], r['offset']))

print("\n--- LDRB instructions with target offsets ---")  
for r in results['ldrb']:
    print("  {}: {} (offset 0x{:x})".format(r['addr'], r['inst'], r['offset']))

# Look for patterns like CMP followed by branch
print("\n--- Looking for decision patterns ---")
inst_iter = listing.getInstructions(True)
while inst_iter.hasNext():
    inst = inst_iter.next()
    mnemonic = inst.getMnemonicString().lower()
    
    if 'cmp' in mnemonic:
        inst_str = str(inst).lower()
        # Check if comparing with #1 or #2
        if '#0x1]' in inst_str or '#1]' in inst_str or ', #0x1' in inst_str or ', #1' in inst_str or ', #0x2' in inst_str or ', #2' in inst_str:
            # Get next instruction
            next_addr = inst.getAddress().add(inst.getLength())
            next_inst = listing.getInstructionAt(next_addr)
            if next_inst:
                next_mn = next_inst.getMnemonicString().lower()
                if next_mn.startswith('b'):  # Branch instruction
                    print("  {}: {} -> {}: {}".format(inst.getAddress(), str(inst), next_addr, str(next_inst)))

print("\n" + "=" * 60)
print("Analysis complete")
