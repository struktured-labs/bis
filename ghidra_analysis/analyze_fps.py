# Ghidra script to analyze FPS control in Mario & Luigi BIS
# @category Analysis

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
import java

def find_strb_with_offset(program, offset):
    """Find STRB instructions with specific offset"""
    listing = program.getListing()
    memory = program.getMemory()
    results = []
    
    # Get all instructions
    inst_iter = listing.getInstructions(True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnemonic = inst.getMnemonicString().lower()
        
        if 'strb' in mnemonic:
            # Check operands for the offset
            ops_str = str(inst)
            if f'#0x{offset:x}' in ops_str.lower() or f'#{offset}' in ops_str:
                results.append({
                    'address': inst.getAddress(),
                    'instruction': str(inst),
                    'mnemonic': mnemonic
                })
    
    return results

def find_ldrb_with_offset(program, offset):
    """Find LDRB instructions with specific offset"""
    listing = program.getListing()
    results = []
    
    inst_iter = listing.getInstructions(True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnemonic = inst.getMnemonicString().lower()
        
        if 'ldrb' in mnemonic:
            ops_str = str(inst)
            if f'#0x{offset:x}' in ops_str.lower() or f'#{offset}' in ops_str:
                results.append({
                    'address': inst.getAddress(),
                    'instruction': str(inst),
                    'mnemonic': mnemonic
                })
    
    return results

def analyze_refs_to_address(program, addr):
    """Analyze all references to a specific address"""
    ref_mgr = program.getReferenceManager()
    refs = ref_mgr.getReferencesTo(addr)
    results = []
    for ref in refs:
        results.append({
            'from': ref.getFromAddress(),
            'type': ref.getReferenceType()
        })
    return results

# Main analysis
print("=" * 60)
print("FPS Control Analysis for Mario & Luigi BIS")
print("=" * 60)

# Target offsets from CTRPF cheat
target_offsets = [0x44, 0x45, 0x64, 0x65, 0x74, 0x75]

for offset in target_offsets:
    print(f"\n--- Offset 0x{offset:02X} ---")
    
    print("STRB instructions:")
    strb_results = find_strb_with_offset(currentProgram, offset)
    for r in strb_results[:10]:
        print(f"  {r['address']}: {r['instruction']}")
    
    print("LDRB instructions:")
    ldrb_results = find_ldrb_with_offset(currentProgram, offset)
    for r in ldrb_results[:10]:
        print(f"  {r['address']}: {r['instruction']}")

print("\n" + "=" * 60)
print("Analysis complete")
