# Minimal FPS address finder - outputs only key findings
# @category Analysis

"""
Find FPS control code. The cheat uses:
- Base: 0x30000000 (code region)
- Key addresses: 0x74/75, 0x64/65, 0x44/45, 0xDA3AC/AD
- Value 0x00 = 60fps, 0x01 = 30fps
"""

from ghidra.util.task import ConsoleTaskMonitor

def main():
    listing = currentProgram.getListing()

    # Target offsets from cheat codes
    targets = [0xDA3AC, 0x74, 0x64, 0x44]

    print("="*60)
    print("FPS Address Analysis - Mario & Luigi BIS+BJJ")
    print("="*60)

    results = []

    # Analyze code at 0xDA3AC (primary FPS control)
    base = currentProgram.getMinAddress()
    primary_addr = base.add(0xDA3AC)

    print("\n[1] Code at 0xDA3AC region:")
    for i in range(-16, 32, 4):
        addr = base.add(0xDA3AC + i)
        instr = listing.getInstructionAt(addr)
        if instr:
            results.append((str(addr), instr.toString()))
            print("  %s: %s" % (addr, instr))

    # Find functions containing these instructions
    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(primary_addr)
    if func:
        print("\n[2] Function containing 0xDA3AC:")
        print("  Name: %s" % func.getName())
        print("  Entry: %s" % func.getEntryPoint())
        print("  Size: %d bytes" % func.getBody().getNumAddresses())

        # Print first 20 instructions of the function
        print("\n  Function code (first 30 instrs):")
        entry = func.getEntryPoint()
        instr = listing.getInstructionAt(entry)
        count = 0
        while instr and count < 30:
            print("    %s: %s" % (instr.getAddress(), instr))
            instr = instr.getNext()
            count += 1

    # Search for patterns that write byte 1 near these offsets
    print("\n[3] Looking for MOV #1 patterns near target offsets...")

    for target in targets:
        addr = base.add(target)
        for i in range(-32, 32, 2):
            try:
                check_addr = base.add(target + i)
                instr = listing.getInstructionAt(check_addr)
                if instr:
                    instr_str = str(instr).lower()
                    if '#0x1' in instr_str or '#1' in instr_str:
                        print("  0x%x+%d: %s: %s" % (target, i, check_addr, instr))
            except:
                pass

    # Find references to address 0xDA3AC
    print("\n[4] Finding references to 0xDA3AC...")
    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(primary_addr)
    for ref in refs:
        print("  From: %s" % ref.getFromAddress())

    # Save summary
    output = "/workspace/build/fps_findings.txt"
    with open(output, 'w') as f:
        f.write("FPS Control Address Analysis\n")
        f.write("="*60 + "\n")
        f.write("Primary control at offset 0xDA3AC\n")
        f.write("Low offsets: 0x44, 0x64, 0x74\n\n")
        for addr, instr in results:
            f.write("%s: %s\n" % (addr, instr))

    print("\n[*] Saved to %s" % output)
    print("="*60)

if __name__ == "__main__":
    main()
