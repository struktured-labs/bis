# Targeted FPS analysis at specific addresses
# @category Analysis

"""
Analyze specific addresses known to contain FPS control STRB instructions.
Find the preceding MOV instructions that load the value.
"""

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

def set_thumb_mode(addr):
    """Set Thumb mode for an address"""
    try:
        tmode = currentProgram.getRegister("TMode")
        if tmode:
            val = RegisterValue(tmode, BigInteger.ONE)
            currentProgram.getProgramContext().setRegisterValue(addr, addr, val)
    except:
        pass

def disassemble_region(offset, length=64):
    """Force Thumb mode disassembly of a region"""
    base = currentProgram.getMinAddress()
    start = base.add(offset)
    end = base.add(offset + length)

    # Set Thumb mode for entire region
    for i in range(0, length, 2):
        set_thumb_mode(base.add(offset + i))

    addr_set = AddressSet(start, end)
    cmd = DisassembleCommand(addr_set, None, True)
    cmd.applyTo(currentProgram, ConsoleTaskMonitor())

def get_disasm_at(offset, context=32):
    """Get disassembly around an offset"""
    base = currentProgram.getMinAddress()
    listing = currentProgram.getListing()

    # Disassemble the region
    disassemble_region(offset - context, context * 3)

    results = []
    addr = base.add(offset - context)
    end = base.add(offset + context)

    while addr.compareTo(end) < 0:
        instr = listing.getInstructionAt(addr)
        if instr:
            file_offset = addr.getOffset() - base.getOffset()
            is_target = (file_offset == offset)

            # Get raw bytes
            raw_bytes = []
            for i in range(instr.getLength()):
                b = currentProgram.getMemory().getByte(addr.add(i)) & 0xFF
                raw_bytes.append("%02x" % b)

            results.append({
                'offset': file_offset,
                'instr': instr.toString(),
                'bytes': ' '.join(raw_bytes),
                'is_target': is_target,
                'mnemonic': instr.getMnemonicString()
            })
            addr = instr.getNext().getAddress() if instr.getNext() else addr.add(2)
        else:
            addr = addr.add(2)

    return results

def find_mov_before_strb(disasm_list, target_offset):
    """Find MOV #1 instruction before a STRB target"""
    mov_candidates = []

    for i, item in enumerate(disasm_list):
        if item['offset'] == target_offset:
            # Look backwards for MOV
            for j in range(i-1, max(0, i-10), -1):
                prev = disasm_list[j]
                mnem = prev['mnemonic'].lower()
                instr_str = prev['instr'].lower()

                if 'mov' in mnem and '#0x1' in instr_str:
                    mov_candidates.append(prev)
                    break

    return mov_candidates

def main():
    print("=" * 70)
    print("TARGETED FPS PATCH ANALYSIS")
    print("=" * 70)

    # Known STRB locations from previous analysis
    targets = [
        (0x013B20, "STRB to #0x75"),
        (0x013B24, "STRB to #0x75 (adjacent)"),
        (0x01C900, "STRB to #0x74"),
        (0x01DB6C, "STRB to #0x64"),
    ]

    report = []
    patch_points = []

    for offset, desc in targets:
        print("\n" + "=" * 70)
        print("Analyzing 0x%06X: %s" % (offset, desc))
        print("=" * 70)

        report.append("\n=== 0x%06X: %s ===" % (offset, desc))

        disasm = get_disasm_at(offset, 24)

        for item in disasm:
            marker = " <<<TARGET" if item['is_target'] else ""
            line = "0x%06X: [%s] %s%s" % (item['offset'], item['bytes'], item['instr'], marker)
            print(line)
            report.append(line)

            # Check if this is a MOV #1 near our target
            if 'mov' in item['mnemonic'].lower():
                instr_str = item['instr'].lower()
                if '#0x1' in instr_str or '#1' in instr_str:
                    # Check if within 10 instructions of target
                    if abs(item['offset'] - offset) < 20:
                        patch_info = {
                            'offset': item['offset'],
                            'bytes': item['bytes'],
                            'instr': item['instr'],
                            'near_target': desc
                        }
                        patch_points.append(patch_info)
                        print("  ^^^ POTENTIAL PATCH POINT: Change #1 to #0")

    # Summary
    print("\n" + "=" * 70)
    print("PATCH POINT CANDIDATES")
    print("=" * 70)
    report.append("\n\n=== PATCH POINT CANDIDATES ===")

    for pp in patch_points:
        line = "0x%06X: [%s] %s (near %s)" % (pp['offset'], pp['bytes'], pp['instr'], pp['near_target'])
        print(line)
        report.append(line)

        # Determine patch byte
        bytes_list = pp['bytes'].split()
        if len(bytes_list) >= 1 and bytes_list[0] == '01':
            print("  -> PATCH: Change byte at 0x%06X from 0x01 to 0x00" % pp['offset'])
            report.append("  -> PATCH: Change byte at 0x%06X from 0x01 to 0x00" % pp['offset'])

    # Write report
    output = "/workspace/build/targeted_fps_report.txt"
    with open(output, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "=" * 70)
    print("Report saved to: " + output)
    print("=" * 70)

if __name__ == "__main__":
    main()
