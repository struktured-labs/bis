# GSP Frame Control Analysis
# @category Analysis

"""
Analyze GSP (GPU Service) related code to find frame timing control.
The GSP service controls screen refresh and frame buffer swapping.
"""

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

def find_gsp_functions():
    """Find functions that reference GSP strings"""
    results = []
    memory = currentProgram.getMemory()
    ref_mgr = currentProgram.getReferenceManager()
    func_mgr = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    listing = currentProgram.getListing()

    # Find gsp string
    gsp_addr = memory.findBytes(currentProgram.getMinAddress(), b"gsp", None, True, monitor)

    if gsp_addr:
        print("GSP string at: %s" % gsp_addr)

        # Look for references to nearby addresses
        for offset in range(-16, 16):
            check_addr = gsp_addr.add(offset)
            refs = ref_mgr.getReferencesTo(check_addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                if func:
                    results.append((str(func.getEntryPoint()), func.getName(), str(from_addr)))

    return results

def analyze_function_decompiled(func_addr_str):
    """Get decompiled view of a function"""
    try:
        func_mgr = currentProgram.getFunctionManager()
        addr = currentProgram.getAddressFactory().getAddress(func_addr_str)
        func = func_mgr.getFunctionAt(addr)

        if func:
            decomp = DecompInterface()
            decomp.openProgram(currentProgram)
            result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
            if result and result.decompileCompleted():
                return result.getDecompiledFunction().getC()
    except Exception as e:
        return "Decompile error: %s" % str(e)
    return None

def find_frame_wait_patterns():
    """Find patterns that might be frame wait/sync calls"""
    results = []
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()

    # Look for SVC (supervisor call) instructions - used for OS services
    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()
        if 'svc' in mnem or 'swi' in mnem:
            func = func_mgr.getFunctionContaining(instr.getAddress())
            func_name = func.getName() if func else "unknown"
            results.append((str(instr.getAddress()), instr.toString(), func_name))
            if len(results) > 50:
                break

    return results

def find_cmp_1_patterns():
    """Find CMP Rx, #1 patterns which might be FPS flag checks"""
    results = []
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()

    for instr in listing.getInstructions(True):
        mnem = instr.getMnemonicString().lower()
        if 'cmp' in mnem:
            instr_str = instr.toString()
            if '#0x1' in instr_str or ', #1' in instr_str:
                # Check next instruction for branch
                next_instr = instr.getNext()
                if next_instr and 'b' in next_instr.getMnemonicString().lower():
                    func = func_mgr.getFunctionContaining(instr.getAddress())
                    func_name = func.getName() if func else "unknown"
                    results.append((str(instr.getAddress()),
                                   instr.toString() + " ; " + next_instr.toString(),
                                   func_name))
        if len(results) > 100:
            break

    return results

def analyze_function_at_0xDA3AC():
    """Analyze the function containing offset 0xDA3AC if any"""
    base = currentProgram.getMinAddress()
    target = base.add(0xDA3AC)

    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(target)

    if func:
        return (str(func.getEntryPoint()), func.getName(),
                analyze_function_decompiled(str(func.getEntryPoint())))
    return None

def find_double_stores():
    """Find patterns where same value is stored to multiple nearby addresses"""
    results = []
    listing = currentProgram.getListing()

    prev_instr = None
    for instr in listing.getInstructions(True):
        if prev_instr:
            mnem = instr.getMnemonicString().lower()
            prev_mnem = prev_instr.getMnemonicString().lower()

            if 'str' in mnem and 'str' in prev_mnem:
                # Two consecutive stores - might be setting multiple flags
                results.append((str(prev_instr.getAddress()),
                               prev_instr.toString() + " ; " + instr.toString()))
        prev_instr = instr
        if len(results) > 50:
            break

    return results

def main():
    print("="*70)
    print("GSP Frame Control Analysis - Mario & Luigi BIS+BJJ")
    print("="*70)

    report = []
    report.append("GSP Frame Control Analysis Report")
    report.append("="*70)

    # 1. Find GSP-related functions
    print("\n[1] Finding functions that reference GSP...")
    gsp_funcs = find_gsp_functions()
    report.append("\n=== GSP-related functions ===")
    for entry, name, ref_from in gsp_funcs:
        line = "%s: %s (ref from %s)" % (entry, name, ref_from)
        report.append(line)
        print("  " + line)

    # 2. Find SVC patterns
    print("\n[2] Finding SVC (system call) instructions...")
    svc_results = find_frame_wait_patterns()
    report.append("\n=== SVC instructions (first 30) ===")
    for addr, instr, func in svc_results[:30]:
        line = "%s: %s [%s]" % (addr, instr, func)
        report.append(line)
        print("  " + line)

    # 3. Find CMP #1 patterns
    print("\n[3] Finding CMP #1 -> Branch patterns...")
    cmp_results = find_cmp_1_patterns()
    report.append("\n=== CMP #1 patterns (first 50) ===")
    for addr, pattern, func in cmp_results[:50]:
        line = "%s: %s [%s]" % (addr, pattern, func)
        report.append(line)
        print("  " + line)

    # 4. Check function at 0xDA3AC
    print("\n[4] Analyzing code at 0xDA3AC...")
    da3ac = analyze_function_at_0xDA3AC()
    report.append("\n=== Function at 0xDA3AC ===")
    if da3ac:
        entry, name, decomp = da3ac
        report.append("Entry: %s, Name: %s" % (entry, name))
        print("  Entry: %s, Name: %s" % (entry, name))
        if decomp:
            report.append("Decompiled:")
            report.append(decomp[:2000] if len(decomp) > 2000 else decomp)
            print("  Decompiled (truncated):")
            print(decomp[:500] if len(decomp) > 500 else decomp)
    else:
        report.append("No function at 0xDA3AC")
        print("  No function at 0xDA3AC")

    # 5. Decompile first GSP function if found
    if gsp_funcs:
        print("\n[5] Decompiling first GSP-related function...")
        entry, name, _ = gsp_funcs[0]
        decomp = analyze_function_decompiled(entry)
        report.append("\n=== Decompiled GSP function: %s ===" % name)
        if decomp:
            report.append(decomp[:3000] if len(decomp) > 3000 else decomp)
            print(decomp[:800] if len(decomp) > 800 else decomp)

    # Write report
    output = "/workspace/build/gsp_frame_report.txt"
    with open(output, 'w') as f:
        f.write('\n'.join(report))

    print("\n" + "="*70)
    print("Report saved to: " + output)
    print("="*70)

if __name__ == "__main__":
    main()
