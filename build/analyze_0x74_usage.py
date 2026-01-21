#!/usr/bin/env python3
"""
Analyze 0x74 Immediate Value Usage
Similar to 0x75 analysis, but for the CTRPF conditional check byte

CTRPF cheat checks: if [0x74] == 0x01
This might be the REAL FPS control byte
"""

import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CsError

def analyze_0x74_usage():
    # Load code.bin
    code_path = Path("build/extracted/exefs_dir/code.bin")
    if not code_path.exists():
        print("ERROR: code.bin not found")
        print(f"Looked in: {code_path}")
        return

    with open(code_path, "rb") as f:
        code_data = f.read()

    # Setup disassembler
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    results = {
        "total_instructions": 0,
        "uses_0x74": [],
        "high_priority": [],
        "medium_priority": [],
        "low_priority": []
    }

    print("Scanning for 0x74 immediate value usage...")
    print(f"Code size: {len(code_data)} bytes")
    print()

    # Scan all instructions
    for inst in md.disasm(code_data, 0):
        results["total_instructions"] += 1

        # Check if instruction uses immediate 0x74 (116 decimal)
        try:
            has_0x74 = False
            for op in inst.operands:
                if op.type == 2:  # IMM type
                    if op.imm == 0x74 or op.imm == 116:
                        has_0x74 = True
                        break

            if not has_0x74:
                continue

            # Found 0x74 usage
            record = {
                "offset": inst.address,
                "mnemonic": inst.mnemonic,
                "op_str": inst.op_str,
                "bytes": inst.bytes.hex(),
                "priority": "UNKNOWN"
            }

            # Analyze context to determine priority
            # HIGH: Instructions that load/compare/branch on 0x74
            # MEDIUM: Move/add to register used in next few instructions
            # LOW: Unrelated use of value 116

            mnem = inst.mnemonic.lower()

            # HIGH PRIORITY: Loads from memory with 0x74 offset
            if 'ldr' in mnem or 'str' in mnem:
                record["priority"] = "HIGH"
                record["reason"] = "Memory access with 0x74 offset - likely struct field"
                results["high_priority"].append(record)

            # HIGH PRIORITY: Compare with 0x74
            elif 'cmp' in mnem or 'tst' in mnem:
                record["priority"] = "HIGH"
                record["reason"] = "Comparison with 0x74 - possible FPS check"
                results["high_priority"].append(record)

            # MEDIUM PRIORITY: Move/add 0x74 to register
            elif 'mov' in mnem or 'add' in mnem:
                record["priority"] = "MEDIUM"
                record["reason"] = "Move/add 0x74 to register - check surrounding code"
                results["medium_priority"].append(record)

            # LOW PRIORITY: Other uses
            else:
                record["priority"] = "LOW"
                record["reason"] = f"Other use in {mnem}"
                results["low_priority"].append(record)

            results["uses_0x74"].append(record)

        except CsError:
            continue

    # Save results
    output_path = Path("tmp/0x74_analysis.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary
    print("=" * 70)
    print("  0x74 Immediate Value Analysis")
    print("=" * 70)
    print()
    print(f"Total instructions scanned: {results['total_instructions']:,}")
    print(f"Instructions using 0x74: {len(results['uses_0x74'])}")
    print()
    print(f"HIGH priority candidates: {len(results['high_priority'])}")
    print(f"MEDIUM priority candidates: {len(results['medium_priority'])}")
    print(f"LOW priority candidates: {len(results['low_priority'])}")
    print()

    # Show top HIGH priority candidates
    print("TOP 10 HIGH PRIORITY CANDIDATES:")
    print("-" * 70)
    for i, rec in enumerate(results["high_priority"][:10], 1):
        print(f"{i}. Offset 0x{rec['offset']:06X}: {rec['mnemonic']} {rec['op_str']}")
        print(f"   Reason: {rec['reason']}")
        print()

    # Show some MEDIUM priority
    if results["medium_priority"]:
        print("TOP 5 MEDIUM PRIORITY CANDIDATES:")
        print("-" * 70)
        for i, rec in enumerate(results["medium_priority"][:5], 1):
            print(f"{i}. Offset 0x{rec['offset']:06X}: {rec['mnemonic']} {rec['op_str']}")
            print(f"   Reason: {rec['reason']}")
            print()

    print(f"Full results saved to: {output_path}")
    print()

    # Return top candidates for ROM generation
    top_candidates = results["high_priority"][:15]
    if len(top_candidates) < 15:
        top_candidates.extend(results["medium_priority"][:15-len(top_candidates)])

    return top_candidates

if __name__ == "__main__":
    candidates = analyze_0x74_usage()

    if candidates:
        print(f"Identified {len(candidates)} top candidates for testing")
        print("Ready to generate test ROMs")
