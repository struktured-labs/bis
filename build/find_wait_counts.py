#!/usr/bin/env python3
"""
Find Potential Wait Count Values

30 FPS: Wait for 2 VBlanks per frame
60 FPS: Wait for 1 VBlank per frame

Search for:
- MOVS rX, #2 followed by loop/wait
- MOVS rX, #1 followed by loop/wait
- Variables initialized to 2 that control timing
"""

import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CsError

def find_wait_counts():
    code_path = Path("build/extracted/exefs_dir/code.bin")
    with open(code_path, "rb") as f:
        code_data = f.read()

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    results = {
        "movs_2": [],  # MOVS rX, #2
        "movs_1": [],  # MOVS rX, #1
        "candidates": []
    }

    print("Scanning for wait count patterns...")
    print()

    prev_instructions = []

    for inst in md.disasm(code_data, 0):
        # Keep window of previous instructions
        prev_instructions.append({
            "offset": inst.address,
            "mnemonic": inst.mnemonic,
            "op_str": inst.op_str,
            "bytes": inst.bytes.hex()
        })
        if len(prev_instructions) > 10:
            prev_instructions.pop(0)

        # Look for MOVS rX, #1 or #2
        try:
            if inst.mnemonic.lower() == "movs":
                for op in inst.operands:
                    if op.type == 2:  # IMM
                        if op.imm == 2:
                            # Check if followed by loop/wait/svc within next 10 instructions
                            record = {
                                "offset": inst.address,
                                "instruction": f"{inst.mnemonic} {inst.op_str}",
                                "bytes": inst.bytes.hex(),
                                "context_before": list(prev_instructions[-5:-1]),
                                "priority": "UNKNOWN"
                            }

                            # Check for nearby SVC, branch, or loop
                            # This is a simplified heuristic
                            has_nearby_control = any(
                                prev["mnemonic"] in ["svc", "b", "beq", "bne", "bl", "cmp"]
                                for prev in prev_instructions[-5:]
                            )

                            if has_nearby_control:
                                record["priority"] = "HIGH"
                                record["reason"] = "MOVS #2 near control flow"
                            else:
                                record["priority"] = "MEDIUM"
                                record["reason"] = "MOVS #2"

                            results["movs_2"].append(record)
                            results["candidates"].append(record)

                        elif op.imm == 1:
                            record = {
                                "offset": inst.address,
                                "instruction": f"{inst.mnemonic} {inst.op_str}",
                                "bytes": inst.bytes.hex(),
                                "priority": "LOW",
                                "reason": "MOVS #1 (for reference)"
                            }
                            results["movs_1"].append(record)

        except (CsError, IndexError):
            pass

    print("=" * 70)
    print("  Wait Count Analysis")
    print("=" * 70)
    print()
    print(f"MOVS rX, #2 found: {len(results['movs_2'])}")
    print(f"MOVS rX, #1 found: {len(results['movs_1'])}")
    print()

    # Show HIGH priority candidates
    high_pri = [c for c in results["movs_2"] if c.get("priority") == "HIGH"]
    print(f"HIGH priority (MOVS #2 near control flow): {len(high_pri)}")
    print()

    if high_pri:
        print("TOP 20 HIGH PRIORITY CANDIDATES:")
        print("-" * 70)
        for i, rec in enumerate(high_pri[:20], 1):
            print(f"{i}. Offset 0x{rec['offset']:06X}: {rec['instruction']}")
            print(f"   Reason: {rec['reason']}")
            if rec.get("context_before"):
                print("   Context:")
                for ctx in rec["context_before"][-3:]:
                    print(f"     0x{ctx['offset']:06X}: {ctx['mnemonic']:8s} {ctx['op_str']}")
            print()

    # Save results
    output_path = Path("tmp/wait_count_analysis.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Full results saved to: {output_path}")
    print()

    return results

if __name__ == "__main__":
    results = find_wait_counts()

    if results:
        print("Next: Generate test ROMs that change MOVS #2 to MOVS #1")
