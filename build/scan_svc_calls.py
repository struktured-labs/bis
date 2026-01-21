#!/usr/bin/env python3
"""
Scan for SVC (Supervisor Call) Instructions - VBlank/GSP Analysis

3DS games control frame rate via VBlank synchronization:
- 30 FPS: Wait for 2 VBlanks per frame
- 60 FPS: Wait for 1 VBlank per frame

Key SVC calls:
- SVC 0x25: svcWaitSynchronization (used for gspWaitForVBlank)
- SVC 0x24: svcWaitSynchronizationN
- SVC 0x17: svcCreateEvent
- SVC 0x2E: svcGetSystemTick

Strategy: Find VBlank wait loops and patch wait count or NOP them out
"""

import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CsError
from capstone.arm import *

def analyze_svc_calls():
    # Load code.bin
    code_path = Path("build/extracted/exefs_dir/code.bin")
    if not code_path.exists():
        print(f"ERROR: code.bin not found at {code_path}")
        return

    with open(code_path, "rb") as f:
        code_data = f.read()

    # Setup disassembler
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    results = {
        "total_instructions": 0,
        "total_svc": 0,
        "svc_by_number": {},
        "vblank_candidates": [],
        "interesting_patterns": []
    }

    print("Scanning for SVC calls...")
    print(f"Code size: {len(code_data)} bytes")
    print()

    # Scan all instructions
    prev_instructions = []  # Track previous 10 instructions for context
    svc_contexts = []

    for inst in md.disasm(code_data, 0):
        results["total_instructions"] += 1

        # Keep sliding window of previous instructions
        prev_instructions.append({
            "offset": inst.address,
            "mnemonic": inst.mnemonic,
            "op_str": inst.op_str,
            "bytes": inst.bytes.hex()
        })
        if len(prev_instructions) > 10:
            prev_instructions.pop(0)

        # Check for SVC instruction
        if inst.mnemonic.lower() == "svc":
            results["total_svc"] += 1

            try:
                # Get SVC number
                svc_num = inst.operands[0].imm if inst.operands else None

                if svc_num is not None:
                    # Track by SVC number
                    svc_key = f"0x{svc_num:02X}"
                    if svc_key not in results["svc_by_number"]:
                        results["svc_by_number"][svc_key] = []

                    record = {
                        "offset": inst.address,
                        "svc_number": svc_num,
                        "hex": svc_key,
                        "bytes": inst.bytes.hex(),
                        "context_before": list(prev_instructions[-5:-1])  # 4 instructions before
                    }

                    results["svc_by_number"][svc_key].append(record)

                    # Identify VBlank-related SVC calls
                    # SVC 0x25 = svcWaitSynchronization (most likely for VBlank)
                    # SVC 0x24 = svcWaitSynchronizationN
                    if svc_num in [0x24, 0x25]:
                        # Analyze context to see if it's in a loop
                        is_in_loop = any(
                            prev["mnemonic"] in ["b", "beq", "bne", "blt", "bgt", "ble", "bge"]
                            for prev in prev_instructions[-5:]
                        )

                        # Check for immediate values 1 or 2 (VBlank count) in context
                        has_count_value = any(
                            "#1" in prev["op_str"] or "#2" in prev["op_str"]
                            for prev in prev_instructions[-5:]
                        )

                        priority = "HIGH" if (is_in_loop and has_count_value) else "MEDIUM"

                        candidate = {
                            "offset": inst.address,
                            "svc_number": svc_num,
                            "svc_name": "svcWaitSynchronization" if svc_num == 0x25 else "svcWaitSynchronizationN",
                            "priority": priority,
                            "in_loop": is_in_loop,
                            "has_count": has_count_value,
                            "context": list(prev_instructions[-5:])
                        }

                        results["vblank_candidates"].append(candidate)

            except (CsError, IndexError):
                pass

    # Analyze patterns
    print("=" * 70)
    print("  SVC Call Analysis - VBlank/Frame Timing")
    print("=" * 70)
    print()
    print(f"Total instructions scanned: {results['total_instructions']:,}")
    print(f"Total SVC calls found: {results['total_svc']}")
    print()

    print("SVC Calls by Number:")
    print("-" * 70)
    for svc_key in sorted(results["svc_by_number"].keys()):
        count = len(results["svc_by_number"][svc_key])
        svc_num = int(svc_key, 16)

        # Known SVC names
        svc_names = {
            0x24: "svcWaitSynchronizationN",
            0x25: "svcWaitSynchronization",
            0x17: "svcCreateEvent",
            0x2E: "svcGetSystemTick",
            0x01: "svcControlMemory",
            0x02: "svcQueryMemory",
            0x03: "svcExitProcess",
            0x08: "svcCreateThread",
            0x09: "svcExitThread",
        }

        name = svc_names.get(svc_num, "unknown")
        print(f"  {svc_key} ({name:25s}): {count:4d} calls")

    print()
    print(f"VBlank candidates found: {len(results['vblank_candidates'])}")
    print()

    # Show HIGH priority VBlank candidates
    high_pri = [c for c in results["vblank_candidates"] if c["priority"] == "HIGH"]
    if high_pri:
        print("HIGH PRIORITY VBlank Candidates (in loop + has count):")
        print("-" * 70)
        for i, cand in enumerate(high_pri[:10], 1):
            print(f"{i}. Offset 0x{cand['offset']:06X}: {cand['svc_name']}")
            print(f"   In loop: {cand['in_loop']}, Has count: {cand['has_count']}")
            print(f"   Context (last 5 instructions):")
            for ctx in cand["context"][-5:]:
                print(f"     0x{ctx['offset']:06X}: {ctx['mnemonic']:8s} {ctx['op_str']}")
            print()

    # Show MEDIUM priority if no HIGH
    if not high_pri:
        med_pri = [c for c in results["vblank_candidates"] if c["priority"] == "MEDIUM"]
        print("MEDIUM PRIORITY VBlank Candidates:")
        print("-" * 70)
        for i, cand in enumerate(med_pri[:10], 1):
            print(f"{i}. Offset 0x{cand['offset']:06X}: {cand['svc_name']}")
            print(f"   In loop: {cand['in_loop']}, Has count: {cand['has_count']}")
            print()

    # Save results
    output_path = Path("tmp/svc_analysis.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Full results saved to: {output_path}")
    print()

    return results

if __name__ == "__main__":
    results = analyze_svc_calls()

    if results:
        print("=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)
        print()
        print("Next steps:")
        print("1. Review HIGH priority VBlank candidates")
        print("2. Generate test ROMs that NOP out these SVC calls")
        print("3. Or patch nearby count values (2 → 1) if found")
        print()
