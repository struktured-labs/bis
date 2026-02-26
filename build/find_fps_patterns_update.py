#!/usr/bin/env python3
"""
Find FPS control patterns in updated BIS code.bin.

The v1.0 60fps patch replaces two LDRB instructions that read the FPS mode byte
from a heap struct at offset +0x3D:
  - 0x03E918: E5D4103D -> LDRB R1,[R4,#0x3D] (main frame loop)
  - 0x180A84: E5D4003D -> LDRB R0,[R4,#0x3D] (init-time)

This script finds equivalent patterns in the updated code.bin.
"""
import struct
import sys
from pathlib import Path

BASE_ADDR = 0x00100000

# ARM instruction encoding for LDRB Rn, [Rm, #0x3D]:
# E5Dm n03D where m=base reg, n=dest reg
# Mask: 0xFF0F0FFF, Match: 0xE5000030 with bits for #0x3D
# More precisely: LDRB is cond=E, opcode pattern 0101 (LDR), B bit set
# E5D?_?03D pattern

KNOWN_V10_PATTERNS = {
    0x03E918: (b'\xe5\xd4\x10\x3d', "LDRB R1,[R4,#0x3D]", b'\xe3\xa0\x10\x00', "MOV R1,#0"),
    0x180A84: (b'\xe5\xd4\x00\x3d', "LDRB R0,[R4,#0x3D]", b'\xe3\xa0\x00\x00', "MOV R0,#0"),
}


def scan_ldrb_0x3d(data: bytes) -> list:
    """Find all LDRB Rx,[Ry,#0x3D] instructions in ARM code."""
    results = []
    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        # ARM LDRB immediate: E5D[Rn][Rd]03D
        # cond[31:28]=0xE, opcode[27:20]=0x5D, Rn[19:16], Rd[15:12], imm12[11:0]=0x03D
        # Mask out Rn (bits 19:16) and Rd (bits 15:12): mask = 0xFFF00FFF
        if (word & 0xFFF00FFF) == 0xE5D0003D:
            rn = (word >> 16) & 0xF
            rd = (word >> 12) & 0xF
            vaddr = offset + BASE_ADDR
            results.append({
                'offset': offset,
                'vaddr': vaddr,
                'word': word,
                'rn': rn,
                'rd': rd,
                'asm': f"LDRB R{rd},[R{rn},#0x3D]",
                'hex': f"{word:08X}",
            })
    return results


def scan_context(data: bytes, offset: int, window: int = 40) -> str:
    """Get surrounding instructions for context."""
    lines = []
    start = max(0, offset - window)
    end = min(len(data), offset + 4 + window)
    for i in range(start, end, 4):
        word = struct.unpack_from('<I', data, i)[0]
        marker = " >>>" if i == offset else "    "
        vaddr = i + BASE_ADDR
        lines.append(f"  {marker} 0x{vaddr:08X}: {word:08X}")
    return "\n".join(lines)


def find_nearby_similarities(v10_data: bytes, v12_data: bytes, v10_offset: int, results_v12: list) -> list:
    """Find v1.2 candidates that are in similar code context as v1.0."""
    # Get surrounding bytes from v1.0 (skip the target instruction itself)
    context_range = 64  # bytes before/after
    v10_before = v10_data[max(0, v10_offset - context_range):v10_offset]
    v10_after = v10_data[v10_offset + 4:min(len(v10_data), v10_offset + 4 + context_range)]

    scored = []
    for r in results_v12:
        o = r['offset']
        v12_before = v12_data[max(0, o - context_range):o]
        v12_after = v12_data[o + 4:min(len(v12_data), o + 4 + context_range)]

        # Count matching 4-byte words in context
        score = 0
        for i in range(0, min(len(v10_before), len(v12_before)) - 3, 4):
            if v10_before[-(i+4):len(v10_before)-i if i > 0 else None] == \
               v12_before[-(i+4):len(v12_before)-i if i > 0 else None]:
                score += 1
        for i in range(0, min(len(v10_after), len(v12_after)) - 3, 4):
            if v10_after[i:i+4] == v12_after[i:i+4]:
                score += 1

        scored.append((score, r))

    scored.sort(key=lambda x: -x[0])
    return scored


def main():
    if len(sys.argv) < 2:
        print("Usage: find_fps_patterns_update.py <v12_code.bin> [v10_code.bin]")
        sys.exit(1)

    v12_path = sys.argv[1]
    v10_path = sys.argv[2] if len(sys.argv) > 2 else "tmp/decompressed/code_decompressed.bin"

    v12_data = Path(v12_path).read_bytes()
    print(f"v1.2 code: {v12_path} ({len(v12_data):,} bytes)")

    v10_data = None
    if Path(v10_path).exists():
        v10_data = Path(v10_path).read_bytes()
        print(f"v1.0 code: {v10_path} ({len(v10_data):,} bytes)")
    print()

    # Step 1: Verify v1.0 patterns
    if v10_data:
        print("=" * 70)
        print("  V1.0 REFERENCE PATTERNS")
        print("=" * 70)
        for offset, (expected, asm, patch, patch_asm) in KNOWN_V10_PATTERNS.items():
            actual = v10_data[offset:offset + 4]
            # Note: expected is little-endian bytes of the big-endian hex shown
            word = struct.unpack('<I', actual)[0]
            match = "OK" if actual == struct.pack('<I', int.from_bytes(expected, 'big')) else "MISMATCH"
            # Actually the hex E5D4103D is the big-endian representation
            # In little-endian memory: 3D 10 D4 E5
            expected_le = bytes([expected[3], expected[2], expected[1], expected[0]])
            match = "OK" if actual == expected_le else "MISMATCH"
            print(f"  0x{offset:06X} (vaddr 0x{offset + BASE_ADDR:08X}): {word:08X} [{asm}] - {match}")
            if match == "MISMATCH":
                print(f"    Expected: {int.from_bytes(expected, 'big'):08X}, Got: {word:08X}")
        print()

    # Step 2: Scan v1.2 for all LDRB Rx,[Ry,#0x3D]
    print("=" * 70)
    print("  V1.2 LDRB Rx,[Ry,#0x3D] SCAN")
    print("=" * 70)
    results = scan_ldrb_0x3d(v12_data)
    print(f"  Found {len(results)} LDRB Rx,[Ry,#0x3D] instructions")
    print()

    for r in results:
        print(f"  offset 0x{r['offset']:06X} (vaddr 0x{r['vaddr']:08X}): {r['hex']} = {r['asm']}")

    # Step 3: Check if v1.0 patterns exist at same offsets
    print()
    print("=" * 70)
    print("  DIRECT OFFSET CHECK")
    print("=" * 70)
    direct_matches = 0
    for offset, (expected, asm, patch, patch_asm) in KNOWN_V10_PATTERNS.items():
        if offset + 4 <= len(v12_data):
            word = struct.unpack_from('<I', v12_data, offset)[0]
            expected_word_be = int.from_bytes(expected, 'big')
            expected_word_le = struct.unpack('<I', expected)[0]
            # The hex E5D4103D - in the IPS patch, this appears as-is in big endian
            # But in ARM memory it's little-endian
            # Let's check both
            is_match = (word == expected_word_be) or (word == expected_word_le)
            status = "SAME" if is_match else "CHANGED"
            print(f"  0x{offset:06X}: v1.0={expected.hex()} v1.2={word:08X} -> {status}")
            if is_match:
                direct_matches += 1
            elif word:
                # Show what's actually there
                print(f"    v1.2 has different instruction at this offset")
        else:
            print(f"  0x{offset:06X}: OUT OF RANGE in v1.2 (v1.2 size: 0x{len(v12_data):X})")

    if direct_matches == len(KNOWN_V10_PATTERNS):
        print("\n  *** ALL patterns at SAME offsets! v1.0 IPS patch may work directly! ***")
    print()

    # Step 4: Find best matches using context similarity
    if v10_data and results:
        print("=" * 70)
        print("  CONTEXT SIMILARITY ANALYSIS")
        print("=" * 70)

        for v10_offset, (expected, asm, patch_bytes, patch_asm) in KNOWN_V10_PATTERNS.items():
            print(f"\n  Looking for equivalent of v1.0 0x{v10_offset:06X} ({asm}):")
            # Filter candidates by same base register
            expected_word = struct.unpack('>I', expected)[0]
            target_rn = (expected_word >> 16) & 0xF
            target_rd = (expected_word >> 12) & 0xF

            same_regs = [r for r in results if r['rn'] == target_rn and r['rd'] == target_rd]
            if same_regs:
                print(f"    Candidates with same registers (R{target_rd},[R{target_rn},#0x3D]): {len(same_regs)}")
                scored = find_nearby_similarities(v10_data, v12_data, v10_offset, same_regs)
                for score, r in scored[:5]:
                    offset_delta = r['offset'] - v10_offset
                    print(f"      0x{r['offset']:06X} (delta: {offset_delta:+d}): context score={score}")
                    print(f"        {scan_context(v12_data, r['offset'], 16)}")
            else:
                print(f"    No candidates with R{target_rd},[R{target_rn},#0x3D]")
                # Show all candidates
                scored = find_nearby_similarities(v10_data, v12_data, v10_offset, results)
                for score, r in scored[:3]:
                    print(f"      0x{r['offset']:06X} ({r['asm']}): context score={score}")

    # Step 5: Output patch candidates
    print()
    print("=" * 70)
    print("  RECOMMENDED PATCHES")
    print("=" * 70)
    print()

    # Save results for generate_update_ips.py
    import json
    output = {
        'v12_path': v12_path,
        'v12_size': len(v12_data),
        'all_ldrb_0x3d': results,
        'v10_patterns': {hex(k): v[1] for k, v in KNOWN_V10_PATTERNS.items()},
    }
    out_path = Path("tmp/update_v12/fps_scan_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"  Results saved to: {out_path}")


if __name__ == "__main__":
    main()
