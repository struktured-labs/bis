#!/usr/bin/env python3
"""
Generate 60fps IPS patch for BIS v1.2 update.

Strategy:
  1. Check if v1.0 offsets still have LDRB Rx,[R4,#0x3D] -> use directly
  2. If not, use context similarity matching to find equivalent instructions
  3. Generate IPS with exactly 2 patches (main loop + init-time)

IPS Format:
  - Header: "PATCH" (5 bytes)
  - Records: 3-byte BE offset + 2-byte BE size + data
  - Footer: "EOF" (3 bytes)
  - Offsets are into decompressed code.bin (vaddr = offset + 0x100000)
"""
import struct
import sys
import json
from pathlib import Path

BASE_ADDR = 0x00100000

# v1.0 known patches
V10_PATCHES = [
    {
        'name': 'main_frame_loop',
        'offset': 0x03E918,
        'word': 0xE5D4103D,  # LDRB R1,[R4,#0x3D]
        'rd': 1, 'rn': 4,
        # Context: instructions around the patch site (for matching)
        'context_before': [0x13A00001, 0x1A000000, 0xE3A00000, 0xE5D4203C],
        'context_after':  [0xE5C40047, 0xE5C42044, 0xE3510002, 0xE5C41045],
    },
    {
        'name': 'init_time',
        'offset': 0x180A84,
        'word': 0xE5D4003D,  # LDRB R0,[R4,#0x3D]
        'rd': 0, 'rn': 4,
        'context_before': [0xE3500000, 0x15C4704A, 0x05C4804A, 0xE5D4103C],
        'context_after':  [0xE5C47046, 0xE5C41044, 0xE5C46378, 0xE5C40045],
    },
]


def find_ldrb_r4_0x3d(data: bytes) -> list:
    """Find all LDRB Rx,[R4,#0x3D] instructions."""
    results = []
    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        # LDRB Rx,[R4,#0x3D] = E5D4x03D
        # Mask out Rd (bits 15:12): 0xFFFF0FFF, match E5D4003D
        if (word & 0xFFFF0FFF) == 0xE5D4003D:
            rd = (word >> 12) & 0xF
            results.append({'offset': offset, 'word': word, 'rd': rd})
    return results


def context_score(data: bytes, offset: int, ref_before: list, ref_after: list) -> int:
    """Score how well the context around an offset matches reference context."""
    score = 0
    # Check instructions before
    for i, ref_word in enumerate(reversed(ref_before)):
        check_offset = offset - (i + 1) * 4
        if check_offset >= 0:
            actual = struct.unpack_from('<I', data, check_offset)[0]
            if actual == ref_word:
                score += 2  # Exact match
    # Check instructions after
    for i, ref_word in enumerate(ref_after):
        check_offset = offset + (i + 1) * 4
        if check_offset + 4 <= len(data):
            actual = struct.unpack_from('<I', data, check_offset)[0]
            if actual == ref_word:
                score += 2  # Exact match
    return score


def make_mov_r_0(rd: int) -> bytes:
    """Generate ARM MOV Rd, #0 instruction (little-endian)."""
    word = 0xE3A00000 | (rd << 12)
    return struct.pack('<I', word)


def make_ips_patch(records: list) -> bytes:
    """Generate IPS patch from list of (offset, data) tuples."""
    patch = b'PATCH'
    for offset, data in records:
        patch += struct.pack('>I', offset)[1:]  # 3-byte BE offset
        patch += struct.pack('>H', len(data))    # 2-byte BE size
        patch += data
    patch += b'EOF'
    return patch


def find_best_match(data: bytes, v10_patch: dict, all_candidates: list) -> dict | None:
    """Find the best matching candidate for a v1.0 patch in the new code."""
    target_rd = v10_patch['rd']

    # Strategy 1: Check exact same offset
    if v10_patch['offset'] + 4 <= len(data):
        word = struct.unpack_from('<I', data, v10_patch['offset'])[0]
        if word == v10_patch['word']:
            score = context_score(data, v10_patch['offset'],
                                  v10_patch['context_before'], v10_patch['context_after'])
            return {
                'offset': v10_patch['offset'],
                'word': word,
                'rd': target_rd,
                'match_type': 'exact_offset',
                'score': score,
            }

    # Strategy 2: Find candidates with same Rd, score by context
    same_rd = [c for c in all_candidates if c['rd'] == target_rd]
    if not same_rd:
        # Fallback: any candidate
        same_rd = all_candidates

    scored = []
    for cand in same_rd:
        s = context_score(data, cand['offset'],
                          v10_patch['context_before'], v10_patch['context_after'])
        scored.append((s, cand))

    scored.sort(key=lambda x: -x[0])

    if scored and scored[0][0] > 0:
        best_score, best_cand = scored[0]
        return {
            'offset': best_cand['offset'],
            'word': best_cand['word'],
            'rd': best_cand['rd'],
            'match_type': f'context_match (score={best_score})',
            'score': best_score,
        }

    # Strategy 3: Closest offset with same register
    if same_rd:
        closest = min(same_rd, key=lambda c: abs(c['offset'] - v10_patch['offset']))
        return {
            'offset': closest['offset'],
            'word': closest['word'],
            'rd': closest['rd'],
            'match_type': f'closest_offset (delta={closest["offset"] - v10_patch["offset"]:+d})',
            'score': 0,
        }

    return None


def main():
    code_path = sys.argv[1] if len(sys.argv) > 1 else "tmp/update_v12/exefs_dir/.code"
    aggressive = "--aggressive" in sys.argv

    code_data = Path(code_path).read_bytes()
    print(f"Code: {code_path} ({len(code_data):,} bytes)")
    print()

    # Find all candidates
    all_candidates = find_ldrb_r4_0x3d(code_data)
    print(f"Found {len(all_candidates)} total LDRB Rx,[R4,#0x3D] instructions")
    for c in all_candidates:
        rd = c['rd']
        vaddr = c['offset'] + BASE_ADDR
        print(f"  0x{c['offset']:06X} (vaddr 0x{vaddr:08X}): LDRB R{rd},[R4,#0x3D]")
    print()

    if aggressive:
        print("=== AGGRESSIVE MODE: Patching ALL candidates ===")
        selected = all_candidates
    else:
        # Smart matching: find the 2 equivalent patches
        print("=== SMART MATCHING: Finding equivalent v1.0 patches ===")
        selected = []
        for v10 in V10_PATCHES:
            match = find_best_match(code_data, v10, all_candidates)
            if match:
                vaddr = match['offset'] + BASE_ADDR
                print(f"  {v10['name']}:")
                print(f"    v1.0: 0x{v10['offset']:06X} (LDRB R{v10['rd']},[R4,#0x3D])")
                print(f"    v1.2: 0x{match['offset']:06X} (LDRB R{match['rd']},[R4,#0x3D])")
                print(f"    match: {match['match_type']}")
                selected.append(match)
            else:
                print(f"  {v10['name']}: NO MATCH FOUND")
                print(f"    Manual analysis required for v1.0 offset 0x{v10['offset']:06X}")
        print()

    if not selected:
        print("ERROR: Could not find any matching patterns!")
        sys.exit(1)

    # Generate patches
    patches = []
    for s in selected:
        patches.append({
            'offset': s['offset'],
            'data': make_mov_r_0(s['rd']),
            'original': s['word'],
            'replacement': struct.unpack('<I', make_mov_r_0(s['rd']))[0],
            'asm_old': f"LDRB R{s['rd']},[R4,#0x3D]",
            'asm_new': f"MOV R{s['rd']},#0",
        })

    print(f"Generating IPS patch with {len(patches)} records:")
    for p in patches:
        vaddr = p['offset'] + BASE_ADDR
        print(f"  0x{p['offset']:06X} (vaddr 0x{vaddr:08X}): "
              f"{p['original']:08X} -> {p['replacement']:08X}")
        print(f"    {p['asm_old']} -> {p['asm_new']}")
    print()

    # Generate IPS
    records = [(p['offset'], p['data']) for p in patches]
    ips_data = make_ips_patch(records)

    # Write IPS patch
    suffix = "_aggressive" if aggressive else ""
    out_path = Path(f"patches/60fps_v12{suffix}.ips")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(ips_data)
    print(f"IPS patch: {out_path} ({len(ips_data)} bytes)")

    # Hex dump
    print(f"\nHex dump:")
    for i, b in enumerate(ips_data):
        if i % 16 == 0:
            print(f"  {i:04X}: ", end="")
        print(f"{b:02X} ", end="")
        if i % 16 == 15:
            print()
    if len(ips_data) % 16 != 0:
        print()

    # Install instructions
    mod_path = Path.home() / ".local/share/azahar-emu/load/mods/00040000001D1400/exefs"
    print(f"\nInstall: cp {out_path} {mod_path}/code.ips")

    # Generate patched code.bin
    patched = bytearray(code_data)
    for p in patches:
        patched[p['offset']:p['offset']+4] = p['data']
    patched_path = Path(f"tmp/update_v12/code_decompressed_60fps{suffix}.bin")
    patched_path.parent.mkdir(parents=True, exist_ok=True)
    patched_path.write_bytes(patched)
    print(f"Patched code: {patched_path}")


if __name__ == "__main__":
    main()
