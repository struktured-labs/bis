#!/usr/bin/env python3
"""Scan ARM32 code.bin for all instructions accessing struct offset +0x3D.

Searches for:
- LDRB Rn,[Rm,#0x3D] (byte load from base+0x3D)
- STRB Rn,[Rm,#0x3D] (byte store to base+0x3D)
- LDRH, STRH variants with offset 0x3D
- LDR/STR word with offset 0x3D

Covers all condition codes (not just AL/always).
"""

import struct
import sys

CODE_BIN = "/home/struktured/projects/bis/tmp/update_v12/exefs_dir/code.bin"
VADDR_BASE = 0x100000

# Already patched locations (v1.2 file offsets)
PATCHED = {0x03E8E8, 0x180A5C}

COND_CODES = {
    0x0: "EQ", 0x1: "NE", 0x2: "CS", 0x3: "CC",
    0x4: "MI", 0x5: "PL", 0x6: "VS", 0x7: "VC",
    0x8: "HI", 0x9: "LS", 0xA: "GE", 0xB: "LT",
    0xC: "GT", 0xD: "LE", 0xE: "",   0xF: "NV",
}

REG_NAMES = {
    0: "R0", 1: "R1", 2: "R2", 3: "R3",
    4: "R4", 5: "R5", 6: "R6", 7: "R7",
    8: "R8", 9: "R9", 10: "R10", 11: "R11",
    12: "R12", 13: "SP", 14: "LR", 15: "PC",
}


def decode_reg(n):
    return REG_NAMES.get(n, f"R{n}")


def main():
    with open(CODE_BIN, "rb") as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes from {CODE_BIN}")
    print(f"Scanning for all ARM instructions with immediate offset 0x3D...\n")

    results = []

    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, offset)[0]

        # Extract fields
        cond = (word >> 28) & 0xF
        if cond == 0xF:
            continue  # unconditional space, skip

        # ---- LDRB Rd,[Rn,#0x3D] ----
        # Encoding: cond 0101 U1D1 Rn Rd 0000 0011 1101
        # Bits [27:20] for LDRB imm, pre-indexed, no writeback, up:
        #   01 0 P U 1 W 1 = 0101 1101 = 0x5D (pre, up, byte, load)
        # But also 0x55 (pre, up, byte, load, no writeback) -> bits[27:20]=01011101=0x5D
        # Actually: bits[27:26]=01, bit25=0(imm), bit24=P, bit23=U, bit22=B, bit21=W, bit20=L
        # LDRB pre-index up no-writeback: P=1,U=1,B=1,W=0,L=1 -> 0b01011101 = 0x5D
        # imm12 in bits[11:0]

        bits_27_20 = (word >> 20) & 0xFF

        # LDRB Rd,[Rn,#+0x3D] (pre-indexed, up, byte, load, no writeback)
        if bits_27_20 == 0x5D and (word & 0xFFF) == 0x03D:
            rn = (word >> 16) & 0xF
            rd = (word >> 12) & 0xF
            cc = COND_CODES[cond]
            instr = f"LDRB{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
            results.append((offset, word, instr, "LDRB"))

        # STRB Rd,[Rn,#+0x3D] (pre-indexed, up, byte, store, no writeback)
        # P=1,U=1,B=1,W=0,L=0 -> 0b01011100 = 0x5C
        elif bits_27_20 == 0x5C and (word & 0xFFF) == 0x03D:
            rn = (word >> 16) & 0xF
            rd = (word >> 12) & 0xF
            cc = COND_CODES[cond]
            instr = f"STRB{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
            results.append((offset, word, instr, "STRB"))

        # LDR word Rd,[Rn,#+0x3D] (pre, up, word, load, no wb)
        # P=1,U=1,B=0,W=0,L=1 -> 0b01011001 = 0x59
        elif bits_27_20 == 0x59 and (word & 0xFFF) == 0x03D:
            rn = (word >> 16) & 0xF
            rd = (word >> 12) & 0xF
            cc = COND_CODES[cond]
            instr = f"LDR{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
            results.append((offset, word, instr, "LDR"))

        # STR word Rd,[Rn,#+0x3D] (pre, up, word, store, no wb)
        # P=1,U=1,B=0,W=0,L=0 -> 0b01011000 = 0x58
        elif bits_27_20 == 0x58 and (word & 0xFFF) == 0x03D:
            rn = (word >> 16) & 0xF
            rd = (word >> 12) & 0xF
            cc = COND_CODES[cond]
            instr = f"STR{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
            results.append((offset, word, instr, "STR"))

        # LDRH Rd,[Rn,#+0x3D] - halfword load
        # Encoding: cond 000P U1W1 Rn Rd imm4H 1011 imm4L
        # P=1,U=1,W=0,L=1: bits[27:20] = 0001 1101 = 0x1D (but bit25=0 for imm)
        # Actually bits[27:25]=000, bit24=P, bit23=U, bit22=1(imm), bit21=W, bit20=L
        # imm8 = imm4H:imm4L, bits[11:8] and [3:0]
        # For offset 0x3D = 0b00111101: imm4H=0x3, imm4L=0xD
        # bits[7:4] = 1011 for LDRH
        elif bits_27_20 == 0x1D:
            imm4h = (word >> 8) & 0xF
            imm4l = word & 0xF
            op2 = (word >> 4) & 0xF
            imm8 = (imm4h << 4) | imm4l
            if imm8 == 0x3D and op2 == 0xB:  # 1011 = LDRH
                rn = (word >> 16) & 0xF
                rd = (word >> 12) & 0xF
                cc = COND_CODES[cond]
                instr = f"LDRH{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
                results.append((offset, word, instr, "LDRH"))

        # STRH Rd,[Rn,#+0x3D]
        # P=1,U=1,W=0,L=0: bits[27:20] = 0001 1100 = 0x1C
        elif bits_27_20 == 0x1C:
            imm4h = (word >> 8) & 0xF
            imm4l = word & 0xF
            op2 = (word >> 4) & 0xF
            imm8 = (imm4h << 4) | imm4l
            if imm8 == 0x3D and op2 == 0xB:  # 1011 = STRH
                rn = (word >> 16) & 0xF
                rd = (word >> 12) & 0xF
                cc = COND_CODES[cond]
                instr = f"STRH{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
                results.append((offset, word, instr, "STRH"))

        # LDRSB Rd,[Rn,#+0x3D] - signed byte load
        # Same format as LDRH but op2 = 1101 (0xD)
        elif bits_27_20 == 0x1D:
            imm4h = (word >> 8) & 0xF
            imm4l = word & 0xF
            op2 = (word >> 4) & 0xF
            imm8 = (imm4h << 4) | imm4l
            if imm8 == 0x3D and op2 == 0xD:  # 1101 = LDRSB
                rn = (word >> 16) & 0xF
                rd = (word >> 12) & 0xF
                cc = COND_CODES[cond]
                instr = f"LDRSB{cc} {decode_reg(rd)},[{decode_reg(rn)},#0x3D]"
                results.append((offset, word, instr, "LDRSB"))

    # Print results
    print(f"{'Type':<8} {'File Offset':<14} {'VAddr':<12} {'Raw Hex':<12} {'Instruction':<45} {'Patched?'}")
    print("-" * 120)

    ldrb_count = 0
    strb_count = 0
    other_count = 0

    for offset, word, instr, itype in sorted(results, key=lambda x: x[0]):
        vaddr = offset + VADDR_BASE
        raw = f"{word:08X}"
        patched = "** PATCHED **" if offset in PATCHED else ""
        print(f"{itype:<8} 0x{offset:08X}   0x{vaddr:06X}   {raw}   {instr:<45} {patched}")

        if itype == "LDRB":
            ldrb_count += 1
        elif itype == "STRB":
            strb_count += 1
        else:
            other_count += 1

    print(f"\nSummary: {len(results)} total hits")
    print(f"  LDRB: {ldrb_count}")
    print(f"  STRB: {strb_count}")
    print(f"  Other (LDR/STR/LDRH/STRH/LDRSB): {other_count}")
    print(f"  Already patched: {sum(1 for o,_,_,_ in results if o in PATCHED)}")
    print(f"  Unpatched: {sum(1 for o,_,_,_ in results if o not in PATCHED)}")


if __name__ == "__main__":
    main()
