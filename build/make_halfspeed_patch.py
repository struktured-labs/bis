"""Create half-speed game logic IPS patch v3: SELF-CONTAINED.

60fps rendering + 30Hz game logic, no emulator modifications needed.

Strategy:
1. Force mode 0 (60fps) at FPS read sites
2. Replace run-all path entry at 0x3DF7C with B trampoline
3. Trampoline alternates toggle byte (+0x48) itself:
   - Flip toggle 0<->1
   - If new value is 0: skip entire game logic block (B 0x3E3A4)
   - If new value is 1: run game logic normally (B 0x3DF80)
4. No emulator toggle code needed - fully self-contained IPS patch

The trampoline runs once per game frame (in the mode 0 run-all path).
Toggle alternates each frame: run, skip, run, skip...
Result: 60fps rendering, 30Hz game logic = correct 1x game speed.

Trampoline at 0x3E900 (8 instructions, 32 bytes):
  0x3E900: LDRB R0,[R4,#0x48]     ; load toggle
  0x3E904: EOR R0,R0,#1           ; flip 0<->1
  0x3E908: STRB R0,[R4,#0x48]     ; store new toggle
  0x3E90C: CMP R0,#0              ; check new value
  0x3E910: BEQ skip_logic         ; if 0, skip game logic
  0x3E914: CPY R10,R5             ; replicate replaced instruction
  0x3E918: B 0x3DF80             ; continue to full game logic
  skip_logic:
  0x3E91C: B 0x3E3A4             ; skip entire game logic block
"""
import struct

def encode_branch(from_addr, to_addr, cond='AL'):
    """Encode ARM B instruction (little-endian)."""
    offset = (to_addr - from_addr - 8) // 4
    cond_codes = {'AL': 0xE, 'EQ': 0x0, 'NE': 0x1}
    cond_val = cond_codes[cond]
    offset_24 = offset & 0x00FFFFFF
    instr = (cond_val << 28) | (0xA << 24) | offset_24
    return struct.pack('<I', instr)

# Verify branch encoding
test = encode_branch(0x3E8FC, 0x3E924, 'NE')
assert test == b'\x08\x00\x00\x1A', "Branch encoding test failed: %s" % test.hex()

# ARM instruction encodings (little-endian)
LDRB_R0_R4_0x48 = b'\x48\x00\xD4\xE5'  # LDRB R0,[R4,#0x48]
EOR_R0_R0_1    = b'\x01\x00\x20\xE2'  # EOR R0,R0,#1
STRB_R0_R4_0x48 = b'\x48\x00\xC4\xE5'  # STRB R0,[R4,#0x48]
CMP_R0_0       = b'\x00\x00\x50\xE3'  # CMP R0,#0
CPY_R10_R5     = b'\x05\xA0\xA0\xE1'  # MOV R10,R5

# Trampoline: 8 instructions (32 bytes)
trampoline = b''
trampoline += LDRB_R0_R4_0x48                        # load toggle
trampoline += EOR_R0_R0_1                             # flip 0<->1
trampoline += STRB_R0_R4_0x48                         # store new value
trampoline += CMP_R0_0                                # check
trampoline += encode_branch(0x3E910, 0x3E91C, 'EQ')  # BEQ skip_logic
trampoline += CPY_R10_R5                              # replicate replaced instruction
trampoline += encode_branch(0x3E918, 0x3DF80)         # B 0x3DF80 (game logic)
# skip_logic:
trampoline += encode_branch(0x3E91C, 0x3E3A4)         # B 0x3E3A4 (skip game logic)

assert len(trampoline) == 32, "Trampoline should be 32 bytes, got %d" % len(trampoline)

patches = [
    # Force mode 0 (60fps) at read sites
    (0x03E8E8, b'\x00\x10\xA0\xE3'),  # MOV R1,#0 (main frame loop)
    (0x180A5C, b'\x00\x00\xA0\xE3'),  # MOV R0,#0 (init-time)

    # Branch to trampoline (replaces cpy r10,r5 at 0x3DF7C)
    (0x03DF7C, encode_branch(0x3DF7C, 0x3E900)),

    # Trampoline code (in dead space: mode 2 toggle code, never reached in mode 0)
    (0x03E900, trampoline),
]

with open("patches/60fps_halfspeed_v1.2.ips", "wb") as f:
    f.write(b"PATCH")
    for offset, data in patches:
        f.write(struct.pack(">I", offset)[1:])
        f.write(struct.pack(">H", len(data)))
        f.write(data)
    f.write(b"EOF")

total_bytes = sum(len(d) for _, d in patches)
print("Created patches/60fps_halfspeed_v1.2.ips (%d records, %d bytes patched)" % (len(patches), total_bytes))
for off, data in patches:
    print("  0x%06X (%2d bytes): %s" % (off, len(data), data.hex()))

print("\nBranch verification:")
print("  0x3DF7C -> 0x3E900: %s" % encode_branch(0x3DF7C, 0x3E900).hex())
print("  0x3E910 -> 0x3E91C (BEQ): %s" % encode_branch(0x3E910, 0x3E91C, 'EQ').hex())
print("  0x3E918 -> 0x3DF80: %s" % encode_branch(0x3E918, 0x3DF80).hex())
print("  0x3E91C -> 0x3E3A4: %s" % encode_branch(0x3E91C, 0x3E3A4).hex())
