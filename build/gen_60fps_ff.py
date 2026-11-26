#!/usr/bin/env python3
"""v1.2.4 candidate: give R back to the game's cutscene fast-forward, move
the 30fps hold to L, and add an in-game FPS counter (toggle: hold L, press
SELECT). Game 1.0 and game 1.2 each get their own files (never cross-install).

Outputs (patches/ff/):
  60fps_v1X_ff.ips           release candidate; counter built in, OFF at boot
  60fps_v1X_ff_fpson.ips     same code, counter ON at boot (hardware testing)
  60fps_v1X_ff_nocounter.ips fallback: v1.2.3 with only the R->L change

Base = shipped v1.2.3 patch (patches/60fps_v1X_full_r.ips), byte for byte,
except the 30fps-hold button in the toggle cave: KEY_R (0x100) -> KEY_L
(0x200). R is no longer read by the patch, so holding R is exactly the
stock game's fast-forward, at 60fps.

Counter hooks:
  * TaskBase::callbackVSync (the game's own VSync callback, called by nngx
    for every top/bottom LCD VSync): +1 to a VSync counter for the top
    screen (0x400).
  * The BL at the top-screen display-buffer swap (the game's call to the
    nngx framebuffer setter, which hands the finished frame to GSP): +1
    frame; every >= 60 VSyncs fps = round(frames*60/vsyncs). The pad is
    read through the game's HID object (*(*(0x42A6C0+4)+0x1C), null-checked);
    L held + SELECT rising edge flips the on/off flag. When on, two digits
    are drawn into the top-left of the frame about to be shown (address,
    stride and format are the arguments the game passes to the setter), and
    that range is flushed from the CPU data cache with the game's own nngx
    FlushDataCache wrapper (GSP IPC), so the LCD sees the pixels on hardware.
    When off: no drawing and no flush, only the counters run.
Counter state lives in the zero padding after .bss inside the game's own
    data segment (exheader: data 0x3F0000 + 0x9170, bss 0x3CBD0 ->
    0x435D40; mapped to 0x436000). It is not assumed to be zero: a magic
    word gates initialisation.

Rules: docs/REAL_HARDWARE_RULES.md. No hardcoded HID/IO/shared-memory VA,
no new SVC, no runtime .text writes, caves in end-of-.text padding.
"""

import hashlib
import os
import struct
import sys

from keystone import KS_ARCH_ARM, KS_MODE_ARM, Ks

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
BASE = 0x100000

VERSIONS = {
    "v10": dict(
        code_bin=os.environ.get("BIS_V10_CODE_BIN") or os.path.expanduser("~/projects/bis/tmp/v10_extract/exefs_dir/code.bin"),
        base_ips="patches/60fps_v10_full_r.ips",
        base_sha="7628c2a30beee2a324b8feb7399f812a09b3189fd4d1cb13ec05396a6173c5d2",
        text_end=0x3890E8,
        cb_vsync=0x13DA58,     # ad::fw::TaskBase::callbackVSync(unsigned)
        fb_call=0x105758,      # BL nngx framebuffer setter, top screen (0x400)
        fb_set=0x112C30,
        flush=0x1225A8,        # nngx FlushDataCache(addr,size) wrapper (GSP 0x00080082)
    ),
    "v12": dict(
        code_bin=os.environ.get("BIS_V12_CODE_BIN") or os.path.expanduser("~/projects/bis/tmp/update_v12/exefs_dir/code.bin"),
        base_ips="patches/60fps_v12_full_r.ips",
        base_sha="47fe2432d95d237cd832c2aff82cd9f447598a002bf448b794297339bf1ac889",
        text_end=0x389218,
        cb_vsync=0x13DA28,
        fb_call=0x1057A0,
        fb_set=0x112D5C,
        flush=0x122578,
    ),
}

TOGGLE_CAVE_FOFF = 0x289F00
TST_R = 0xE3120C01          # TST R2,#0x100 (KEY_R)
TST_L = 0xE3120C02          # TST R2,#0x200 (KEY_L)

FPS_CAVE = 0x389A00         # end-of-.text padding (both versions end < 0x389220)
FPS_CAVE_END = 0x389F00     # toggle cave starts here
STATE = 0x435E00            # .bss tail padding (bss ends 0x435D40, page ends 0x436000)
DATA_END_MAPPED = 0x436000
BSS_END = 0x3F0000 + 0x9170 + 0x3CBD0
MAGIC = 0x46505332          # 'FPS2'
HID_OBJECT = 0x0042A6C0     # game's HID object (.bss); +4 = PAD shm ptr the game stored

# 3x5 digit font, rows top->bottom, 3 bits per row (bit2 = left column)
FONT = [
    [7, 5, 5, 5, 7], [2, 6, 2, 2, 7], [7, 1, 7, 4, 7], [7, 1, 7, 1, 7], [5, 5, 7, 1, 1],
    [7, 4, 7, 1, 7], [7, 4, 7, 5, 7], [7, 1, 1, 2, 2], [7, 5, 7, 5, 7], [7, 5, 7, 1, 7],
]
SCALE = 3
BOX_X, BOX_Y = 2, 2
BOX_W = 2 + 3 * SCALE + SCALE + 3 * SCALE + 2   # 25
BOX_H = 2 + 5 * SCALE + 2                       # 19


def font_words():
    # one 16-bit mask per digit: bit (row*3 + col), col 0 = left
    out = []
    for g in FONT:
        m = 0
        for r, bits in enumerate(g):
            for c in range(3):
                if bits & (4 >> c):
                    m |= 1 << (r * 3 + c)
        out.append(m)
    return out


def parse_ips(buf):
    assert buf[:5] == b"PATCH" and buf[-3:] == b"EOF"
    p, recs = 5, []
    while p < len(buf) - 3:
        off = int.from_bytes(buf[p:p + 3], "big"); n = int.from_bytes(buf[p + 3:p + 5], "big")
        recs.append((off, buf[p + 5:p + 5 + n])); p += 5 + n
    return recs


def make_ips(records):
    buf = b"PATCH"
    for off, data in sorted(records):
        assert 0 <= off <= 0xFFFFFF and len(data) <= 0xFFFF
        buf += off.to_bytes(3, "big") + len(data).to_bytes(2, "big") + data
    return buf + b"EOF"


def asm(src, addr):
    enc, _ = Ks(KS_ARCH_ARM, KS_MODE_ARM).asm(src, addr)
    return bytes(enc)


def fps_cave_src(v, default_on=False):
    fw = font_words()
    s = f"""
cave_vs:
    cmp   r1, #0x400
    bne   vs_out
    ldr   r12, =0x{STATE:x}
    ldr   r2, [r12, #4]
    add   r2, r2, #1
    str   r2, [r12, #4]
vs_out:
    push  {{r4, lr}}
    b     #0x{v['cb_vsync'] + 4:x}

cave_fb:
    push  {{r0-r12, lr}}
    cmp   r0, #0x400
    bne   done
    ldr   r4, =0x{STATE:x}
    ldr   r5, [r4]
    ldr   r6, =0x{MAGIC:x}
    cmp   r5, r6
    beq   counted
    str   r6, [r4]
    ldr   r7, [r4, #4]
    str   r7, [r4, #12]
    mov   r7, #0
    str   r7, [r4, #8]
    str   r7, [r4, #16]
    str   r7, [r4, #20]
    mov   r7, #{1 if default_on else 0}
    str   r7, [r4, #24]
counted:
    ldr   r5, [r4, #8]
    add   r5, r5, #1
    str   r5, [r4, #8]
    ldr   r7, [r4, #4]
    ldr   r8, [r4, #12]
    sub   r9, r7, r8
    cmp   r9, #60
    blo   pad
    mov   r10, #60
    mul   r11, r5, r10
    add   r11, r11, r9, lsr #1
    mov   r10, #0
div60:
    cmp   r11, r9
    subhs r11, r11, r9
    addhs r10, r10, #1
    bhs   div60
    cmp   r10, #99
    movhi r10, #99
    str   r10, [r4, #16]
    mov   r5, #0
    str   r5, [r4, #8]
    str   r7, [r4, #12]

pad:
    @ L held + SELECT pressed (rising edge) toggles the counter. Pad is read
    @ the way the game does: *(*(HID_OBJECT+4)+0x1C), null-checked.
    ldr   r0, =0x{HID_OBJECT:x}
    ldr   r0, [r0, #4]
    cmp   r0, #0
    moveq r1, #0
    ldrne r1, [r0, #0x1C]
    ldr   r2, [r4, #20]
    str   r1, [r4, #20]
    tst   r1, #0x200
    beq   no_toggle
    tst   r1, #4
    beq   no_toggle
    tst   r2, #4
    bne   no_toggle
    ldr   r3, [r4, #24]
    eor   r3, r3, #1
    str   r3, [r4, #24]
no_toggle:
    ldr   r3, [r4, #24]
    cmp   r3, #0
    beq   done

draw:
    ldr   r0, [sp, #56]
    ldr   r1, =0x8051
    cmp   r0, r1
    moveq r6, #3
    beq   bpp_ok
    ldr   r1, =0x8058
    cmp   r0, r1
    moveq r6, #4
    movne r6, #2
bpp_ok:
    ldr   r3, [sp, #12]
    mul   r7, r3, r6
    ldr   r8, [sp, #4]
    bl    draw_buf
    ldr   r0, [sp, #8]
    cmp   r0, #0
    beq   done
    ldr   r1, [sp, #4]
    cmp   r0, r1
    beq   done
    mov   r8, r0
    bl    draw_buf
done:
    pop   {{r0-r12, lr}}
    b     #0x{v['fb_set']:x}

draw_buf:
    push  {{r4, r5, r9, r10, r11, lr}}
    cmp   r8, #0
    beq   db_out
    mov   r0, #{BOX_X}
    mov   r1, #{BOX_Y}
    mov   r2, #{BOX_W}
    mov   r3, #{BOX_H}
    mov   r12, #0
    bl    fill
    ldr   r10, [r4, #16]
    mov   r11, #0
tens:
    cmp   r10, #10
    subhs r10, r10, #10
    addhs r11, r11, #1
    bhs   tens
    mov   r0, r11
    mov   r9, #{BOX_X + 2}
    bl    glyph
    mov   r0, r10
    mov   r9, #{BOX_X + 2 + 4 * SCALE}
    bl    glyph
    mov   r0, #{BOX_X}
    mul   r0, r0, r7
    add   r0, r0, r8
    mov   r1, #{BOX_W}
    mul   r1, r1, r7
    bl    #0x{v['flush']:x}
db_out:
    pop   {{r4, r5, r9, r10, r11, pc}}

glyph:
    push  {{r4, r5, r9, r10, r11, lr}}
    adr   r1, font
    lsl   r0, r0, #1
    ldrh  r11, [r1, r0]
    mov   r10, #0
g_loop:
    tst   r11, #1
    beq   g_next
    mov   r5, r10
    mov   r4, #0
g_row:
    cmp   r5, #3
    subhs r5, r5, #3
    addhs r4, r4, #1
    bhs   g_row
    mov   r0, #{SCALE}
    mul   r0, r5, r0
    add   r0, r0, r9
    mov   r1, #{SCALE}
    mul   r1, r4, r1
    add   r1, r1, #{BOX_Y + 2}
    mov   r2, #{SCALE}
    mov   r3, #{SCALE}
    mov   r12, #0xFF
    bl    fill
g_next:
    lsr   r11, r11, #1
    add   r10, r10, #1
    cmp   r10, #15
    blo   g_loop
    pop   {{r4, r5, r9, r10, r11, pc}}

fill:
    push  {{r4, r5, r9, r10, r11, lr}}
    add   r1, r1, r3
    rsb   r1, r1, #240
    mul   r1, r1, r6
    mul   r3, r3, r6
f_col:
    mul   r4, r0, r7
    add   r4, r4, r8
    add   r4, r4, r1
    mov   r5, r3
f_byte:
    strb  r12, [r4], #1
    subs  r5, r5, #1
    bne   f_byte
    add   r0, r0, #1
    subs  r2, r2, #1
    bne   f_col
    pop   {{r4, r5, r9, r10, r11, pc}}

font:
    .short {", ".join(hex(x) for x in fw)}
    .align 2
"""
    return s


def build(vname, with_counter, toggle="L", default_on=False):
    v = VERSIONS[vname]
    base = open(os.path.join(ROOT, v["base_ips"]), "rb").read()
    assert hashlib.sha256(base).hexdigest() == v["base_sha"], f"{v['base_ips']} is not the shipped v1.2.3 file"
    code = open(v["code_bin"], "rb").read()
    recs = dict(parse_ips(base))

    cave = bytearray(recs[TOGGLE_CAVE_FOFF])
    assert struct.unpack_from("<I", cave, 24)[0] == TST_R
    if toggle == "L":
        struct.pack_into("<I", cave, 24, TST_L)
    recs[TOGGLE_CAVE_FOFF] = bytes(cave)

    if with_counter:
        # site checks against the original code.bin
        def word(va):
            return struct.unpack_from("<I", code, va - BASE)[0]
        assert word(v["cb_vsync"]) == 0xE92D4010, "callbackVSync must start with PUSH {R4,LR}"
        assert word(v["cb_vsync"] + 4) == 0xE3510B01, "callbackVSync: CMP R1,#0x400"
        fbw = word(v["fb_call"])
        assert fbw >> 24 == 0xEB and (v["fb_call"] + 8 + (((fbw & 0xFFFFFF) ^ 0x800000) - 0x800000) * 4) == v["fb_set"], "fb call site"
        assert word(v["flush"]) == 0xE92D4070
        assert v["text_end"] <= FPS_CAVE
        assert code[FPS_CAVE - BASE:TOGGLE_CAVE_FOFF] == bytes(TOGGLE_CAVE_FOFF - (FPS_CAVE - BASE)), "cave padding not zero"
        assert BSS_END <= STATE and STATE + 0x20 <= DATA_END_MAPPED

        blob = asm(fps_cave_src(v, default_on), FPS_CAVE)
        assert FPS_CAVE + len(blob) <= FPS_CAVE_END, f"fps cave too big: {len(blob)}"
        # entry points: cave_vs at +0, cave_fb right after its 8 instrs + literal? find via assembling labels
        cave_vs = FPS_CAVE
        cave_fb = FPS_CAVE + 8 * 4
        assert blob[32:36] == bytes.fromhex("ff5f2de9"), blob[32:36].hex()  # push {r0-r12,lr}
        recs[FPS_CAVE - BASE] = blob

        def b_instr(src, dst, link):
            off = ((dst - (src + 8)) >> 2) & 0xFFFFFF
            return struct.pack("<I", (0xEB if link else 0xEA) << 24 | off)
        recs[v["cb_vsync"] - BASE] = b_instr(v["cb_vsync"], cave_vs, False)
        recs[v["fb_call"] - BASE] = b_instr(v["fb_call"], cave_fb, True)

    return make_ips(list(recs.items()))


def main():
    outdir = os.path.join(ROOT, "patches", "ff")
    os.makedirs(outdir, exist_ok=True)
    variants = [
        ("ff", True, False),             # release candidate: counter built in, OFF until L+SELECT
        ("ff_fpson", True, True),        # HW test build: same code, counter ON at boot
        ("ff_nocounter", False, False),  # fallback: v1.2.3 + L for 30fps only
    ]
    for vname in ("v10", "v12"):
        for suffix, counter, on in variants:
            name = f"60fps_{vname}_{suffix}.ips"
            data = build(vname, counter, default_on=on)
            p = os.path.join(outdir, name)
            open(p, "wb").write(data)
            print(f"{name:32s} {len(data):5d} B  sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
