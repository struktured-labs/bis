#!/usr/bin/env python3
"""Combined build: 60fps + R fast-forward + L 30fps hold + FPS counter
(L+SELECT) + cutscene skip (hold START) + FPS counter in battles.

Built on top of gen_60fps_ff.py (same base v1.2.3 IPS, same counter cave).

Cutscene skip ("turbo skip"): hold START while the game's own fast-forward
is allowed (the event system sets the allow flag; the >>R icon shows):
  * START counts as R for the game's fast-forward controller
    (fld FastForward controller, v1.0 0x31EFD4 / v1.2 0x31F108), so the game
    itself switches fast-forward on/off exactly as with R.
  * The fast-forward time scale the controller loads (stock 2.0, from the
    game's own global 0x413C80) becomes 4.0 while START is held (stays 2.0
    if L is also held). At 60fps a 4.0 scale is the same per-frame time step
    the stock game uses for R fast-forward at 30fps (2 VSyncs x 2.0), so no
    game logic sees a step it never saw in the stock game.
  * Dialogue pages that wait for a button (message window flag 2) get a
    one-frame A press through the message manager's own one-shot input word
    (the word the stock fast-forward uses to inject R), injected right before
    the game's message-window update and only when no window has a choice
    open (flag 4). Choice prompts are never answered; battles use other code.
  Nothing is jumped over: every script command still runs in order, so flags,
  party, positions, music and map loads are produced by the game itself.

FPS counter VSync redraw (battle fix): every top-screen present goes through
the one hooked setter call (v1.0 0x105758 / v1.2 0x1057A0; the only other
setter call, 0x287F94 / 0x2880C8, is always the bottom screen 0x401). nngx
applies a buffer swap only once the GPU command list is done, so when the GPU
is busy (battles) the GPU's display transfer can land in the front buffer
after the counter was drawn into it at present time and erase it on hardware
(Azahar runs command lists synchronously, so it never shows this). The
present-time draw is kept, and the counter cave additionally records the
buffers the game handed to the setter (current + previous, with the VSync
count at which each was last presented). The game's own top-screen VSync
callback then redraws the two digits into those buffers, only while the
counter is on and only for buffers presented within the last 3 (current) /
6 (previous) VSyncs, and flushes them with the game's own GSP FlushDataCache
wrapper, as the present-time draw does.
"""
import hashlib, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_60fps_ff as ff  # noqa: E402

BASE = ff.BASE
SKIP = {
    "v10": dict(ffc=0x31EFD4, rchk1=0x31F028, spd=0x31F074, rchk2=0x31F14C,
                msg_bl=0x20EF10, msg_fn=0x132834, bot_call=0x287F94,
                calc_call=0x13DF54, field_calc=0x306F08, field_vt=0x3E4B54),
    "v12": dict(ffc=0x31F108, rchk1=0x31F15C, spd=0x31F1A8, rchk2=0x31F280,
                msg_bl=0x20EEE8, msg_fn=0x132804, bot_call=0x2880C8,
                calc_call=0x13DF24, field_calc=0x30703C, field_vt=0x3E4B54),
}
FF_SPEED_GLOBAL = 0x413C80          # game's fast-forward scale (2.0), same VA in 1.0 and 1.2
TURBO = 0x40800000                  # 4.0f
SKIP_MAGIC = 0x534B5032             # 'SKP2' at STATE+0x2C
TAP_TICKS = 20                      # START released before 20 controller ticks (~1/3 s) = tap
CALC_TICKS = 16                     # field logic steps per displayed frame while a tap-skip is latched
SKIP_CAVE = 0x389240                # end-of-.text zero padding (v1.2 .text ends 0x389218, v1.0 0x3890E8)
SKIP_CAVE_END = 0x389A00            # counter cave starts here
VMAGIC = 0x46425631                 # 'FBV1' at STATE+0x50: present-record valid
VSD_CAVE = 0x389F40                 # end-of-.text padding after the toggle cave (zero, < 0x38A000)
TEXT_MAPPED_END = 0x38A000
# counter box moves to the top-right corner: the top LCD scans the frame from the
# left edge (x=0) to the right, so a VSync-time redraw at the right edge lands
# well before the scan reaches it.
BOX_X_RIGHT = 400 - ff.BOX_W - 2    # 373
# present record (STATE+): 0x30 stride bytes, 0x34 cur L, 0x38 cur R, 0x3C prev L,
# 0x40 prev R, 0x44 bytes/pixel, 0x48 VSync count cur, 0x4C VSync count prev
REC_OLD = """    ldr   r3, [sp, #12]
    mul   r7, r3, r6
    ldr   r8, [sp, #4]
    bl    draw_buf
"""
REC_NEW = f"""    ldr   r3, [sp, #12]
    mul   r7, r3, r6
    ldr   r8, [sp, #4]
    ldr   r0, [r4, #0x50]
    ldr   r1, =0x{VMAGIC:x}
    cmp   r0, r1
    movne r0, #0
    strne r0, [r4, #0x34]
    strne r0, [r4, #0x38]
    strne r0, [r4, #0x3C]
    strne r0, [r4, #0x40]
    strne r1, [r4, #0x50]
    ldr   r0, [r4, #0x34]
    cmp   r0, r8
    ldrne r1, [r4, #0x38]
    strne r0, [r4, #0x3C]
    strne r1, [r4, #0x40]
    ldrne r1, [r4, #0x48]
    strne r1, [r4, #0x4C]
    ldr   r1, [sp, #8]
    str   r7, [r4, #0x30]
    str   r6, [r4, #0x44]
    str   r1, [r4, #0x38]
    str   r8, [r4, #0x34]
    ldr   r1, [r4, #4]
    str   r1, [r4, #0x48]
    bl    draw_buf
"""


def vsd_src(v, draw_buf):
    # replaces the counter cave's VSync entry: same +1 VSync count for 0x400,
    # then the redraw, then the callback's own first instruction
    return f"""
vs_draw:
    push  {{r0-r12, lr}}
    cmp   r1, #0x400
    bne   vd_out
    ldr   r4, =0x{S:x}
    ldr   r2, [r4, #4]
    add   r2, r2, #1
    str   r2, [r4, #4]
    ldr   r3, [r4]
    ldr   r5, =0x{ff.MAGIC:x}
    cmp   r3, r5
    bne   vd_out
    ldr   r3, [r4, #24]
    cmp   r3, #0
    beq   vd_out
    ldr   r3, [r4, #0x50]
    ldr   r5, =0x{VMAGIC:x}
    cmp   r3, r5
    bne   vd_out
    ldr   r3, [r4, #0x48]
    sub   r3, r2, r3
    cmp   r3, #3
    bhi   vd_out
    ldr   r6, [r4, #0x44]
    ldr   r7, [r4, #0x30]
    ldr   r5, [r4, #0x34]
    mov   r8, r5
    bl    #0x{draw_buf:x}
    ldr   r8, [r4, #0x38]
    cmp   r8, r5
    blne  #0x{draw_buf:x}
    ldr   r3, [r4, #0x4C]
    sub   r3, r2, r3
    cmp   r3, #6
    bhi   vd_out
    ldr   r9, [r4, #0x3C]
    cmp   r9, r5
    beq   vd_out
    mov   r8, r9
    bl    #0x{draw_buf:x}
    ldr   r8, [r4, #0x40]
    cmp   r8, r9
    blne  #0x{draw_buf:x}
vd_out:
    pop   {{r0-r12, lr}}
    push  {{r4, lr}}
    b     #0x{v['cb_vsync'] + 4:x}
.ltorg
"""
S = ff.STATE
ENTRIES = ("cave_ffc", "rs_r3", "rs_r1", "spd", "cave_msg", "cave_calc")


def skip_src(s):
    return f"""
cave_ffc:
    push  {{r0-r7, r12, lr}}
    ldr   r4, =0x{S:x}
    ldr   r1, [r4, #0x2C]
    ldr   r2, =0x{SKIP_MAGIC:x}
    cmp   r1, r2
    beq   ffc_go
    str   r2, [r4, #0x2C]
    mov   r1, #0
    str   r1, [r4, #0x1C]
    str   r1, [r4, #0x20]
    str   r1, [r4, #0x24]
    str   r1, [r4, #0x28]
    str   r1, [r4, #0x58]
    str   r1, [r4, #0x5C]
ffc_go:
    mov   r6, #0
    mov   r3, #0
    ldr   r1, [r0]
    cmp   r1, #0
    beq   ffc_gated
    add   r2, r1, #0x1000
    ldr   r2, [r2, #0xB00]
    cmp   r2, #0
    beq   ffc_gated
    ldr   r3, [r2]
    ldrb  r12, [r0, #5]
    cmp   r12, #0
    beq   ffc_gated
    ldrb  r12, [r0, #6]
    cmp   r12, #0
    moveq r6, #1
ffc_gated:
    ldr   r5, [r4, #0x58]
    ldr   r7, [r4, #0x5C]
    cmp   r6, #0
    moveq r5, #0
    moveq r7, #0
    beq   ffc_tapdone
    tst   r3, #8
    beq   ffc_rel
    cmp   r7, #255
    addlo r7, r7, #1
    b     ffc_tapdone
ffc_rel:
    cmp   r7, #0
    beq   ffc_tapdone
    cmp   r7, #{TAP_TICKS}
    movlo r5, #1
    mov   r7, #0
ffc_tapdone:
    str   r5, [r4, #0x58]
    str   r7, [r4, #0x5C]
    mov   r1, #0
    cmp   r6, #0
    beq   ffc_sk
    tst   r3, #8
    movne r1, #1
    cmp   r5, #0
    movne r1, #1
ffc_sk:
    ldr   r2, [r4, #0x20]
    str   r1, [r4, #0x20]
    str   r1, [r4, #0x1C]
    str   r1, [r4, #0x24]
    mov   r12, #0
    cmp   r1, #0
    beq   ffc_tset
    tst   r3, #0x200
    moveq r12, #1
ffc_tset:
    str   r12, [r4, #0x28]
    cmp   r2, r1
    beq   ffc_out
    cmp   r6, #0
    beq   ffc_out
    ldrb  r12, [r0, #4]
    cmp   r12, #0
    bne   ffc_out
    cmp   r1, #0
    bne   ffc_retog
    tst   r3, #0x100
    beq   ffc_out
ffc_retog:
    mov   r12, #1
    strb  r12, [r0, #4]
ffc_out:
    pop   {{r0-r7, r12, lr}}
    push  {{r4-r10, lr}}
    b     #0x{s['ffc'] + 4:x}

rs_r3:
    orr   r3, r1, r1, lsl #5
    ldr   r1, =0x{S:x}
    ldr   r1, [r1, #0x58]
    orr   r3, r3, r1, lsl #8
    and   r3, r6, r3, lsr #8
    bx    lr

rs_r1:
    orr   r1, r1, r1, lsl #5
    ldr   r12, =0x{S:x}
    ldr   r12, [r12, #0x58]
    orr   r1, r1, r12, lsl #8
    and   r1, r6, r1, lsr #8
    bx    lr

spd:
    ldr   r0, [r0]
    ldr   r12, =0x{S:x}
    ldr   r12, [r12, #0x28]
    cmp   r12, #0
    ldrne r0, =0x{TURBO:x}
    bx    lr

cave_msg:
    push  {{r0-r7, r12, lr}}
    ldr   r4, =0x{S:x}
    ldr   r1, [r4, #0x2C]
    ldr   r2, =0x{SKIP_MAGIC:x}
    cmp   r1, r2
    bne   m_out
    ldr   r1, [r4, #0x24]
    cmp   r1, #0
    beq   m_out
    mov   r1, #0
    str   r1, [r4, #0x24]
    add   r5, r0, #0x48000
    ldrb  r1, [r5, #0x3C8]
    cmp   r1, #0
    beq   m_out
    ldr   r6, [r5, #0x3C4]
    cmp   r6, #0
    beq   m_out
    add   r1, r6, #0x42000
    ldrb  r7, [r1, #0xADC]
    mov   r2, #0
    mov   r3, #0
m_loop:
    cmp   r3, r7
    bge   m_done
    ldr   r1, =0x6D60
    mla   r1, r3, r1, r6
    add   r1, r1, #0x2D000
    ldr   r12, [r1, #0xC44]
    cmp   r12, #0
    beq   m_next
    ldr   r12, [r1, #0xD18]
    tst   r12, #4
    bne   m_out
    tst   r12, #2
    movne r2, #1
m_next:
    add   r3, r3, #1
    b     m_loop
m_done:
    cmp   r2, #0
    beq   m_out
    ldr   r1, [r5, #0x384]
    orr   r1, r1, #1
    str   r1, [r5, #0x384]
m_out:
    pop   {{r0-r7, r12, lr}}
    b     #0x{s['msg_fn']:x}

cave_calc:
    push  {{r4-r8, lr}}
    mov   r4, r0
    mov   r5, r1
    blx   r5
    ldr   r1, =0x{s['field_calc']:x}
    cmp   r5, r1
    bne   c_out
    ldr   r6, =0x{S:x}
    ldr   r1, [r6, #0x2C]
    ldr   r2, =0x{SKIP_MAGIC:x}
    cmp   r1, r2
    bne   c_out
    mov   r7, #{CALC_TICKS - 1}
c_loop:
    ldr   r1, [r6, #0x58]
    cmp   r1, #0
    beq   c_out
    add   r2, r4, #0x1000
    ldrb  r1, [r2, #0xAC5]
    cmp   r1, #0
    beq   c_out
    ldrb  r1, [r2, #0xAC6]
    cmp   r1, #0
    bne   c_out
    ldr   r0, [r2, #0xB30]
    cmp   r0, #0
    beq   c_out
    add   r1, r0, #0x48000
    ldr   r8, [r1, #0x3C4]
    cmp   r8, #0
    beq   c_out
    add   r1, r8, #0x42000
    ldrb  r3, [r1, #0xADC]
    mov   r2, #0
c_win:
    cmp   r2, r3
    bge   c_tick
    ldr   r1, =0x6D60
    mla   r1, r2, r1, r8
    add   r1, r1, #0x2D000
    ldr   r12, [r1, #0xC44]
    cmp   r12, #0
    beq   c_wnext
    ldr   r12, [r1, #0xD18]
    tst   r12, #4
    bne   c_out
c_wnext:
    add   r2, r2, #1
    b     c_win
c_tick:
    mov   r0, r4
    blx   r5
    subs  r7, r7, #1
    bne   c_loop
c_out:
    pop   {{r4-r8, pc}}
"""


def bl_target(code, va):
    w = struct.unpack_from("<I", code, va - BASE)[0]
    assert w >> 24 == 0xEB, hex(va)
    return va + 8 + ((((w & 0xFFFFFF) ^ 0x800000) - 0x800000) * 4)


def b_instr(src, dst, link):
    off = ((dst - (src + 8)) >> 2) & 0xFFFFFF
    return struct.pack("<I", (0xEB if link else 0xEA) << 24 | off)


def build(vname, default_on, vsync_only=False):
    v, s = ff.VERSIONS[vname], SKIP[vname]
    code = open(v["code_bin"], "rb").read()
    word = lambda va: struct.unpack_from("<I", code, va - BASE)[0]
    recs = dict(ff.parse_ips(ff.build(vname, True, default_on=default_on)))
    # counter cave with the present record added (re-assembled from the same source)
    src = ff.fps_cave_src(v, default_on)
    assert src.count(REC_OLD) == 1
    src = src.replace(REC_OLD, REC_NEW)
    xs = {ff.BOX_X: BOX_X_RIGHT, ff.BOX_X + 2: BOX_X_RIGHT + 2, ff.BOX_X + 2 + 4 * ff.SCALE: BOX_X_RIGHT + 2 + 4 * ff.SCALE}
    for reg, old in (("r0", ff.BOX_X), ("r9", ff.BOX_X + 2), ("r9", ff.BOX_X + 2 + 4 * ff.SCALE)):
        a = f"    mov   {reg}, #{old}\n"
        assert a in src, a
        src = src.replace(a, f"    ldr   {reg}, =0x{xs[old]:x}\n")
    assert BOX_X_RIGHT + ff.BOX_W <= 400
    if vsync_only:  # diagnostic only: no present-time draw, VSync redraw alone
        src = src.replace("    bl    draw_buf\n", "    nop\n")
    counter = ff.asm(src, ff.FPS_CAVE)
    assert counter[32:36] == bytes.fromhex("ff5f2de9")
    db = counter.find(bytes.fromhex("304e2de9"), 32)  # draw_buf: first PUSH {r4,r5,r9-r11,lr} after cave_fb
    assert db > 0 and counter[db + 4:db + 8] == bytes.fromhex("000058e3"), "draw_buf entry (cmp r8,#0)"
    draw_buf = ff.FPS_CAVE + db
    recs[ff.FPS_CAVE - BASE] = counter
    # hook-site byte checks against the original code.bin
    assert word(s["ffc"]) == 0xE92D47F0, "FF controller entry PUSH {r4-r10,lr}"
    assert word(s["ffc"] + 0xC) == 0xE5D00006, "FF controller: LDRB r0,[r0,#6]"
    assert word(s["rchk1"]) == 0xE0063421, "AND r3,r6,r1,LSR#8 (R bit)"
    assert word(s["rchk2"]) == 0xE0061421, "AND r1,r6,r1,LSR#8 (R bit)"
    assert word(s["rchk1"] - 0x10) == 0xE5921B00 and word(s["rchk2"] - 0x18) == 0xE5921B00, "LDR r1,[r2,#0xB00] pad ptr"
    assert word(s["spd"]) == 0xE5900000, "LDR r0,[r0]"
    lw = word(s["spd"] - 8)
    assert lw >> 12 == 0xE59F0 and word(s["spd"] - 8 + 8 + (lw & 0xFFF)) == FF_SPEED_GLOBAL, "FF speed literal"
    assert bl_target(code, s["msg_bl"]) == s["msg_fn"]
    assert word(s["msg_bl"] - 4) == 0xE1A00005, "MOV r0,r5 before msg-window update"
    # the only other setter call is the bottom screen (0x401) in the two-screen swap: not hooked
    assert bl_target(code, s["bot_call"]) == v["fb_set"]
    assert word(v["cb_vsync"]) == 0xE92D4010 and word(v["cb_vsync"] + 4) == 0xE3510B01
    for va in (s["ffc"], s["rchk1"], s["spd"], s["rchk2"], s["msg_bl"]):
        assert va - BASE not in recs, hex(va)

    # TaskBase frame: ldr r0,[r4]; ldr r1,[r0,#0x18]; mov r0,r4; blx r1  (scene logic step)
    assert word(s["calc_call"] - 12) == 0xE5940000 and word(s["calc_call"] - 8) == 0xE5901018 and word(s["calc_call"] - 4) == 0xE1A00004 and word(s["calc_call"]) == 0xE12FFF31, "TaskBase calc call"
    # field scene task logic step (its vtable slot +0x18), same prologue in 1.0 and 1.2
    assert code[s["field_calc"] - BASE:s["field_calc"] - BASE + 32] == bytes.fromhex("f04f2de90070a0e1e80a9fed048b2deda4d04de294008de2e38a9fede48adfed"), "field calc prologue"
    assert word(s["field_vt"]) == s["field_calc"], "field task vtable slot"
    assert s["calc_call"] - BASE not in recs
    cave = SKIP_CAVE
    parts, cur = [], None
    for line in skip_src(s).strip().splitlines():
        t = line.strip()
        if t.endswith(":") and t[:-1] in ENTRIES:
            cur = [t[:-1], []]; parts.append(cur)
        cur[1].append(line)
    blob, L = b"", {}
    for name, lines in parts:
        L[name] = len(blob)
        blob += ff.asm("\n".join(lines) + "\n.ltorg\n", cave + len(blob))
        assert len(blob) % 4 == 0
    assert cave + len(blob) <= SKIP_CAVE_END, f"skip cave too big {len(blob):#x}"
    assert v["text_end"] <= SKIP_CAVE
    assert code[cave - BASE:cave - BASE + len(blob)] == bytes(len(blob)), "cave not zero padding"
    recs[cave - BASE] = blob
    recs[s["ffc"] - BASE] = b_instr(s["ffc"], cave + L["cave_ffc"], False)
    recs[s["rchk1"] - BASE] = b_instr(s["rchk1"], cave + L["rs_r3"], True)
    recs[s["rchk2"] - BASE] = b_instr(s["rchk2"], cave + L["rs_r1"], True)
    recs[s["spd"] - BASE] = b_instr(s["spd"], cave + L["spd"], True)
    recs[s["msg_bl"] - BASE] = b_instr(s["msg_bl"], cave + L["cave_msg"], True)
    recs[s["calc_call"] - BASE] = b_instr(s["calc_call"], cave + L["cave_calc"], True)
    vsd = ff.asm(vsd_src(v, draw_buf), VSD_CAVE)
    assert VSD_CAVE >= ff.TOGGLE_CAVE_FOFF + BASE + len(recs[ff.TOGGLE_CAVE_FOFF]) and VSD_CAVE + len(vsd) <= TEXT_MAPPED_END, f"vsd {len(vsd):#x}"
    assert code[VSD_CAVE - BASE:TEXT_MAPPED_END - BASE] == bytes(TEXT_MAPPED_END - VSD_CAVE), "vsd cave not zero padding"
    recs[VSD_CAVE - BASE] = vsd
    recs[v["cb_vsync"] - BASE] = b_instr(v["cb_vsync"], VSD_CAVE, False)
    assert ff.STATE + 0x60 <= ff.DATA_END_MAPPED
    return ff.make_ips(list(recs.items())), cave, len(blob), L


def main():
    out = os.path.join(ff.ROOT, "patches", "skip")
    os.makedirs(out, exist_ok=True)
    for vname in ("v10", "v12"):
        for suf, on, vo in (("skip", False, False), ("skip_fpson", True, False), ("diag_vsynconly_fpson", True, True)):
            data, cave, n, L = build(vname, on, vo)
            name = f"60fps_{vname}_{suf}.ips"
            open(os.path.join(out, name), "wb").write(data)
            print(f"{name:28s} {len(data):5d} B sha256 {hashlib.sha256(data).hexdigest()}  cave {cave:#x}+{n:#x}")


if __name__ == "__main__":
    main()
