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

Battle FPS counter: the game's second top-screen present call
(v1.0 0x287F94 / v1.2 0x2880C8, same nngx framebuffer setter) also goes
through the counter cave.
"""
import hashlib, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_60fps_ff as ff  # noqa: E402

BASE = ff.BASE
SKIP = {
    "v10": dict(ffc=0x31EFD4, rchk1=0x31F028, spd=0x31F074, rchk2=0x31F14C,
                msg_bl=0x20EF10, msg_fn=0x132834, fb2_call=0x287F94),
    "v12": dict(ffc=0x31F108, rchk1=0x31F15C, spd=0x31F1A8, rchk2=0x31F280,
                msg_bl=0x20EEE8, msg_fn=0x132804, fb2_call=0x2880C8),
}
FF_SPEED_GLOBAL = 0x413C80          # game's fast-forward scale (2.0), same VA in 1.0 and 1.2
TURBO = 0x40800000                  # 4.0f
SKIP_MAGIC = 0x534B5031             # 'SKP1' at STATE+0x2C
S = ff.STATE
ENTRIES = ("cave_ffc", "rs_r3", "rs_r1", "spd", "cave_msg")


def skip_src(s):
    return f"""
cave_ffc:
    push  {{r0-r5, r12, lr}}
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
ffc_go:
    mov   r5, #0
    mov   r3, #0
    ldr   r1, [r0]
    cmp   r1, #0
    beq   ffc_store
    add   r2, r1, #0x1000
    ldr   r2, [r2, #0xB00]
    cmp   r2, #0
    beq   ffc_store
    ldr   r3, [r2]
    ldrb  r12, [r0, #5]
    cmp   r12, #0
    beq   ffc_store
    ldrb  r12, [r0, #6]
    cmp   r12, #0
    bne   ffc_store
    tst   r3, #8
    movne r5, #1
ffc_store:
    ldr   r2, [r4, #0x20]
    str   r5, [r4, #0x20]
    str   r5, [r4, #0x1C]
    str   r5, [r4, #0x24]
    mov   r12, #0
    cmp   r5, #0
    beq   ffc_t
    tst   r3, #0x200
    moveq r12, #1
ffc_t:
    str   r12, [r4, #0x28]
    cmp   r2, r5
    beq   ffc_out
    ldrb  r12, [r0, #4]
    cmp   r12, #0
    bne   ffc_out
    tst   r3, #0x108
    movne r12, #1
    strbne r12, [r0, #4]
ffc_out:
    pop   {{r0-r5, r12, lr}}
    push  {{r4-r10, lr}}
    b     #0x{s['ffc'] + 4:x}

rs_r3:
    orr   r3, r1, r1, lsl #5
    and   r3, r6, r3, lsr #8
    bx    lr

rs_r1:
    orr   r1, r1, r1, lsl #5
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
"""


def bl_target(code, va):
    w = struct.unpack_from("<I", code, va - BASE)[0]
    assert w >> 24 == 0xEB, hex(va)
    return va + 8 + ((((w & 0xFFFFFF) ^ 0x800000) - 0x800000) * 4)


def b_instr(src, dst, link):
    off = ((dst - (src + 8)) >> 2) & 0xFFFFFF
    return struct.pack("<I", (0xEB if link else 0xEA) << 24 | off)


def build(vname, default_on):
    v, s = ff.VERSIONS[vname], SKIP[vname]
    code = open(v["code_bin"], "rb").read()
    word = lambda va: struct.unpack_from("<I", code, va - BASE)[0]
    recs = dict(ff.parse_ips(ff.build(vname, True, default_on=default_on)))
    counter = recs[ff.FPS_CAVE - BASE]
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
    assert bl_target(code, s["fb2_call"]) == v["fb_set"], "second top-screen present call"
    for va in (s["ffc"], s["rchk1"], s["spd"], s["rchk2"], s["msg_bl"], s["fb2_call"]):
        assert va - BASE not in recs, hex(va)

    cave = (ff.FPS_CAVE + len(counter) + 0x1F) & ~0x1F
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
    assert cave + len(blob) <= ff.FPS_CAVE_END, f"skip cave too big {len(blob):#x}"
    assert code[cave - BASE:cave - BASE + len(blob)] == bytes(len(blob)), "cave not zero padding"
    recs[cave - BASE] = blob
    recs[s["ffc"] - BASE] = b_instr(s["ffc"], cave + L["cave_ffc"], False)
    recs[s["rchk1"] - BASE] = b_instr(s["rchk1"], cave + L["rs_r3"], True)
    recs[s["rchk2"] - BASE] = b_instr(s["rchk2"], cave + L["rs_r1"], True)
    recs[s["spd"] - BASE] = b_instr(s["spd"], cave + L["spd"], True)
    recs[s["msg_bl"] - BASE] = b_instr(s["msg_bl"], cave + L["cave_msg"], True)
    recs[s["fb2_call"] - BASE] = b_instr(s["fb2_call"], ff.FPS_CAVE + 32, True)
    assert ff.STATE + 0x30 <= ff.DATA_END_MAPPED
    return ff.make_ips(list(recs.items())), cave, len(blob), L


def main():
    out = os.path.join(ff.ROOT, "patches", "skip")
    os.makedirs(out, exist_ok=True)
    for vname in ("v10", "v12"):
        for suf, on in (("skip", False), ("skip_fpson", True)):
            data, cave, n, L = build(vname, on)
            name = f"60fps_{vname}_{suf}.ips"
            open(os.path.join(out, name), "wb").write(data)
            print(f"{name:28s} {len(data):5d} B sha256 {hashlib.sha256(data).hexdigest()}  cave {cave:#x}+{n:#x}")


if __name__ == "__main__":
    main()
