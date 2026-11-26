# Cutscene skip (hold START) + battle FPS-counter fix — 2026-11-25

Branch `feature/cutscene-skip` (based on `08fb883`, the v1.2.4 candidate).
Generator: `build/gen_60fps_skip.py` (imports `gen_60fps_ff.py`; same shipped
v1.2.3 base IPS, byte-checked). Outputs in `patches/skip/`. Game 1.0 and game
1.2 get separate files; never cross-install.

| File | Use |
|---|---|
| `60fps_v10_skip.ips` / `60fps_v12_skip.ips` | RELEASE: 60fps, R = stock FF, L = 30fps hold, L+SELECT counter (off at boot), hold START = cutscene skip |
| `60fps_v1X_skip_fpson.ips` | TEST: identical code, counter on at boot |
| `60fps_v1X_diag_vsynconly_fpson.ips` | DIAGNOSTIC ONLY (hardware): counter drawn *only* from the VSync redraw, no present-time draw. Shows nothing in Azahar by design (see below). |

## Controls

| Input | Effect |
|---|---|
| R | stock cutscene fast-forward (unchanged from v1.2.4 candidate) |
| hold L | 30fps |
| hold L + press SELECT | FPS counter on/off |
| **hold START** (during a cutscene that shows the `>> R` prompt) | turbo skip: fast-forward at 2x the stock FF rate + auto-advance of dialogue pages |

### Why START
* The game ignores START during cutscenes (field events lock menus), so no
  stock function is lost; outside cutscenes the skip is inert (the game's own
  FF "allowed" flag is 0 in free roam, verified with gdb: `allow=0`, skip/turbo
  state 0), so START keeps its normal meaning there.
* No overlap with R (FF), L (30fps) or L+SELECT (counter). START + L =
  skip at the stock 2.0 FF scale (L disables the turbo multiplier).

## How the skip works ("turbo skip", not a jump)

Found by RE of the field event / message system (v1.0 addresses, v1.2 in the
generator):

* fld fast-forward controller `0x31EFD4` (object: +4 state 0=on/1=off,
  +5 allowed (set by the running event), +6 disable). R is tested at
  `0x31F028` and `0x31F14C` as `and rX,r6,r1,lsr#8` on the field pad word.
* When FF turns on the controller loads the scale from the game's global
  `0x413C80` (2.0) at `0x31F074`.
* Message-window manager `*(main+0x1b30)`: windows at `*(p+0x483c4)`, count at
  `+0x42adc`, stride `0x6D60`, active ptr `+0x2dc44`, flags `+0x2dd18`
  (2 = page waiting for a button, 4 = choice selection open). `p+0x48384` is
  the one-shot injected input word the stock FF already uses.

The patch:
1. `cave_ffc` (controller entry): if allowed && !disabled && START held →
   skip active; START is treated as R by the two R tests (`rs_r3`/`rs_r1`),
   so the game itself toggles FF exactly as with R.
2. `spd` (scale load): 4.0 instead of 2.0 while skip active and L not held.
   At 60fps a 4.0 scale equals the per-frame step the stock game uses for R
   FF at 30fps (`0x3FD018` step: 1 normal / 2 FF / 4 turbo; stock 30fps FF is
   4) — no step the stock game never produces.
3. `cave_msg` (right before the game's message-window update at `0x20EF10`):
   one-frame A via `p+0x48384`, only if some window has flag 2 **and no window
   has flag 4**. Choice prompts are never answered; battles and battle
   tutorials run other code (the field FF controller is not called in battle).

Every script command still runs in order, so flags, variables, party,
positions, music and map loads are produced by the game itself.
**A true jump-to-end is not feasible**: there is no per-cutscene end-state
table; the end state only exists as the result of executing the script
(flag writes, actor moves, BGM/map commands interleaved with waits). Turbo
skip is the safe alternative.

## Battle FPS counter fix

Report: counter fine on hardware in field/cutscenes and through the battle
intro (capture `/workspace/bis_hw_capture/ANALYSIS.md`: badge on all 4447
frames incl. the battle-intro pan), but it disappears once in combat
(fighters + command UI).

Findings:
* Only two calls to the nngx framebuffer setter (`0x112C30`) exist (Ghidra
  xrefs): `0x105758` (inside `FUN_00105568`, every top-screen present —
  already hooked) and `0x287F94` (inside `FUN_00287EDC`, which calls
  `FUN_00105568` then sets **0x401**, the bottom screen). gdb in field and in
  battle: `0x105758` always `r0=0x400`, `0x287F94` always `r0=0x401`. So
  battles have no separate top-screen present path; the earlier WIP "fb2"
  hook was a no-op and is removed.
* Same buffers in field and battle (`0x32B50490` / `0x32C28490`, fmt 0x8051).
  Not reproducible in Azahar even with 3D slider 100 + simulate 3DS GPU
  timings (`docs/img_skip/battle_counter_stereo3d_gputimings_old.png`).
* The setter only writes the GSP framebuffer info (applied at the next
  VBlank). The game does not have to wait for its GPU display transfer into
  that buffer before calling it — only before VBlank. When the GPU is busy
  (combat scene), the transfer lands **after** the counter was drawn at
  present time and erases it. Azahar executes command lists synchronously, so
  it can never show this. This matches the capture (fine while GPU-light,
  gone once the full battle scene renders).

Fix (combined build):
* Present-time draw kept (it is what works in field on hardware).
* The counter cave records the buffers the game hands to the setter
  (current + previous L/R, stride, bpp, VSync count at present) in its state
  block (`0x435E30..0x435E53`, magic `FBV1` at `+0x50`, zeroed on first use).
* The game's own top-screen VSync callback (`0x13DA58`, `cmp r1,#0x400`)
  is redirected to `vs_draw` (`0x389F40`, end-of-.text padding after the
  toggle cave; asserted zero and below the mapped end `0x38A000`), which does
  the same VSync count as before, then — only if the counter is on and the
  record is valid — redraws the digits into the current buffer (if presented
  ≤3 VSyncs ago) and the previous buffer (≤6 VSyncs ago), each flushed with
  the game's own GSP FlushDataCache wrapper (`0x1225A8`, plain svc 0x32 IPC
  on the calling thread's TLS buffer — thread safe). At VBlank the buffer
  being shown has finished its transfer, so the redraw sticks.
* The badge moves to the **top-right** (x=373): the top LCD scans from the
  left edge, so a VSync-time redraw at the right edge lands ~15 ms before
  the scan reaches it.
* Verified with gdb (diag build): `vs_draw` runs on the game's VSync thread,
  record values correct (`cur=32b50490 prev=32c28490`, ages 2/3), glyph bytes
  written into the buffer. Field + battle + attack turn + L+SELECT off/on in
  battle all fine with the normal build, v1.0 and v1.2, test and release.

## REAL_HARDWARE_RULES self-audit
* No hardcoded HID/IO/shared-memory VAs. Pads: field pad via the game's own
  `main+0x1b00` pointer (null-checked); counter pad via `*(*(0x42A6C0+4)+0x1C)`
  (null-checked). Framebuffer addresses come only from the game's own setter
  arguments.
* All new state in the zero padding after .bss inside the game's data segment
  (`0x435E00..0x435E53` < `0x436000`), gated by magics (`FPS2`, `SKP1`,
  `FBV1`); never assumed zero.
* Caves only in end-of-.text zero padding (asserted zero in the original
  code.bin): `0x389A00` counter, `0x389D20` skip (+0x1C8), `0x389F40` vsd (+0xC0).
* Every hook site's original bytes asserted against the original code.bin
  (FF controller entry/+0xC, both R tests + pad-pointer loads, scale load +
  its literal, msg-window BL target + preceding `mov r0,r5`, VSync callback
  `push {r4,lr}; cmp r1,#0x400`, setter call target).
* No new SVCs (flush uses the game's own wrapper), no runtime .text writes,
  registers saved/restored around every cave.
* Stale-pointer guard: VSync redraw only touches buffers the game presented
  within the last 3/6 VSyncs. The game's display buffers are fixed for its
  lifetime (same addresses in new-game and save-loaded sessions, field and
  battle, 1.0 and 1.2).

## Evidence (stock Azahar, headless private Xvfb, gdb stub)

| Test | Result |
|---|---|
| Opening cutscene → control (v1.0) | watched 296 s, R FF 146 s, START 58 s; v1.2 START 58 s |
| Opening: story store `0x3FA5F0–0x3FD000` | identical W / R / S (1.0) and S (1.2); identical end frames, positions, HP 30/24 (`opening_end_compare.png`) |
| Late-game Dark Bowser pre-battle cutscene → battle start (Checkpoint save) | watched 117 s, START 22 s (1.0) / 24 s (1.2) |
| Dark Bowser: story store | 0 differing words 1.0 S vs W; 1.2 vs 1.0 only `0x3FCFC0` (heap pointer, 0x0806xxxx) |
| End frames | same battle command menu, HP 380 / 140 (`darkbowser_end_compare.png`) |
| Skip stops at the battle | yes; battle commands still need input; attack turn plays normally |
| START in free roam | inert (`allow=0`, skip state 0); no menu, no movement change |
| Counter in battle | visible, v1.0 + v1.2, test + release (after L+SELECT); toggle works in battle |
| 3D slider 100 + GPU timings | counter on both eyes, field + battle |

Not verified: a choice prompt *inside* a FF-allowed cutscene (none in the
tested cutscenes; protected by the flag-4 gate), a full mid-game story
sweep, music beyond "commands run in order", and — most importantly — the
battle counter fix on real hardware (cannot be shown in Azahar; see the
diag build).

## Risks
* Battle-counter fix is a reasoned fix for a hardware-only race; needs the
  hardware checklist. Possible residual: a one-frame flicker if the redraw
  races scanout; small 1–10 px stale-pixel fringe at the badge edge from
  cache-line write-back (cosmetic only).
* Counter badge position changed (top-left → top-right) in the combined build.
* Turbo skip runs cutscenes at the stock 30fps-FF step size; cutscenes with
  timing-sensitive script waits behave as under stock R FF at 30fps.
* A cutscene that sets FF allowed during an input-required tutorial would
  auto-advance plain pages (never choices); none seen.
