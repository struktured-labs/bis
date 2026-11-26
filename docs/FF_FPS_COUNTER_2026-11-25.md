# v1.2.4 candidate: R fast-forward back, 30fps on L, in-game FPS counter (2026-11-25)

Branch `feature/ff-fps-counter`. Generator: `build/gen_60fps_ff.py`.
Outputs: `patches/ff/` (one set per game version; never cross-install).

| file | what |
|------|------|
| `60fps_v10_ff.ips` / `60fps_v12_ff.ips` | release candidate: 60fps, hold **L** = 30fps, **R** = game's own fast-forward, FPS counter built in but **off** until toggled |
| `60fps_v1X_ff_fpson.ips` | same code, counter **on** at boot (hardware test build) |
| `60fps_v1X_ff_nocounter.ips` | fallback: shipped v1.2.3 with only the R -> L change |

## Controls

- Hold **R** in a cutscene: the game's fast-forward (the `>> R` icon), now at 60fps.
- Hold **L**: 30fps for as long as it is held (was R in v1.2.1 - v1.2.3).
- Hold **L** and press **SELECT**: FPS counter on/off (two digits, top-left of the top screen).

## Why R did not "work"

The R-toggle cave forced 30fps whenever R was held. In headless stock Azahar
the game's fast-forward still ran underneath (cutscene reached the next scene
in ~7.4 s with R vs ~14.5 s without, v1.2.3 included), but at 30fps. Cutscene
timing is not frame-locked (stock 30fps and patched 60fps play the same
cutscene in the same wall time), so the only effect of the old mapping was a
choppy 30fps fast-forward. On hardware Carmelo saw no speed-up; R held there
was during dialogue, which fast-forward does not auto-advance in stock
either, so it is not certain the hardware behaved differently. The fix
removes the patch from R completely: holding R is now exactly the stock
game's behaviour, at 60fps.

Tradeoff: the 30fps hold moves to L. L may have a game function in some screens;
holding it for 30fps is the same kind of overlap R had. SELECT is otherwise
rarely used, and the counter toggle needs L held, so a stray SELECT press
does nothing.

## How the counter measures (valid on hardware)

- VSync count: hook at the entry of `ad::fw::TaskBase::callbackVSync`, the
  game's own nngx VSync callback; +1 per top-screen VSync (display 0x400).
- Frame count: hook on the game's BL to the nngx framebuffer setter for the
  top screen (v1.0 `0x105758 -> 0x112C30`, v1.2 `0x1057A0 -> 0x112D5C`):
  +1 per frame handed to GSP for display.
- Every >= 60 VSyncs: fps = round(frames * 60 / vsyncs), clamped to 99.
- Drawing: into the frame the game is about to display, using the address,
  column stride (width x bytes-per-pixel) and pixel format the game passes
  to the setter (RGB8 / RGBA8 / 16-bit handled). Then the touched columns
  are flushed from the CPU data cache with the game's own
  `FlushDataCache(addr,size)` wrapper (v1.0 `0x1225A8`, v1.2 `0x122578`,
  GSP command 0x00080082). The display buffers are in FCRAM (linear heap,
  cached on hardware); without the flush the digits could show only in an
  emulator.
- So the number is what the LCD is actually being fed, per real VSync. It
  is not an emulator statistic.

## REAL_HARDWARE_RULES self-audit

- **Addresses:** only the game's own segments. Caves in end-of-`.text`
  zero padding (`0x389A00`-`0x389C9x` counter, `0x389F00` toggle; text ends
  `0x3890E8` / `0x389218`; asserted zero in the generator). Counter state at
  `0x435E00`, in `.bss` tail padding (exheader data `0x3F0000+0x9170`, bss
  `0x3CBD0` -> ends `0x435D40`; segment mapped to `0x436000`). Pad read via
  the game's HID object pointer `*(*(0x42A6C0+4)+0x1C)`. No `0x1000xxxx`,
  `0x1FFxxxxx`, VRAM or config-page constants.
- **Initialized state:** the `.bss` tail is not assumed zero (hardware heap
  and page tails may not be): a magic word (`'FPS2'`) gates init of all
  counters and the on/off flag.
- **Null checks:** HID pointer null -> pad treated as 0. Framebuffer
  pointer null -> no draw. Right-eye buffer drawn only if non-null and
  different from the left (3D on).
- **Cave placement:** `callbackVSync` is preceded by `BX LR; NOP` (no
  fall-through); its first instruction `PUSH {R4,LR}` is replaced by a `B`
  to the cave, which re-executes it and branches to entry+4. The setter
  call is a plain `BL` swapped for `BL cave`; the cave tail-branches to the
  original setter with all registers and the stack argument unchanged.
- **Timing/threads:** nothing waits or removes a wait. The VSync counter
  has one writer (VSync thread) and one reader (main thread), aligned word
  access. No sync primitives touched.
- **No runtime `.text` writes, no new `svc`:** the only IPC is the game's
  existing FlushDataCache wrapper, called on the main thread at a call
  boundary (no IPC in flight on that thread). Counter off -> no IPC at all.
- **ABI:** caves save every register they clobber (`PUSH {R0-R12,LR}` =
  56 bytes, keeps 8-byte alignment), word loads/stores aligned, byte stores
  only into the framebuffer; flags clobbered only where the caller does not
  read them (function entry / before `POP {..,PC}`).
- **Version split:** separate files for game 1.0 and 1.2; every hook site is
  checked against the original code.bin bytes before the patch is written.

## Verification (stock Azahar 2126.2, headless, private Xvfb, WAYLAND_DISPLAY unset)

New game -> opening cutscene (`>> R` icon), frames captured every ~0.34 s,
Azahar's App FPS read from the status bar, counter digits cropped from the
same frames. Evidence: `/workspace/bis_hwtest_ff/evidence/`.

Not tested on a real 3DS yet.

Results with the final IPS files (hashes below), both game versions:

| check | 1.0 | 1.2 |
|---|---|---|
| R held in opening cutscene: Azahar App FPS | 60 (59-61) | 60 (59-60) |
| R held: in-game counter | 60 | 60 |
| scene-change dip after start, R held (FF) | 8.9 s | 8.5 s |
| scene-change dip after start, no input | 15.7 s | 15.7 s |
| idle: App FPS / counter | 60 / 60 | 60 / 60 |
| L held: App FPS / counter | 30 / 30 (after ~1 s ramp) | 30 / 30 |
| RELEASE build at boot | no counter | no counter |
| L+SELECT x3 at title (RELEASE) | on / off / on | on / off / on |
| TEST (`_fpson`) build at boot, then L+SELECT x3 | on, off / on / off | on, off / on / off |
| L+SELECT during cutscene | toggles, no menu / side effect | same |

(The old 30fps-on-R builds, v1.2.3 included, also fast-forwarded in Azahar
at ~2x, but at 30fps.)

Hashes (sha256):

```
804489d1dc7ad474d457978c6d93fe5080c4fce1e247ba9e310f9f5ea38d7a85  60fps_v10_ff.ips (844 B)
200eb2386fb45d8aa759819106cf0fc291d87a2391021833037a1d394e666c80  60fps_v10_ff_fpson.ips (844 B)
0c9209dbfef3e3769d34ea54aeb0b424aed51e50abe85b2274788fd1e467df50  60fps_v10_ff_nocounter.ips (133 B)
25fe84a2c38be0216b85ba4fceca3c290531354a70233d5c0acfc4ee46abbed1  60fps_v12_ff.ips (862 B)
1a906442ed79f15e901796b88ae93ba4e412b11fa66092649b034aa3e4e995f7  60fps_v12_ff_fpson.ips (862 B)
7369bf53aaa4ac08fb3fd196d869614d8bdd1498b9d13bf3f687dec78e3ad853  60fps_v12_ff_nocounter.ips (151 B)
```

### Unverified / risks for the hardware test

- Cache flush: emulators ignore the data cache; only hardware shows whether
  the flushed range is enough (symptom if not: missing/partial digits).
- The counter draws when the frame is handed to the setter; if the GPU
  display transfer for that buffer is still running on hardware, digits
  could flicker. Worst case is cosmetic.
- L may have an in-game function on some screens (holding it = 30fps there).
- Carmelo's "R doesn't fast-forward" on hardware was likely the dialogue
  case (stock FF doesn't advance dialogue); re-check in an animated stretch.
- Counter in battles and the bottom screen are not measured (top screen only).

Hardware checklist: `/workspace/bis_hwtest_ff/README_HW_CHECKLIST.md`.
