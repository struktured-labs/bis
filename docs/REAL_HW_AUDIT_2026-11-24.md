# Real-hardware audit of v1.2.2 and v1.3.0 IPS patches (2026-11-24)

Scope: every record in `game_v1.0/60fps_v10_full_r.ips`,
`game_v1.2/60fps_v12_full_r.ips`, `legacy_always_60fps/*` (v1.2.2), and
`60fps_v10_auto.ips` / `60fps_v12_auto.ips` (v1.3.0, held). Method:
capstone disassembly of each record before and after patching, a whole-
`.text` xref scan (B/BL targets and literal pools), and Azahar gdbstub
traces. Rule being checked: [REAL_HARDWARE_RULES.md](REAL_HARDWARE_RULES.md).

## Finding 1 (HIGH, timing/emulator-only): the cave overwrote a live boot routine

- The v1.2 cave at `0x104810` and the v1.0 cave at `0x1047C8` were
  described as "unreferenced wait-loops". They are not. The routine starts
  one instruction earlier, at `0x10480C` (v1.2) / `0x1047C4` (v1.0), with
  `LDR R0,=0x3FD670`, then falls through into the `PUSH`. It is called once
  at boot by `BL` from `0x101A24`.
- What the original does: calls `0x108974(0x3FD670)`, then loops
  `svcSleepThread(5 ms)` until worker thread 5 sets byte
  `[0x42A818+0x29C]`.
- What the patched cave does: returns at once. It skips that call and the
  wait.
- gdbstub, stock v1.2: on return to `0x101A28` the flag is 1.
- gdbstub, v1.2.2: on return to `0x101A28` the flag is 0, and the
  `0x108974` call from `0x104818` is missing.
- Azahar's scheduling happens to let boot continue anyway. On hardware,
  this is an unsynchronised race at boot.
- Fix: the cave moves to the zero padding of the last `.text` page, vaddr
  `0x389F00`. `.text` ends at `0x389218` and is mapped as 650 RX pages to
  `0x38A000`. Luma's IPS loader patches up to the full mapped code size.
  The boot routine is left untouched.

## Finding 2 (MEDIUM on v1.0 only, uninitialised memory)

- v1.0 NOPed the constructor store `STRB R0,[R4,#0x3D]` at `0x24B474`
  (which writes 0xFF), along with every other writer.
- Four v1.0 readers are not patched: `0x112A28`, `0x112B84`, `0x36311C`
  (getter), and `0x36BFE4`. They read heap garbage.
- Emulator heap is usually zero, but hardware heap is not.
- Fix: store R5 instead (R5 = 0 since `0x24B454`).

## Checked, no issue

- **HID read:** `*(*(0x42A6C0+4)+0x1C)` with a null check.
  - `0x42A6C0` is in `.bss`, which is zero at load.
  - +4 is the PAD pointer the game stored after `svcMapMemoryBlock`.
  - +0x1C is the current PAD state, word-aligned.
- **Cave ABI:**
  - Saves R2 and LR.
  - SP stays 8-byte aligned.
  - Flags are clobbered, but the caller re-sets them (`CMP R1,#2` at
    `0x13E8F4`) before any conditional.
  - R0 is preserved, and the caller pushes LR.
- **v1.3.0 auto `LDR R2,[R4]`:** R4 has already been dereferenced by the
  caller.
- **Other code:**
  - No SVCs, no runtime `.text` writes, and no self-modifying code.
  - No absolute IO/shared-memory/config addresses.
- **Plain instruction swaps:** the setter MOVs, the reader MOVs, the
  `0x1828D8` NOPs, and the legacy always-60 records are plain swaps with
  no emulator dependence.

## Verification (stock Azahar 2126.2, private Xvfb, WAYLAND_DISPLAY unset)

| build | boot | 60fps | R held -> 30 | R released -> 60 |
|-------|------|-------|--------------|------------------|
| v1.2 full_r (fixed) | yes | yes | yes (x2) | yes |
| v1.0 full_r (fixed) | yes | yes | yes (x2) | yes |
| v1.2 auto (fixed, v1.3.0 branch) | yes | yes | yes (x2) | yes |
| v1.0 auto (fixed, v1.3.0 branch) | yes | yes | yes (x2) | yes |

The gdbstub trace on the fixed v1.2 build matches stock:
`0x108974(0x3FD670)` is called from `0x104818`, and the flag is 1 on
return.

None of this has been tested on a real 3DS yet.
