# v1.2.2 - fix boot crash on real 3DS / 2DS

## Fix
v1.2.1's R-toggle patches (`60fps_v12_full_r.ips`, `60fps_v10_full_r.ips`) crashed immediately at boot on a real New 2DS XL with Luma game patching (GameBanana post 14144835). The 1.0 patch on an un-updated 1.0 game was reported as working by that user.

Root cause: both caves loaded the R button from the hardcoded address `0x1000201C`. Citra/Azahar map HID shared memory there when the game calls `svcMapMemoryBlock` with `addr=0`. A real 3DS does not — the kernel picks a different VA, and `0x1000201C` is unmapped, so the first main-loop read data-aborts. This matches an earlier Remillio crash dump (commit `96050f7`) on the v1.0 HID cave.

The caves now read the shared-memory base from the game's HID object at `0x42A6C0+4` (same BSS address in 1.0 and 1.2) and the current pad at `+0x1C`, with a null check. The v1.0 cave was also moved off a live `CloseHandle` at `0x10378C` (that was a shutdown crash) to the unused wait-loop at `0x1047C8`, matching how the 1.2 cave already sat at `0x104810`.

The IPS files are otherwise the same as v1.2.1 (standard PATCH/EOF, no IPS32, all records inside the 0x2FA000 code.bin). Luma still wants the file at `SD:/luma/titles/00040000001D1400/code.ips` — the BASE title ID, even when the 1.2 update is installed. Putting it under `0004000E...` would skip the patch, not crash.

## Verified
Stock Azahar 2126.2, FPS from the emulator's own "App: N FPS" counter, R held with xdotool, emulation speed 100%:

| Patch | Game | R released | R held | R released again |
|---|---|---|---|---|
| `60fps_v12_full_r.ips` | USA 1.2 | 60 | 30 | 60 |
| `60fps_v10_full_r.ips` | USA 1.0 | 60 | 30 | 60 |

The hardware abort cannot be reproduced in Azahar, because HID *is* mapped at `0x1000201C` there. Real hardware is still untested.

## EUR
EUR game 1.2 (00040000001D1500): the 1.2 patch is byte-identical at every patched spot, including the HID object and the cave. Use folder `00040000001D1500`. Not run. EUR 1.0 is unchecked.

SHA-256:
- `60fps_v12_full_r.ips` b0c4032747264c2b831afba7150374c309695471b60c20e850f07dc0b55c483d
- `60fps_v10_full_r.ips` a950770b13513158e3f2b6a5233eebaa8a6d23e699cb00dae43d94c4776f2511
