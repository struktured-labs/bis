## Tested on real 3DS hardware

v1.2.3's R-toggle patch for **game 1.0** was run on a real 3DS (Luma3DS, USA game 1.0, no update): it **boots and runs with no crash**, through the opening cutscene and the first battle.

- Video (38 s): [bis_v1.2.3_real_3ds_game1.0.mp4](https://github.com/struktured-labs/bis/releases/download/v1.2.3/bis_v1.2.3_real_3ds_game1.0.mp4)
- Still: [bis_v1.2.3_real_3ds_game1.0_still.jpg](https://github.com/struktured-labs/bis/releases/download/v1.2.3/bis_v1.2.3_real_3ds_game1.0_still.jpg)
- Test notes: [docs/HW_TEST_2026-11-24.md](https://github.com/struktured-labs/bis/blob/v1.2.3/docs/HW_TEST_2026-11-24.md)

**Scope, honestly:** on hardware, game 1.0 boot and play are confirmed. The 60fps / hold-R-for-30fps toggle is verified in stock Azahar 2126.2 (the phone video is 30fps, so it can't show the frame rate). **Game 1.2 has not been run on real hardware yet**; please report back if you try it.

> **Pick the folder that matches your game version.** Title screen shows "Ver. 1.2" (FBI lists the update title) = `game_v1.2/`; no label (FBI shows Version 0 and no update title) = `game_v1.0/`. **The wrong one crashes at boot.** (That is exactly what happened on our first hardware attempt: a 1.2 patch on a 1.0 game.)

## Fixes

- **Boot-sync fix (all R-toggle patches).** The v1.2.2 code cave (`0x104810` on 1.2, `0x1047C8` on 1.0) was not dead code: it was the body of a boot routine that waits for a worker thread to finish starting up. The patch made it return at once, skipping the wait, an unsynchronised boot race that Azahar's scheduling happened to hide. The cave now lives in unused zero padding at the end of `.text` (vaddr `0x389F00`), and the boot routine runs as stock (confirmed with a gdbstub trace).
- **Game 1.0 uninitialised-byte fix.** v1.0 NOPed the constructor store of the frame-rate byte `+0x3D`, so four unpatched readers saw leftover heap data (usually zero in emulators, not on hardware). It now stores 0.
- Still includes v1.2.2's fix: R is read through the game's own HID object, not the emulator-only address `0x1000201C`.
- New standing rule for this repo: no hardcoded addresses or emulator-only behaviour ([REAL_HARDWARE_RULES.md](https://github.com/struktured-labs/bis/blob/v1.2.3/docs/REAL_HARDWARE_RULES.md)).

## Install (Luma3DS)

Copy `game_v1.0/60fps_v10_full_r.ips` or `game_v1.2/60fps_v12_full_r.ips` to `SD:/luma/titles/00040000001D1400/code.ips` (base title ID even with the 1.2 update; ftpd works, no SD swap), enable "Enable game patching" in Luma config (hold SELECT at boot), launch. Hold R for 30fps. Full steps in the zip's README.txt.

## Known issues

- R is also the game's own hold-to-fast-forward button for cutscenes. With the R-toggle patches, holding R gives 30fps instead, so the built-in fast-forward doesn't kick in (seen in the hardware video; same since v1.2.1).
- Game logic is tied to frame rate, so at 60fps the game runs faster; hold R for timing-sensitive moments.
- Giant battles may stay at 30fps. Old 3DS / 2DS will slow down at 60fps.

Thanks to ChaoticDubz for the hardware crash report.
