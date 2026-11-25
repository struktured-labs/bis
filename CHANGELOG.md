# Changelog

## v1.2.3 (2026-11-24): tested on real 3DS hardware

- **Tested on a real 3DS** (Luma3DS, USA game 1.0): the game 1.0 R-toggle patch
  boots and runs with no crash. See [docs/HW_TEST_2026-11-24.md](docs/HW_TEST_2026-11-24.md).
  60fps / R toggle verified in Azahar; game 1.2 not yet run on hardware.
- Fixed: the v1.2.2 R-toggle code cave (`0x104810` on 1.2, `0x1047C8` on 1.0) sat
  on a live boot routine that waits for a worker thread to finish starting up,
  so the patch skipped that wait (an unsynchronised boot race that Azahar's
  scheduling hid). The cave now lives in unused zero padding at the end of
  `.text` (vaddr `0x389F00`), and the boot routine is untouched.
- Fixed (game 1.0): the patch no longer leaves the frame-rate byte `+0x3D`
  uninitialised. The constructor now stores 0 instead of nothing, so four
  unpatched readers no longer see leftover heap data (zero in emulators, not on
  hardware).
- Docs: standing rule, no emulator-only assumptions ([docs/REAL_HARDWARE_RULES.md](docs/REAL_HARDWARE_RULES.md));
  audit in [docs/REAL_HW_AUDIT_2026-11-24.md](docs/REAL_HW_AUDIT_2026-11-24.md);
  stronger "pick your game version" warning.
- Legacy always-60fps patches unchanged.

## v1.2.2 (2026-11-24)

- Fixed: v1.2.1 R-toggle crashed at boot on a real 3DS / 2DS. The cave now reads R
  through the game's HID object instead of the emulator-only address `0x1000201C`.
  The 1.0 cave was also moved off a live CloseHandle.

## v1.2.1

- Fixed: the R toggle did nothing on game 1.2 (issue #1). Added R-toggle patches
  for 1.0 and 1.2; original always-60fps patch moved to legacy, 1.2 version added.

## v1.0

- Original always-60fps `code.ips` (game 1.0 offsets only).
