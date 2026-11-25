# Contributing

## Standing rule: real hardware first

Never hardcode memory addresses or rely on behavior that only holds in
Azahar or any other emulator. Read state the way the game or the OS does,
e.g. the R button via the game's HID object `*(*(0x42A6C0 + 4) + 0x1C)`,
not the emulator-only `0x1000201C` (the v1.2.1 real-3DS boot crash).
Anything that depends on emulator-only state is an antipattern.

Full rule, the cautionary example, and the per-patch checklist:
[docs/REAL_HARDWARE_RULES.md](docs/REAL_HARDWARE_RULES.md).

## Other project rules

- Python via `uv` only.
- Test headless in stock Azahar on a private Xvfb display with
  `WAYLAND_DISPLAY` unset and `SDL_AUDIODRIVER=dummy`. Automate tests; don't
  ask people to test by hand.
- Build IPS files from the generators in `build/` (`gen_60fps_*.py`), not
  by hand-editing.
