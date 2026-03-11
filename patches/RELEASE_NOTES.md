# Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey (3DS) — 60fps Patch

## Release: v1.0 (R-Toggle) | `60fps_v10_full_r.ips`
## Release: v1.2 (R-Toggle) | `60fps_v12_full_r.ips`

---

### Description

This IPS patch unlocks 60fps in Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey on Nintendo 3DS. The game normally runs at 30fps — this patch doubles the framerate for a dramatically smoother experience across the overworld, battles, and menus.

**R-Button Toggle:** Hold the R shoulder button to drop back to 30fps at will (useful for stability during scene transitions or particle-heavy battles), then release to return to 60fps. No other controls are affected.

The patch is a **standalone IPS file** — no LayeredFS, no homebrew required. Applies directly to the game ROM.

---

### Compatibility

| Variant | Game Version | File | Notes |
|---------|-------------|------|-------|
| USA v1.0 | v1.0 (no update applied) | `60fps_v10_full_r.ips` | Original cart / base CIA |
| USA v1.2 | v1.2 (update installed) | `60fps_v12_full_r.ips` | Nintendo eShop update |

**Tested with:** Azahar emulator (headless, llvmpipe), custom Lime3DS build
**Real hardware:** Compatible — uses only IPS patching, no emulator-specific features
**Region:** USA only (Title ID: 00040000001D1400). EUR/JPN not tested.

---

### Installation

#### For Emulator (Azahar / Citra / Lime3DS)

1. Determine your game version: check if you have the v1.2 update installed in your emulator's title manager.
2. Copy the matching `.ips` file:
   ```
   ~/.local/share/azahar-emu/load/mods/00040000001D1400/exefs/code.ips
   ```
   (Create the directory if it doesn't exist.)
3. Launch the game normally.

#### For Real 3DS Hardware (Luma3DS)

1. Place the `.ips` file on your SD card at:
   ```
   /luma/titles/00040000001D1400/code.ips
   ```
2. In Luma3DS settings, enable **"Enable game patching"**.
3. Launch the game from the HOME menu.

> **Note:** IPS patches apply to the **decompressed** ExeFS `code.bin`. Luma3DS handles decompression automatically. If using a custom patcher, ensure you decompress `code.bin` first.

---

### What's Patched

The game stores an FPS mode byte at struct offset `+0x3D`. A value of `0x01` = 30fps; `0x00` = 60fps. The game has a 4-level dynamic FPS setter that can write values 0–3 based on scene complexity, plus multiple read sites scattered across `code.bin`.

This patch:
1. **Code cave** (52 bytes at a verified-dead `.text` function): reads the R button state from the game's HID input global (`[*(0x3F71C0) + 0x61C28]`, bit 8). R held → write `1` (30fps); R released → write `0` (60fps).
2. **Main frame loop** BL → code cave (replaces `LDRB R1,[R4,#0x3D]`).
3. **Init-time reader** → `MOV R0,#0` (forces 60fps at startup).
4. **FPS setter writers** (3 sites) → `MOV R0,#0` (prevents dynamic 30fps downgrade during scene transitions and particle effects).
5. **Other readers** (4 sites) → `MOV Rx,#0` (render flag setters, FPS wrapper).
6. **Conditional writer** → NOP×2 (prevents stray 30fps write during state changes).

**Total:** 11 patch records, 159 bytes.

---

### Performance Results

Verified via automated headless testing (25+ second run, FPS CSV logging):

| Mode | Avg FPS | Min FPS | Max FPS |
|------|---------|---------|---------|
| Unpatched | ~29.9 | ~29.9 | ~29.9 |
| Patched (R released) | **59.88** | 59.82 | 59.94 |
| Patched (R held) | ~29.9 | ~29.9 | ~29.9 |

---

### Known Issues

- **QTE timing:** Quick-time events (key-hold prompts during battles) run on frame counters. At 60fps these timers tick 2x faster, so input windows are roughly half as wide. A separate QTE timing patch (`60fps_qte_v1.2.ips`) doubles these windows — not yet included in this release.
- **Giant battles (HugeBattle.cro):** The code.bin patch covers all FPS writes in the main binary. The `HugeBattle.cro` module (loaded for large enemy battles) has its own FPS byte writer. A CRO patch is available separately but is not bundled here (requires romfs modding, not IPS-only).
- **EUR/JPN regions:** Untested. The byte offsets differ from USA — do not use USA patches on other region ROMs.
- **Speed:** Game logic is fixed-step and tied to VBlank. At 60fps, the game runs at full 2× speed (walking, animations, timers all faster). This is expected behavior for a frame-rate unlock without delta-time compensation.

---

### Changelog

| Version | Date | Notes |
|---------|------|-------|
| v1.0-r | 2026-03-10 | R-toggle code cave; patches all FPS readers+writers in code.bin |
| v1.0 | 2026-03-08 | Full patch (no toggle); v3 comprehensive (9 sites) |
| v1.0 | 2026-03-07 | v2 enhanced (writer-side fix) |
| v1.0 | 2026-03-06 | v1 basic (2-site reader patch) |

---

### Credits

- **Patch author:** struktured (Struktured Labs)
- **Investigation method:** Memory watchpoints via dynarmic fastmem disable + cheat engine instrumentation → LDRB readers → IPS replacement
- **Tooling:** Custom Lime3DS/Azahar build with FPS CSV logging; automated headless verification
- **Thanks:** The wider 3DS homebrew community for Luma3DS and IPS patching infrastructure

---

*Generated 2026-03-10. Patch verified on Azahar emulator (USA v1.2).*
