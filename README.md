# 60 FPS Patch - Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey (3DS)

**Double your framerate from 30 FPS to 60 FPS with a tiny 26-byte IPS patch.**

| | |
|---|---|
| **Game** | Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey |
| **Region** | USA |
| **Title ID** | 00040000001D1400 |
| **Patch Size** | 26 bytes |
| **Format** | IPS (code.bin patch) |

---

## What This Does

The game internally supports both 30 FPS and 60 FPS modes, controlled by a single byte in memory. By default, the game locks itself to 30 FPS. This patch modifies two instructions in the game code so the framerate check always returns "60 FPS mode," resulting in smooth 60 FPS gameplay.

Unlike cheat codes that continuously overwrite memory every 50ms, this patch modifies the game code itself -- it's cleaner, more reliable, and works without any cheat engine.

---

## Installation

### Luma3DS (Real 3DS / 2DS Hardware)

1. Download `60fps.ips` from the [patches](patches/) folder
2. On your SD card, create the folder path:
   ```
   SD:/luma/titles/00040000001D1400/
   ```
3. Copy `60fps.ips` into that folder and **rename it to `code.ips`**:
   ```
   SD:/luma/titles/00040000001D1400/code.ips
   ```
4. Make sure "Enable game patching" is turned on in Luma3DS config (hold SELECT on boot)
5. Launch the game -- the patch applies automatically

### Azahar / Lime3DS Emulator

1. Download `60fps.ips`
2. Place it at (create folders as needed):

   **Linux:**
   ```
   ~/.local/share/azahar-emu/load/mods/00040000001D1400/exefs/code.ips
   ```
   **Windows:**
   ```
   %APPDATA%/azahar-emu/load/mods/00040000001D1400/exefs/code.ips
   ```
   **macOS:**
   ```
   ~/Library/Application Support/azahar-emu/load/mods/00040000001D1400/exefs/code.ips
   ```
3. Launch the game -- the patch applies automatically

### Citra Emulator

1. Download `60fps.ips`
2. Place it at:

   **Linux:**
   ```
   ~/.local/share/citra-emu/load/mods/00040000001D1400/exefs/code.ips
   ```
   **Windows:**
   ```
   %APPDATA%/Citra/load/mods/00040000001D1400/exefs/code.ips
   ```
3. Launch the game -- the patch applies automatically

---

## Compatibility

| Platform | Status |
|----------|--------|
| New 3DS / New 2DS XL (Luma3DS) | Tested |
| Azahar / Lime3DS (Vulkan) | Tested |
| Azahar / Lime3DS (OpenGL) | Should work |
| Citra | Should work |
| Old 3DS / 2DS | May have performance issues at 60 FPS |

**Region:** USA (00040000001D1400). Other regions have different Title IDs and may need different patch offsets.

---

## Uninstalling

Delete the `code.ips` file from the mod folder and restart the game. No permanent changes are made to your game files.

---

## How It Works

The game stores a framerate control byte at offset `+0x3D` in a heap-allocated struct. A value of `0x01` means 30 FPS; `0x00` means 60 FPS. Two locations in `code.bin` read this byte every frame to decide the framerate.

This patch replaces both `LDRB` (Load Register Byte) instructions with `MOV #0`, so the game always sees "60 FPS mode":

| Offset | Original | Patched | Instruction Change |
|--------|----------|---------|-------------------|
| `0x03E918` | `E5D4103D` | `E3A01000` | `LDRB R1,[R4,#0x3D]` -> `MOV R1,#0` |
| `0x180A84` | `E5D4003D` | `E3A00000` | `LDRB R0,[R4,#0x3D]` -> `MOV R0,#0` |

Offsets are into the decompressed `code.bin`.

### Discovery Process

This patch was found through dynamic analysis by instrumenting the Lime3DS emulator:

1. **SVC instrumentation** revealed the game uses VBlank synchronization for frame timing
2. **Cheat engine instrumentation** showed the existing 60fps cheat only writes a single byte (`0x320DA3AD = 0x00`)
3. **Memory watchpoints** (with dynarmic fastmem disabled) identified the two game code locations that read the FPS control byte every frame
4. **Disassembly** of those locations revealed `LDRB` instructions loading from struct offset `+0x3D`
5. Replacing both with `MOV #0` forces 60 FPS permanently

36+ test ROMs were built and tested during the investigation. Full technical writeup: [FINAL_ANALYSIS.md](FINAL_ANALYSIS.md)

---

## Alternative: Cheat Code

If you prefer to use a cheat code instead (requires CTRPF or Luma3DS cheat engine):

**File:** `SD:/cheats/00040000001D1400.txt`

```
[60FPS v1.2]
D3000000 30000000
50000074 01000101
20000075 00000000
D0000000 00000000
520DA3AC 01000101
220DA3AD 00000000
D0000000 00000000
50000064 01000101
20000065 01000000
D0000000 00000000
50000044 01000101
20000045 00000000
D0000000 00000000
D2000000 00000000
```

Credit: @Shay from [60FPS-AR-CHEATS-3DS](https://github.com/Reshiban/60FPS-AR-CHEATS-3DS)

The IPS patch is recommended over the cheat code because it patches the game code directly rather than continuously overwriting memory at runtime.

---

## Credits

- **Patch by:** struktured + [Claude](https://claude.ai)
- **Original cheat research:** @Shay ([60FPS-AR-CHEATS-3DS](https://github.com/Reshiban/60FPS-AR-CHEATS-3DS))
- **Emulator:** [Azahar/Lime3DS](https://azahar-emu.org/) (used for dynamic analysis)

## License

MIT
