# Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey - 60fps Patch

Work-in-progress project to create a permanent ROM patch for 60fps gameplay.

## Status

**⚠️ EXPERIMENTAL - Patches are untested and may not work!**

Currently, 60fps for this game is only achievable via runtime cheat codes (CTRPF).
This project aims to create a permanent IPS patch for the game's code.bin.

## Available Patches

| Patch | Description | Status |
|-------|-------------|--------|
| `patches/60fps_v2.ips` | Patches 0x01010101 patterns | Untested |
| `build/60fps.ips` | Initial attempt | Crashed |

## How to Apply Patches

### Method 1: LayeredFS (Recommended for Emulators)

For **Citra/Lime3DS/Azahar**:

1. Create the mods directory:
   ```bash
   mkdir -p ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/exefs/
   ```

2. Copy the IPS patch:
   ```bash
   cp patches/60fps_v2.ips ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/exefs/code.ips
   ```

3. Launch the game normally.

**Note**: The title ID `00040000001D1400` is for the USA version.
For EUR version, use `00040000001D1500`.

### Method 2: Direct ROM Patching

1. Extract the game's ExeFS using a tool like `3dstool`:
   ```bash
   3dstool -xvtf exefs exefs.bin --exefs-dir ./exefs_dir
   ```

2. Apply the IPS patch to `code.bin`:
   ```bash
   # Using flips or similar IPS tool
   flips --apply patches/60fps_v2.ips exefs_dir/code.bin exefs_dir/code_patched.bin
   mv exefs_dir/code_patched.bin exefs_dir/code.bin
   ```

3. Rebuild the ExeFS and ROM.

### Method 3: 3DS Hardware (Luma3DS)

1. Place the IPS patch at:
   ```
   SD:/luma/titles/00040000001D1400/exefs/code.ips
   ```

2. Enable "Enable game patching" in Luma3DS config.

## Working Cheat Code (Alternative)

If the ROM patch doesn't work, use the CTRPF cheat code:

File: `SD:/cheats/00040000001D1400.txt`

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

## Analysis Tools

This repository includes Ghidra scripts and Python tools for analyzing the game binary:

- `ghidra_scripts/` - Ghidra Python scripts for disassembly analysis
- `tools/` - Standalone binary analysis tools
- `docker/` - Docker setup for headless Ghidra

## Technical Details

The game uses a frame skip mechanism controlled by bytes at runtime memory offsets:
- `0x30000074/75` - Frame timing register 1
- `0x30000064/65` - Frame timing register 2
- `0x30000044/45` - Frame timing register 3
- `0x300DA3AC/AD` - Primary FPS control

Setting the control byte to `0x00` = 60fps, `0x01` = 30fps.

The challenge is finding where in `code.bin` these values are initialized.

## Contributing

Analysis reports and working patches are welcome! Please test thoroughly before submitting.

## License

Analysis tools: MIT
Cheat codes: Credit to original authors
