# Mario & Luigi: BIS+BJJ 60fps LayeredFS Patch v31

## What This Is

This is a **LayeredFS mod** that patches the `AttackMiniGame.cro` dynamic module to enable 60fps gameplay.

## Discovery Process

Through dynamic analysis using GDB watchpoints on the emulator, we traced the FPS control byte (at memory address 0x30000075) to discover that the write originates from a **CRO (Code Relocatable Object)** file loaded from romfs, not from the main executable.

The instruction `MOV R2, #1` at offset 0x090C within the CRO was setting the FPS flag to 30fps. This patch changes it to `MOV R2, #0` for 60fps.

## Installation

### For Azahar Emulator:
```bash
mkdir -p ~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/
cp AttackMiniGame.cro ~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/
```

### For Lime3DS:
```bash
mkdir -p ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/romfs/
cp AttackMiniGame.cro ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/romfs/
```

### For Citra:
```bash
mkdir -p ~/.local/share/citra-emu/load/mods/00040000001D1400/romfs/
cp AttackMiniGame.cro ~/.local/share/citra-emu/load/mods/00040000001D1400/romfs/
```

## Technical Details

- **Original CRO location**: romfs.bin offset 0x19084390
- **Full file size**: 61440 bytes (0xF000)
  - Includes 0x80 byte header/wrapper
  - CRO0 magic starts at +0x80
- **Module name**: AttackMiniGame.cro (lObject_ internal name)
- **Patch offset**: 0x098C (0x80 wrapper + 0x090C within CRO)
- **Change**: 0x01 → 0x00 (MOV R2, #1 → MOV R2, #0)
- **Instruction**: 0xE3A02001 → 0xE3A02000

## Testing

Run the game with the emulator. The LayeredFS system will load the patched CRO instead of the original from romfs, changing the FPS control logic to enable 60fps.

## Why This Works

Unlike static IPS patches that modify the ROM file, LayeredFS allows runtime file replacement. The emulator loads our patched AttackMiniGame.cro (with its 0x80-byte wrapper intact) instead of the one embedded in the game's romfs.

## Important Notes

- The CRO file must be exactly 61440 bytes
- The file includes a 0x80-byte header before the CRO0 magic
- Don't use the 41KB version - it's missing the wrapper/padding

🤖 Generated with Claude Code
