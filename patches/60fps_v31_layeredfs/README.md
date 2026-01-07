# Mario & Luigi: BIS+BJJ 60fps LayeredFS Patch v31

## What This Is

This is a **LayeredFS mod** that patches the `AttackMiniGame.cro` dynamic module to enable 60fps gameplay.

## Discovery Process

Through dynamic analysis using GDB watchpoints on the emulator, we traced the FPS control byte (at memory address 0x30000075) to discover that the write originates from a **CRO (Code Relocatable Object)** file loaded from romfs, not from the main executable.

The instruction `MOV R2, #1` at offset 0x090C in AttackMiniGame.cro was setting the FPS flag to 30fps. This patch changes it to `MOV R2, #0` for 60fps.

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
- **Module name**: AttackMiniGame.cro (lObject_ internal name)
- **Patch offset**: 0x090C within CRO
- **Change**: 0x01 → 0x00 (MOV R2, #1 → MOV R2, #0)
- **File size**: 41,648 bytes

## Testing

Run the game and the FPS should be unlocked to 60fps. The patch uses LayeredFS so it doesn't modify the ROM itself - the emulator loads the patched CRO file instead of the original from romfs.

## Why This Works

Unlike static IPS patches that modify the ROM file, LayeredFS allows runtime file replacement. The emulator loads our patched AttackMiniGame.cro instead of the one embedded in the game's romfs, effectively changing the FPS control logic without touching the ROM.

🤖 Generated with Claude Code
