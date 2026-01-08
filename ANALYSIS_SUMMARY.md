# Mario & Luigi: BIS+BJJ 60fps ROM Patch Analysis

## Summary

After extensive analysis using GDB watchpoints on a custom-built emulator, we successfully identified the FPS control code but encountered issues with LayeredFS patching.

## Key Findings

### 1. FPS Control Location

Using GDB watchpoints on memory address 0x30000075, we traced the FPS write to:
- **File**: `AttackMiniGame.cro` (CRO dynamic module in romfs)
- **Offset in CRO**: 0x090C 
- **Instruction**: `MOV R2, #1` (0xE3A02001)
- **Change needed**: `MOV R2, #0` (0xE3A02000)

### 2. File Structure

The CRO file in romfs has a complex structure:
- **Total size**: 61440 bytes (0xF000)
- **Header/wrapper**: 0x80 bytes (contains hashes/metadata)
- **CRO0 section**: Starts at offset 0x80
- **Module name**: lObject_ (internal name for AttackMiniGame)

### 3. Patch Created

**Location**: `patches/60fps_v31_layeredfs/AttackMiniGame.cro`
- Patched byte at offset 0x098C (0x80 wrapper + 0x090C)
- Changes: 0x01 → 0x00

### 4. Issues Encountered

1. **Emulator fails in headless mode** - Qt plugin errors, exits immediately
2. **Game freezes with mod installed** - Both Citra and Azahar freeze/crash
3. **Possible causes**:
   - CRO has integrity checks we haven't bypassed
   - The 0x80-byte header contains hashes that need recalculation
   - LayeredFS might not work for CRO files
   - AttackMiniGame.cro might only load during specific scenarios

## Working Alternative: CTRPF Runtime Cheat

The CTRPF cheat code (which we analyzed) works because it continuously overwrites memory at runtime:

```
D3000000 30000000
50000074 01000101
20000075 00000000
```

This bypasses the CRO entirely by directly modifying the FPS byte in LINEAR heap.

## Recommendations

### Option 1: Use CTRPF Cheat (Recommended)
The runtime cheat is proven to work and doesn't require ROM modification.

### Option 2: Investigate Hash Recalculation
The 0x80-byte header likely contains SHA256 hashes that need updating:
- Hash fields at: 0x00, 0x20, 0x40, 0x60
- Need to determine what each hash covers
- Recalculate after patching

### Option 3: Try Different Emulator Mods
Test if other emulators handle LayeredFS CRO replacement differently:
- Citra Canary
- Lime3DS latest
- Different mod folder structures

### Option 4: ROM Rebuild
Instead of LayeredFS:
1. Extract full romfs with 3dstool
2. Replace AttackMiniGame.cro in extracted romfs
3. Rebuild romfs
4. Rebuild ROM with modified romfs

## Files Generated

- `patches/60fps_v31_layeredfs/AttackMiniGame.cro` - Patched CRO (60KB)
- `patches/60fps_v31_layeredfs/README.md` - Installation instructions
- `tmp/fps_module.cro` - Original CRO extracted from romfs
- `tmp/AttackMiniGame_patched.cro` - Patched version
- Custom emulator build at `build/emulator/Lime3DS/`

## Technical Details

### GDB Watchpoint Results
```
PC: 0x0026DB0C
LR: 0x002849EC
R2: 0x00000001 (FPS flag)
Memory 0x30000075: 0x01 (30fps)
```

### CRO Structure
```
Offset  Content
0x0000  Header/wrapper (0x80 bytes)
0x0080  CRO0 magic
0x098C  Patched instruction (MOV R2, #0)
```

## Conclusion

We successfully identified the exact code location for FPS control through dynamic analysis. The LayeredFS patch may not work due to integrity checks, but the findings enable:
1. Continued use of CTRPF runtime cheat
2. Future ROM rebuild with patched romfs
3. Better understanding of game's FPS architecture

🤖 Generated with Claude Code
