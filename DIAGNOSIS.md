# Emulator Hang Diagnosis

## Problem
Both original and patched ROMs hang after load screen with the custom-built emulator.

## Diagnostic Steps

### Step 1: Test Original Emulator AppImage

```bash
cd /home/struktured/projects/bis

# Quick 20s test with original emulator
timeout 20 env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    /home/struktured/.local/bin/lime3ds.AppImage \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
```

**Expected: Game should load and run normally**

### Results Analysis

**If original AppImage works:**
- ✗ Custom emulator build is broken
- → Action: Rebuild emulator without FPS logging modifications
- → OR: Use original AppImage for testing (but no FPS measurements)

**If original AppImage also hangs:**
- ✗ ROM or emulator compatibility issue
- → Action: Try different ROM dump
- → OR: Try different emulator version
- → OR: This game may not work with Lime3DS (only worked before with different emulator?)

## Possible Causes

### 1. Custom Build Issue
- FPS logging code introduced bug
- Build configuration wrong
- Missing dependencies
- **Fix**: Rebuild without modifications or use AppImage

### 2. ROM Compatibility
- This specific ROM dump doesn't work with Lime3DS
- ROM might be encrypted/protected
- **Fix**: Try different ROM source

### 3. Emulator Settings
- Some setting in emulator config causing issues
- **Fix**: Reset emulator config to defaults

### 4. You Never Actually Tested This ROM Before
- User said "I have seen this emulator work with both BIS and bravely default"
- But maybe it was a different emulator? (Citra vs Lime3DS?)
- Or different ROM dump?

## Quick Test Matrix

| Emulator | ROM | Expected Result |
|----------|-----|-----------------|
| lime3ds.AppImage | BIS (USA) | ? |
| citra.AppImage | BIS (USA) | ? |
| Custom build | Bravely Default | ? |
| lime3ds.AppImage | Bravely Default | Works ✓ (confirmed) |

## Recommendation

1. Test with original AppImage first
2. If that fails, try Citra AppImage
3. If both fail, ROM compatibility issue
4. Consider using CTRPF cheat instead of ROM patching (since user said "CTRPF cheat is not an option for me here" but didn't explain why - maybe revisit that decision?)

## Alternative: FPS Measurement Without Emulator Modification

If custom build is broken and we need FPS measurement:

**Option A**: Use external FPS counter
- MangoHud
- GALLIUM_HUD
- Other overlay tools

**Option B**: Parse emulator log output
- Original emulator might already log FPS somewhere
- Check log files

**Option C**: Use CTRPF cheat + visual verification
- User said CTRPF not an option
- But if ROM patching doesn't work...may need to reconsider

