# Mario & Luigi BIS+BJJ - Testing Guide

## Automated FPS Verification ✨ NEW!

### Comprehensive FPS Test (Recommended)
```bash
./build/test_fps_complete.sh
```

**What it does:**
- Runs BOTH original and patched ROMs (60s each)
- Captures real FPS measurements from emulator logs
- Computes average/min/max FPS automatically
- Provides clear pass/fail verdict
- Saves detailed logs to `tmp/fps_logs/`

**Expected output:**
- Original ROM: ~30 FPS average
- Patched ROM: ~60 FPS average (if patches work!)

**This is the GOLD STANDARD test** - uses actual FPS measurement, not visual estimation.

---

## Manual Test Scripts

### 1. Clean Test (NO mods - Verify Emulator Works)
```bash
./build/test_clean_no_mods.sh
```

**What it does:**
- Temporarily disables ALL emulator mods/LayeredFS
- Launches ORIGINAL unpatched ROM
- Re-enables mods when you exit

**Expected result:**
- Game should load normally
- Will run at 30fps (original speed)
- Proves emulator works correctly

**If this fails:** Emulator or ROM has issues unrelated to patches

---

### 2. Patched ROM Test (60fps - All Modules)
```bash
./build/test_60fps_FINAL.sh
```

**What it does:**
- Uses directly-patched ROM (build/Mario_Luigi_BIS_60fps_FINAL.3ds)
- All 12 CRO modules patched
- No LayeredFS mods needed

**Expected result:**
- Game loads (no "corrupted" error)
- Runs at 60fps (double speed - should be very noticeable)
- Smoother animations in ALL game modes

**If game loads but feels same:** Patches didn't work, need to investigate further
**If game shows "corrupted":** ROM patching broke something

---

## What to Test For

### In Clean Test (30fps):
- ✓ Game loads without errors
- ✓ Title screen appears
- ✓ Menus are navigable
- ✓ Gameplay works
- ✓ Feels normal speed (baseline)

### In Patched Test (60fps):
- ✓ Game loads (no corruption error)
- ✓ Noticeably smoother/faster than clean test
- ✓ No crashes or freezes
- ✓ All modes smooth (battle, field, menus)

## Files Overview

| File | Purpose | Size |
|------|---------|------|
| Mario & Luigi...3ds | Original ROM | 1.0 GB |
| build/Mario_Luigi_BIS_60fps_FINAL.3ds | Patched ROM (all 12 modules) | 1.0 GB |
| build/test_clean_no_mods.sh | Test original (no mods) | - |
| build/test_60fps_FINAL.sh | Test patched ROM | - |

## Current Mods Status

**Azahar**: 2 files in LayeredFS mods
**Lime3DS**: 13 files in LayeredFS mods

**Note**: The clean test script temporarily disables these mods to ensure a pure test.

## Troubleshooting

**Emulator won't start:**
- Check OpenGL env vars (MESA_GL_VERSION_OVERRIDE, etc.)
- Try: `QT_QPA_PLATFORM=xcb` or `QT_QPA_PLATFORM=offscreen`

**Game shows "app is corrupted":**
- ROM patching broke file structure
- Use original ROM instead

**Game freezes during load:**
- LayeredFS CRO mods causing integrity check failures
- Disable mods (run clean test)

**No FPS difference:**
- Patches applied but not taking effect
- May need additional patches (frame limiter in main code?)
- Need actual FPS measurement to confirm

## Technical Details

### FPS Logging Implementation

The custom-built emulator now includes automated FPS logging:

**Modified file:** `build/emulator/Lime3DS/src/citra_qt/citra_qt.cpp:3544-3546`

```cpp
// Log FPS for verification
LOG_INFO(Frontend, "[FPS_MEASUREMENT] Game: {:.1f} FPS | System: {:.1f} FPS | Speed: {:.1f}%",
         results.game_fps, results.system_fps, results.emulation_speed * 100.0);
```

This logs FPS measurements every update interval (~1 second) with an easy-to-grep marker `[FPS_MEASUREMENT]`.

**Log location:** Emulator stderr/stdout (captured by test scripts)

### Measurement Accuracy

- **Game FPS**: GSP frame submissions (actual game rendering rate)
- **System FPS**: LCD VBlanks (3DS hardware refresh rate)
- **Emulation Speed**: Ratio of walltime to emulated time

For 60fps patches to work, we expect:
- **Original ROM**: Game FPS ≈ 30
- **Patched ROM**: Game FPS ≈ 60

## Next Steps

1. **FIRST**: Run automated FPS test (`./build/test_fps_complete.sh`)
2. **Check results**: Original should be ~30 FPS, patched should be ~60 FPS
3. **If patched shows ~30 FPS**: Patches didn't work, investigate further
4. **If patched shows ~60 FPS**: SUCCESS! Document and share

🤖 Generated with Claude Code
