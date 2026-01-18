# Emulator Functionality Test Plan

## Problem
Both original and patched BIS ROMs hang after load screen with the custom emulator build.

## Diagnostic Tests

### Test 1: Original Lime3DS AppImage

**Command:**
```bash
cd /home/struktured/projects/bis

env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    /home/struktured/.local/bin/lime3ds.AppImage \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
```

**What to watch for:**
- Does the emulator window open?
- Does it show the load dialog?
- Does it progress past the load screen to the title screen?
- Can you navigate menus?

**Press Ctrl+C to stop if it hangs**

---

### Test 2: Citra AppImage (Alternative)

**Command:**
```bash
cd /home/struktured/projects/bis

env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    /home/struktured/.local/bin/citra.AppImage \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
```

**Same observations as Test 1**

---

### Test 3: Custom Build

**Command:**
```bash
cd /home/struktured/projects/bis

env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    QT_QPA_PLATFORM=xcb \
    build/emulator/Lime3DS/build/bin/Release/azahar \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
```

**Same observations as Test 1**

---

## Results Interpretation

| Lime3DS Works | Citra Works | Custom Works | Diagnosis |
|---------------|-------------|--------------|-----------|
| ✅ | - | ❌ | Custom build is broken, use Lime3DS |
| - | ✅ | ❌ | Custom build is broken, use Citra |
| ❌ | ❌ | ❌ | ROM incompatibility issue |
| ✅ | ✅ | ✅ | All working - something else wrong with tests |

## If All Fail

**Possible causes:**
1. ROM is encrypted/protected
2. Missing system files (keys, firmware)
3. ROM dump is corrupted
4. Emulator settings issue

**Next steps:**
1. Check emulator log files for errors
2. Verify ROM file integrity (checksums)
3. Try a known-working ROM (Bravely Default?) to confirm emulators work

## If Lime3DS or Citra Works

**Then we can:**
1. Use that emulator for testing
2. Problem: No FPS logging in original AppImages
3. Solutions:
   - **Option A**: Fix custom build (remove FPS logging, rebuild clean)
   - **Option B**: Use external FPS counter (MangoHud, GALLIUM_HUD)
   - **Option C**: Visual comparison only (30fps vs 60fps should be obvious)

## Quick Sanity Check with Bravely Default

You mentioned Bravely Default works. Quick test to confirm emulators are functional:

```bash
# If you have Bravely Default ROM, test with Lime3DS:
/home/struktured/.local/bin/lime3ds.AppImage "path/to/bravely_default.3ds"
```

If this works, we know:
- ✅ Emulator is functional
- ✅ System files/keys are present
- → Problem is specific to BIS ROM

