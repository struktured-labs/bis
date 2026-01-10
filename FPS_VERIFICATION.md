# FPS Verification System - Implementation

## Problem Statement

The expert feedback was clear: **"Measurement is paramount to verification."**

Previous work created ROM patches but had no way to verify they actually changed FPS from 30 to 60. Visual estimation is unreliable.

## Solution: Automated FPS Measurement

### Implementation

Modified the custom-built Lime3DS/Azahar emulator to log FPS measurements in real-time.

**File modified:** `build/emulator/Lime3DS/src/citra_qt/citra_qt.cpp`

**Change at line 3542-3546:**
```cpp
game_fps_label->setText(tr("App: %1 FPS").arg(results.game_fps, 0, 'f', 0));

// Log FPS for verification
LOG_INFO(Frontend, "[FPS_MEASUREMENT] Game: {:.1f} FPS | System: {:.1f} FPS | Speed: {:.1f}%",
         results.game_fps, results.system_fps, results.emulation_speed * 100.0);
```

### What Gets Logged

Every ~1 second, the emulator outputs:
```
[FPS_MEASUREMENT] Game: 30.0 FPS | System: 59.8 FPS | Speed: 100.0%
```

**Metrics explained:**
- **Game FPS**: GSP frame submissions (actual game rendering rate) - **THIS IS THE KEY METRIC**
- **System FPS**: LCD VBlanks (3DS hardware refresh rate, should be ~60)
- **Speed**: Emulation speed percentage (100% = real-time)

### Automated Test Scripts

Created three test scripts:

#### 1. `tmp/measure_fps.sh` - Core Measurement Tool
- Runs emulator for specified duration (default 60s)
- Captures FPS logs to `tmp/fps_logs/`
- Parses logs and computes statistics:
  - Average, Min, Max FPS
  - Sample count
  - Automatic verdict (30fps / 60fps / unusual)

**Usage:**
```bash
./tmp/measure_fps.sh "path/to/rom.3ds" "test_name" [duration_seconds]
```

#### 2. `build/test_fps_complete.sh` - Comprehensive Test
- Runs BOTH original and patched ROMs (60s each)
- Disables LayeredFS mods for clean testing
- Compares results side-by-side
- Provides clear pass/fail verdict

**Usage:**
```bash
./build/test_fps_complete.sh
```

**Expected output:**
```
TEST 1: Original ROM (Expected: ~30 FPS)
  Average: 30.0 FPS
  ✅ VERDICT: Running at ~30 FPS

TEST 2: Patched ROM (Expected: ~60 FPS)
  Average: 60.0 FPS
  ✅ VERDICT: Running at ~60 FPS
```

#### 3. `build/test_clean_no_mods.sh` - Manual Clean Test
- Temporarily disables all mods
- Runs original ROM
- For manual verification that emulator works

### Test Results Directory Structure

```
tmp/fps_logs/
├── original_30fps_20260110_143022.log
├── patched_60fps_20260110_143142.log
└── ...
```

Each log contains:
- Full emulator output
- All FPS measurements with timestamps
- Parsed statistics at the end

## Expected Results

### Original ROM (Baseline)
- Game FPS: ~30 FPS (±2)
- System FPS: ~60 FPS
- Speed: ~100%

### Patched ROM (If successful)
- Game FPS: ~60 FPS (±3)
- System FPS: ~60 FPS
- Speed: ~100%

### If Patches Fail
- Game FPS: ~30 FPS (same as original)
- Indicates patches didn't affect FPS control
- Further investigation needed (frame limiter in main code, etc.)

## Build Process

The modified emulator was rebuilt with:
```bash
cd /home/struktured/projects/bis/build/emulator/Lime3DS/build
ninja -j16 azahar
```

Build succeeded, producing:
- `/home/struktured/projects/bis/build/emulator/Lime3DS/build/bin/Release/azahar`

This custom emulator is used by all test scripts.

## Advantages of This Approach

1. **Objective Measurement**: No guessing, actual FPS values from emulator internals
2. **Automated**: Run test, get verdict, no manual interpretation needed
3. **Repeatable**: Same test can be run anytime, results comparable
4. **Comprehensive**: Tests both ROMs side-by-side for direct comparison
5. **Logged**: All data saved for later analysis

## Usage for Testing

**Quick test:**
```bash
./build/test_fps_complete.sh
```

**Custom duration:**
Edit `build/test_fps_complete.sh` and change `TEST_DURATION=60` to desired seconds.

**Single ROM test:**
```bash
./tmp/measure_fps.sh "path/to/rom.3ds" "my_test" 120  # 2 minutes
```

## What This Addresses

From expert feedback:
- ✅ "Measurement is paramount to verification" - Now have actual FPS measurement
- ✅ "Automate verification of 60 fps" - Fully automated test scripts
- ✅ "Including stability AND the FPS" - Computes average, min, max over test duration
- ✅ "Avoiding the central problem" - Can now definitively verify if patches work

## Next Actions

1. Run `./build/test_fps_complete.sh` to verify the comprehensive 60fps patches
2. Analyze results:
   - If patched ROM shows ~60 FPS: **SUCCESS!** Document and distribute
   - If patched ROM shows ~30 FPS: Investigate further (frame limiter, additional patches needed)
3. If needed: Use FPS logs to identify which game modes work/fail (battle, field, menu, etc.)

🤖 Generated with Claude Code
