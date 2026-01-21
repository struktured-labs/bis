# Dynamic Analysis Findings - 60fps Patch Investigation

## Executive Summary

**Status:** Static analysis exhausted. Moving to dynamic analysis required.
**Problem:** All code.bin patches (1-9 float constants) result in 30 FPS - patches don't work
**Root Cause:** Frame limiter location still unknown

---

## Critical Discovery: Memory Region Analysis

### FPS Control Address: 0x30000075

**Memory Map Location:**
```
Address: 0x30000075
Region: PLUGIN/3GX Memory (0x30000000 - 0x30010000)
Type: Runtime-allocated memory (NOT in ROM)
```

**Implications:**
1. **Cannot be patched in ROM** - this memory doesn't exist until runtime
2. **Allocated by plugin system** - Luma3DS/CTRPF framework
3. **CTRPF cheat writes here every frame** - continuous patching, not one-time init

### CTRPF Cheat Mechanism

```
D3000000 30000000  # Set base address to 0x30000000
50000074 01000101  # If [0x74] == 0x01 (check if 30fps mode)
20000075 00000000  # Write 0x00 to [0x75] (force 60fps)
```

**Key insight:** The cheat is CONDITIONAL and runs EVERY FRAME
- Checks byte 0x30000074 first
- Only writes to 0x30000075 if condition met
- This means game code continuously sets/reads this value

---

## Static Analysis Results

### Base Address References Found

Two locations in code.bin reference 0x30000000:

1. **Offset 0x000B7CA0**: Literal value 0x30000000
   ```
   0x000B7C9C: 0x00422000
   0x000B7CA0: 0x30000000  ← Base address
   0x000B7CA4: 0xCD014100
   ```

2. **Offset 0x0016C61B**: Literal value 0x30000000
   ```
   0x0016C617: 0xE8BD87F0
   0x0016C61B: 0x30000000  ← Base address
   0x0016C61F: 0xC30001C1
   ```

**Analysis:** These are likely plugin initialization code setting up the base address, NOT the actual FPS control logic.

### Float Constants Patched (ALL FAILED)

Patched 9 locations where float 30.0 appears:
- 0x0007A413
- 0x000C6EE4
- 0x000F2373
- 0x0012C3AA
- 0x00151982
- 0x00165F68
- 0x00183280
- 0x001A7F0A
- 0x001BC8E3

**Result:** All patches tested individually and in combinations - **ALL still 30 FPS**

**Conclusion:** Float 30.0 constants are NOT the frame limiter (likely physics/animation timers)

---

## What We Need to Find

Since the plugin memory approach works (CTRPF cheat), the game must:

1. **Read from 0x30000075** - fetch FPS mode byte
2. **Use it to control timing** - branch on this value
3. **Do this every frame** - continuous check

### Target Instructions (Unknown Locations)

Looking for ARM code pattern like:
```arm
LDR  r0, =0x30000000    # Load base address into register
LDRB r1, [r0, #0x75]    # Load byte at offset 0x75
CMP  r1, #0x01          # Check if 30fps mode
BEQ  fps_30_path        # Branch if 30fps
                        # 60fps path here
```

Or:
```arm
LDR  r0, =0x30000075    # Direct address
LDRB r1, [r0]           # Load FPS control byte
...
```

---

## Dynamic Analysis Required

### Why Static Analysis Failed

1. **Address computed at runtime** - base in register + offset
2. **Code uses indirect addressing** - not literal 0x30000075
3. **Multiple potential paths** - game state dependent

### Recommended Approaches

#### Option 1: Memory Watchpoint (GDB)
- Attach GDB to emulator
- Set watchpoint on 0x30000075
- Capture all reads/writes with program counter
- Backtrace to find caller

**Script:** `build/dynamic_analysis_gdb.sh` (requires manual interaction)

#### Option 2: Custom Emulator Logging ✓ (ATTEMPTED)
- Modified Lime3DS to log writes to 0x30000075
- **Status:** Emulator hangs on launch screen
- **Issue:** Custom emulator unstable

#### Option 3: Ghidra Analysis (IN PROGRESS)
- Import code.bin as ARM binary
- Scan all instructions for memory references to 0x30000000 region
- Find LDRB/STRB instructions accessing offset 0x75
- **Status:** Running now

#### Option 4: Alternative Strategy - Emulator-Side Patch
- Modify emulator to ignore game's FPS setting
- Force 60fps rendering regardless of game code
- **Downside:** Only works on emulator, not real 3DS

---

## Testing Summary

### ROMs Tested

| ROM | CRO Patches | code.bin Patches | Result |
|-----|-------------|------------------|--------|
| FINAL | ✓ (12 modules) | None | 30 FPS |
| v2/v3 | ✓ | All 9 patches | Crashes |
| test_patch_0 | ✓ | Patch #0 only | 30 FPS |
| test_patch_1 | ✓ | Patch #1 only | 30 FPS |
| test_patch_0_1_2 | ✓ | Patches #0,#1,#2 | 30 FPS |

**Conclusion:** CRO patches work (no crash) but don't achieve 60fps. Frame limiter is elsewhere.

---

## Next Steps

1. **Complete Ghidra analysis** - wait for current scan to finish
2. **If Ghidra finds nothing:** Use GDB watchpoint approach
3. **If GDB succeeds:** Identify exact instruction, create targeted patch
4. **Create IPS patch** - final deliverable

---

## Tools Available

- ✓ Ghidra (Docker headless setup)
- ✓ GDB (dynamic_analysis_gdb.sh script)
- ✓ Custom Lime3DS emulator (unstable but built)
- ✓ Working citra.AppImage emulator
- ✓ 3dstool, ctrtool, makerom
- ✓ Python analysis scripts

---

## Time Estimate

- Ghidra analysis: 30 minutes (running)
- If successful: 2-4 hours to create patch and test
- If unsuccessful: GDB approach needed (4-8 hours with manual debugging)

**Best case:** Working 60fps patch by end of day
**Realistic:** 1-2 days for proper dynamic analysis
