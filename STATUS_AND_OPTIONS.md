# 60fps Patch Project - Status Report

**Date:** January 20, 2026
**Goal:** Create IPS patch to convert Mario & Luigi: Bowser's Inside Story from 30fps to 60fps

---

## Current Status: Static Analysis Exhausted

### ✅ What Works
- **CRO patches (12 modules)**: Successfully patched all CRO modules at offset 0x76
- **ROM building**: Can rebuild ROMs with patches and they load without corruption
- **Test infrastructure**: Automated testing scripts, emulator builds
- **Working baseline ROM**: `Mario_Luigi_BIS_60fps_FINAL.3ds` (CRO patches only, stable 30fps)

### ❌ What Doesn't Work
- **All code.bin float patches**: Tested 9 locations individually and in combinations → ALL still 30fps
- **Custom emulator watchpoint**: Built Lime3DS with FPS logging but hangs on launch
- **Ghidra automated analysis**: Permission/import issues with Docker approach

### 🔍 What We Discovered
1. **FPS control address 0x30000075** is in plugin memory (0x30000000-0x30010000)
   - Runtime-allocated by Luma3DS/CTRPF framework
   - NOT in ROM data
   - CTRPF cheat writes here every frame

2. **Base address 0x30000000** appears as data at:
   - Offset 0x000B7CA0 (in constant pool)
   - Offset 0x0016C61B (in constant pool)
   - These are loaded by `LDR` instructions, not direct code

3. **Frame limiter pattern** (theoretical):
   ```arm
   LDR  r0, =0x30000000    ; Load base from constant pool
   LDRB r1, [r0, #0x75]    ; Read FPS control byte
   CMP  r1, #0x01          ; Check if 30fps mode
   BEQ  fps_30_branch      ; Branch based on value
   ```

---

## Why Static Analysis Failed

**The FPS control is register-based with runtime address calculation:**
- Base address loaded into register from constant pool
- Offset added dynamically
- Cannot find by searching for literal 0x30000075
- Requires runtime/dynamic analysis to trace execution

---

## Options Going Forward

### Option 1: GDB Watchpoint Analysis (RECOMMENDED)
**Approach:** Use GDB attached to working emulator with memory watchpoint

**Steps:**
1. Run `build/dynamic_analysis_gdb.sh` (already created)
2. Launch game, get past title screen
3. GDB sets watchpoint on 0x30000075
4. Capture Program Counter (PC) when watchpoint hits
5. Analyze instruction at that PC to find frame limiter
6. Create targeted patch

**Pros:**
- Most reliable way to find exact code location
- Will show actual runtime behavior
- Can see full backtrace and context

**Cons:**
- Requires manual interaction (not headless)
- Need to play game briefly to trigger watchpoint
- Takes 1-2 hours of hands-on debugging

**User decision needed:** This violates "headless only" preference

---

### Option 2: Search for LDRB Instructions
**Approach:** Scan entire code.bin for LDRB instructions with small offsets

**Steps:**
1. Disassemble entire code.bin (ARM + Thumb modes)
2. Find all `LDRB rX, [rY, #0x75]` or similar patterns
3. Trace back to find where rY gets loaded with 0x30000000
4. Test patches on candidate locations

**Pros:**
- Fully automated
- No emulator interaction needed
- Can run headless

**Cons:**
- May find many false positives
- Hard to determine which is the actual FPS control
- Could take days of trial and error

**Estimated time:** 8-16 hours to scan, test candidates

---

### Option 3: Emulator-Side FPS Unlock
**Approach:** Modify emulator to force 60fps regardless of game code

**Steps:**
1. Patch Lime3DS to ignore game's frame timing
2. Force 60fps rendering in emulator code
3. Build custom emulator

**Pros:**
- Guaranteed to work
- No game code analysis needed
- Quick to implement (2-3 hours)

**Cons:**
- **Only works on emulator, not real 3DS hardware**
- Not an IPS patch (doesn't meet goal)
- Requires users to use custom emulator

**Verdict:** Doesn't meet project requirements

---

### Option 4: Alternative Static Analysis
**Approach:** Search for timing/delay loops in code.bin

**Theory:** Frame limiter might use delays instead of checking 0x30000075

**Steps:**
1. Find loops with precise timing (33ms for 30fps, 16ms for 60fps)
2. Look for VBLANK wait instructions
3. Patch timing values

**Pros:**
- Fully automated
- Might find alternative frame limiting mechanism

**Cons:**
- Already tested float constants (likely delay timers)
- Low probability of success after 9 failed patches
- May patch wrong timing (physics, animations)

**Estimated success rate:** < 20%

---

## Recommendation

**Best path forward: Option 1 (GDB Watchpoint)**

**Justification:**
- Only reliable way to find exact FPS control code
- 1-2 hours of manual work vs. days of uncertain automated searching
- Guaranteed to find the right code location
- Can then create proper IPS patch

**Alternative if must be headless: Option 2**
- Create comprehensive LDRB scanner
- Test all candidates systematically
- Higher time cost but no manual interaction

---

## Required User Input

**Questions:**
1. Are you willing to do 1-2 hours of manual GDB debugging to find the frame limiter?
   - If YES → Use Option 1 (GDB watchpoint)
   - If NO → Use Option 2 (automated LDRB search)

2. Is emulator-only solution acceptable?
   - If YES → Option 3 is fastest (but doesn't meet stated goal)
   - If NO → Continue with Option 1 or 2

3. Time constraints?
   - Need solution today → Option 1 (GDB) or Option 3 (emulator)
   - Can wait 1-2 days → Option 2 (automated search)

---

## Files Ready

- ✅ `build/dynamic_analysis_gdb.sh` - GDB watchpoint script
- ✅ `build/disassemble_fps_locations.py` - Disassembly tool
- ✅ `build/emulator/Lime3DS/build/bin/Release/azahar` - Custom emulator (unstable)
- ✅ `~/.local/bin/citra.AppImage` - Working emulator for testing
- ✅ Test ROM infrastructure (8 test ROMs created)

---

## Estimated Time to Completion

| Option | Analysis Time | Patch Creation | Testing | Total |
|--------|---------------|----------------|---------|-------|
| Option 1 (GDB) | 1-2 hours | 1 hour | 1 hour | **3-4 hours** |
| Option 2 (LDRB scan) | 8-12 hours | 1 hour | 1 hour | **10-14 hours** |
| Option 3 (Emulator) | N/A | 2 hours | 1 hour | **3 hours** |
| Option 4 (Alternative) | 4-6 hours | 1 hour | 1 hour | **6-8 hours** |

---

## Your Choice

**Please decide:**
- Which option to pursue?
- Are you available for manual GDB session (if Option 1)?
- Any other constraints or preferences?

I'm ready to proceed immediately once you choose a direction.
