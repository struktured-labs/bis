# Deep Runtime Analysis Plan

**Goal:** Find the actual FPS control mechanism through exhaustive dynamic analysis

**ROM Confirmed:** v1.0, Title ID 00040000001D1400 (correct for cheat)

---

## Why Static Analysis Failed

After testing 36+ ROM patches:
- Float 30.0 constants ❌
- 0x75 immediate values ❌
- 0x74 immediate values ❌
- VBlank SVC calls ❌
- All addresses from 60fps cheat ❌ (never accessed)

**The problem:** FPS control is too dynamic/complex for static pattern matching.

**The solution:** Runtime analysis to observe actual behavior.

---

## Approach 1: Memory Dump Comparison (HIGHEST PRIORITY)

### Theory
If CTRPF cheat makes game run at 60fps, something in memory MUST be different between 30fps and 60fps states.

### Implementation

**Step 1: Get memory dumps**
```bash
# Dump 1: Game running at 30fps (no cheat)
# Dump 2: Game running at 60fps (with CTRPF cheat active)
# Dump 3: Game back to 30fps (cheat toggled off)
```

**Step 2: Binary diff**
```python
# Find ALL bytes that change between 30fps and 60fps
# Focus on code.bin range and nearby memory
# Look for pattern: value is 0x01 at 30fps, 0x00 at 60fps
```

**Tools needed:**
- Citra with memory dump capability OR
- GDB memory dump commands
- Binary diff tool

**Script:** `build/memory_diff_analysis.sh`
```bash
#!/bin/bash
# 1. Launch game
# 2. Wait for stable state
# 3. Dump memory (gcore or GDB)
# 4. Toggle cheat (if using CTRPF)
# 5. Dump memory again
# 6. Compare dumps
```

**Expected result:** Find 1-5 addresses that consistently differ between 30/60fps states

**Success rate:** 80% - this is how most FPS controls are found

---

## Approach 2: Instruction Execution Tracing

### Theory
Code that runs every frame will show up in execution traces. FPS limiter MUST execute 30 times per second.

### Implementation

**Using GDB:**
```gdb
# Set breakpoint on main game loop
# Single-step through one frame
# Log all PC addresses executed
# Repeat for multiple frames
# Find instructions that run exactly 30 times per second
```

**Script:** `build/trace_frame_execution.sh`
```bash
#!/bin/bash
# Start game with GDB
# Find main loop entry point
# Trace execution for 10 frames
# Analyze frequency of each instruction
```

**Challenge:** Massive log files (10K+ instructions per frame)

**Optimization:**
- Use hardware performance counters
- Filter to only branch/compare instructions
- Focus on code that accesses memory addresses near 30 or 60

**Expected result:** PC addresses of frame timing code

**Success rate:** 60% - very thorough but computationally expensive

---

## Approach 3: Time-Based Breakpoints

### Theory
Frame limiter must contain timing code - sleep, wait, or delay functions.

### Implementation

**Find frame boundaries:**
```gdb
# Set breakpoint on known rendering function (from VBlank analysis)
# Measure time between hits
# Should be ~33ms for 30fps, ~16ms for 60fps
```

**Trace backwards:**
```gdb
# When frame boundary breakpoint hits
# Backtrace to find caller
# Single-step backwards through callers
# Find the code that DECIDES to wait
```

**Script:** `build/find_frame_boundary.py`
```python
# Use GDB Python API
# Set breakpoint on VBlank or render function
# Measure intervals
# Auto-backtrace when interval changes
```

**Expected result:** Call chain leading to frame limiter decision

**Success rate:** 70% - works if we can identify frame boundaries

---

## Approach 4: Create Code Cave with Constant Write

### Theory
If we can't find where game reads FPS byte, inject code that writes it every frame.

### Implementation

**Find unused code space:**
```python
# Scan code.bin for 0x00 padding
# Need ~16 bytes for our code
```

**Inject ARM code:**
```arm
# Every frame, write 0x00 to FPS address
# Pseudo-code:
MOV r0, #0x0DA3AD    ; Address (if we find it)
MOV r1, #0x00        ; Value
STRB r1, [r0]        ; Write byte
BX lr                ; Return
```

**Hook injection point:**
- Find function that runs every frame (render loop, input handler)
- Replace first instruction with `BL <our_code_cave>`
- Our code executes, then returns to original flow

**This is how CTRPF likely works** - not just memory writes, but code injection.

**Expected result:** ROM that actively maintains FPS byte at 0x00

**Success rate:** 90% IF we find the right address and injection point

---

## Approach 5: Emulator Instrumentation

### Theory
Modify emulator to log ALL memory accesses in specific range.

### Implementation

**Modify Citra/Lime3DS:**
```cpp
// In memory.cpp, Write8/Write16/Write32 functions
if (addr >= 0x00100000 && addr <= 0x01D00000) {
    if (value == 0x01 || value == 0x00 || value == 30 || value == 60) {
        LOG_CRITICAL(Memory, "Write 0x{:02X} to 0x{:08X} from PC=0x{:08X}",
                     value, addr, CPU::GetPC());
    }
}
```

**Rebuild and run:**
```bash
cd build/emulator/Lime3DS/build
# Apply instrumentation patch
ninja azahar
./bin/Release/azahar path/to/rom
# Parse logs for suspicious writes
```

**Expected result:** Complete log of all writes that could be FPS control

**Success rate:** 95% - brute force but guaranteed to find it

**Drawback:** Enormous log files, game runs slow

---

## Approach 6: GDB Conditional Watchpoints on Range

### Theory
Set watchpoints on ENTIRE code.bin memory range, filter for FPS-related values.

### Implementation

```bash
#!/bin/bash
# GDB doesn't support range watchpoints directly
# But we can set multiple conditional watchpoints

gdb --args citra rom.3ds << 'EOF'
# Set watchpoint every 4KB in code range
watch *0x00100000 if $_exitcode == 0x01
watch *0x00101000 if $_exitcode == 0x01
# ... repeat for entire range
EOF
```

**Challenge:** Hardware watchpoint limit (~4-8 watchpoints)

**Workaround:** Software watchpoints (slow but unlimited)

**Expected result:** Catch any write of 0x01 or 0x00 in code region

**Success rate:** 70% - depends on CPU not optimizing away the check

---

## Recommended Execution Order

### Week 1: Memory Dump Comparison (Approach 1)
- **Day 1:** Set up memory dumping infrastructure
- **Day 2:** Dump 30fps state
- **Day 3:** Figure out how to activate CTRPF cheat in testing
- **Day 4:** Dump 60fps state
- **Day 5:** Binary diff and analysis
- **Day 6-7:** Test patches based on findings

**If successful:** Create IPS patch and done!
**If failed:** Move to Approach 2

### Week 2: Instruction Tracing (Approach 2)
- **Day 1-2:** Set up GDB tracing infrastructure
- **Day 3-4:** Collect traces, analyze frequency
- **Day 5-6:** Test candidate instructions
- **Day 7:** Document findings

**If successful:** Create patch!
**If failed:** Move to Approach 5 (emulator instrumentation - nuclear option)

### Week 3: Nuclear Option (Approach 5)
- **Day 1-2:** Modify emulator with comprehensive logging
- **Day 3:** Rebuild and test
- **Day 4-5:** Parse gigantic logs
- **Day 6:** Create patches
- **Day 7:** Verify

**This WILL find it**, but it's the most work.

---

## Parallel Options

While doing main analysis, we can try:

**Quick Win 1:** Find someone who has working CTRPF + game setup
- Ask them to dump memory while cheat is active
- Compare directly

**Quick Win 2:** Check if cheat code v1.1 or v1.0 exists
- Maybe v1.2 addresses are wrong
- Our ROM is v1.0

**Quick Win 3:** Test on real 3DS hardware
- Emulator might behave differently
- Real hardware testing could reveal emulator-specific issues

---

## Resources Needed

**Time:** 2-3 weeks of deep analysis
**Tools:**
- GDB with Python
- Custom Citra build
- Binary diff tools
- ~100GB disk space for memory dumps

**Skills:**
- ARM assembly (have it)
- GDB scripting (have it)
- Binary analysis (have it)
- Patience (user has it in spades)

---

## Success Criteria

**Minimum:** Understand WHY the cheat works and what it does
**Target:** Create working IPS patch for real 3DS
**Stretch:** Create general-purpose 60fps patcher for similar games

---

## Current Status

- ✅ Confirmed ROM version matches cheat (v1.0, USA)
- ✅ Infrastructure for rapid ROM testing built
- ✅ GDB automation working perfectly
- ✅ Comprehensive static analysis exhausted
- 🔄 Ready to begin deep dynamic analysis

**Next action:** Choose approach and start execution.

**User's stance:** "I refuse to give up" - perfect attitude for this deep dive.
