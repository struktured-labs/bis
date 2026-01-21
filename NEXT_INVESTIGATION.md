# Next Investigation Plan: Post-GDB Discovery

**Date:** January 20, 2026
**Status:** 8+ hours invested, taking break, will return
**Critical Finding:** Game NEVER accesses 0x30000075 (GDB watchpoint proof)

---

## The Paradigm Shift

### What We Thought
- CTRPF cheat writes to 0x30000075
- Game reads from 0x30000075 to control FPS
- Find the read instruction → patch it

### What We Discovered (GDB Proof)
- CTRPF cheat writes to 0x30000075
- **Game NEVER reads from 0x30000075**
- The cheat works by a completely different mechanism

### New Hypothesis
The CTRPF cheat likely:
1. Uses 0x30000075 as a **flag for the CTRPF framework itself**
2. When flag changes, CTRPF **runtime patches game code** (code injection/hooking)
3. The actual FPS control is elsewhere in the game

---

## Investigation Path A: CTRPF Framework Analysis

### Goal
Understand HOW the cheat actually works (not just WHAT it does)

### Tasks
1. **Find CTRPF source code**
   - Search GitHub for "CTRPF" / "CTRPluginFramework"
   - Understand cheat execution model
   - Find code injection/hooking mechanisms

2. **Reverse engineer the cheat code**
   ```
   D3000000 30000000  # Set base to 0x30000000
   50000074 01000101  # If [0x74] == 0x01
   20000075 00000000  # Write 0x00 to [0x75]
   ```
   - What is opcode 0x50? (conditional check)
   - What is opcode 0x20? (write)
   - Are there hidden opcodes that patch code?

3. **Search for 0x74 in game code**
   - We focused on 0x75, but cheat checks 0x74 FIRST
   - Maybe 0x74 is the actual FPS control
   - Found 199 candidates with `build/scan_thumb_mode.py` (search for 0x74)

### Expected Outcome
- Document that explains cheat mechanism
- Either find runtime hooking (can't replicate with IPS) OR find real FPS address

---

## Investigation Path B: VBlank/GSP Analysis

### Theory
3DS games typically control FPS via VBlank synchronization:
- 30 FPS: Wait for 2 VBlanks per frame
- 60 FPS: Wait for 1 VBlank per frame

### Evidence
- Found 1042 SVC (supervisor call) instructions in code.bin
- Found 1 "gsp" string reference
- GSP (GPU Service) provides `gspWaitForVBlank()`

### Tasks
1. **Analyze SVC calls**
   ```bash
   uv run build/scan_svc_calls.py  # NEW SCRIPT
   ```
   - Find all `SVC 0x25` (gspWaitForEvent)
   - Find all `SVC 0x32` (WaitSynchronization)
   - Identify VBlank wait loops

2. **Ghidra analysis**
   - Search for "VBlank" strings
   - Find GSP handle initialization
   - Trace VBlank wait call chains

3. **Test VBlank bypass**
   - Create patches that NOP out VBlank waits
   - OR patch wait count (2 → 1)
   - Generate 10-20 test ROMs

### Expected Outcome
- Find actual frame timing code
- Create targeted patches for VBlank logic

---

## Investigation Path C: Test 0x74 Candidates

### Why This Might Work
- CTRPF cheat checks `[0x74] == 0x01` BEFORE writing to 0x75
- Maybe 0x74 is the REAL FPS control byte
- We've been searching for 0x75 reads, but should search for 0x74

### Tasks
1. **Extract 0x74 candidates**
   - Already have scan results from `build/scan_thumb_mode.py`
   - Filter for high-priority (used in conditionals)

2. **Generate test ROMs**
   ```bash
   uv run build/test_0x74_candidates.py  # NEW SCRIPT
   ```
   - Similar to 0x75 approach
   - Top 20 candidates

3. **Automated testing**
   - Use existing test infrastructure
   - 40 second timeout per ROM
   - Report FPS results

### Expected Outcome
- Either find working patch OR rule out 0x74 as well

---

## Investigation Path D: Emulator-Side Solution

### Advantages
- **Guaranteed to work**
- Already have custom Lime3DS build
- Can test immediately

### Disadvantages
- Only works on emulator (not real 3DS)
- User wants IPS patch for real hardware
- Falls short of primary goal

### Implementation
**File:** `build/emulator/Lime3DS/src/core/core_timing.cpp`

Find frame limiter code, force 60fps:
```cpp
// Around line where frame timing is controlled
constexpr u64 frame_ticks_60fps = BASE_CLOCK_RATE_ARM11 / 60;
constexpr u64 frame_ticks_30fps = BASE_CLOCK_RATE_ARM11 / 30;

// Original: use game's timing
// u64 frame_ticks = game_timing;

// Override: always 60fps
u64 frame_ticks = frame_ticks_60fps;
```

### When to Use This
- If Paths A-C all fail
- As a temporary solution while continuing IPS investigation
- To verify the game CAN run at 60fps without issues

---

## Investigation Path E: Different Memory Addresses

### Theory
- Maybe the FPS byte isn't at 0x30000075
- CTRPF cheat might use a different address for this game
- Try nearby addresses or pattern search

### Tasks
1. **Set multiple watchpoints**
   ```bash
   # Modify build/gdb_attach_watchpoint.sh
   watch *(unsigned char*)0x30000074  # The conditional check byte
   watch *(unsigned char*)0x30000076  # Next byte
   watch *(unsigned char*)0x30000070  # Start of range
   # ... scan entire 0x30000000-0x30010000 region
   ```

2. **Memory dump comparison**
   - Run original ROM, dump 0x30000000-0x30010000
   - Run with CTRPF cheat active, dump same region
   - Diff to see what changes

3. **Search for FPS-related values**
   - Scan memory for value 30 (0x1E) or 60 (0x3C)
   - Change FPS with cheat, see what memory locations change

### Expected Outcome
- Find the ACTUAL memory location(s) used for FPS control

---

## Tools and Scripts Ready

### Working Infrastructure
- ✅ `build/gdb_attach_watchpoint.sh` - automated GDB with watchpoints
- ✅ `build/scan_thumb_mode.py` - comprehensive instruction scanner
- ✅ `build/test_fps_candidates.py` - automated ROM generation
- ✅ Custom Lime3DS with FPS logging
- ✅ ROM rebuild pipeline (direct binary patching)

### New Scripts Needed
- `build/scan_svc_calls.py` - analyze VBlank/GSP calls
- `build/test_0x74_candidates.py` - test 0x74 instead of 0x75
- `build/memory_diff_tool.py` - compare memory dumps

---

## Recommended Order

1. **Path C (0x74 candidates)** - 1-2 hours
   - Similar to what we just did
   - Quick to test with existing infrastructure
   - Low effort, medium chance

2. **Path B (VBlank/GSP)** - 2-3 hours
   - Most likely location of REAL frame limiter
   - 3DS games typically use this method
   - Medium effort, high chance

3. **Path A (CTRPF analysis)** - 3-5 hours
   - Understand the cheat mechanism deeply
   - Might reveal it's impossible to replicate with IPS
   - High effort, uncertain outcome

4. **Path E (Memory scanning)** - 1 hour
   - Quick experiment with multiple watchpoints
   - Might find the real address quickly
   - Low effort, low chance (but worth trying)

5. **Path D (Emulator solution)** - LAST RESORT
   - Only if everything else fails
   - Doesn't meet primary goal (IPS for real 3DS)
   - But guarantees 60fps for emulator play

---

## What We've Ruled Out

❌ Float 30.0 constants (9 locations tested)
❌ Immediate value 0x75 (371 occurrences, 15 high-priority tested)
❌ Simple memory read from 0x30000075 (GDB proof: never accessed)
❌ CRO modules alone (stable but still 30fps)

---

## Success Criteria

**Minimum:** Understand WHY the CTRPF cheat works
**Target:** Find the actual FPS control mechanism
**Goal:** Create IPS patch that replicates 60fps on real 3DS

---

## When We Return

**Start with:** Path C (0x74 candidates) - quickest test
**Then:** Path B (VBlank analysis) - most likely to succeed
**Document:** All findings in `INVESTIGATION_RESULTS.md`

**Remember:** User is stubborn, won't give up, prefers compact updates
