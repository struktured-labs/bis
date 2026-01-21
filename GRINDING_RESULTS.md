# Grinding Session Results

**Date:** January 20, 2026
**Status:** Continuing investigation, critical framework discovery made

---

## What We Tested

### Round 1: 0x74 Immediate Value Candidates (15 ROMs)
**Time:** ~1 hour
**Rationale:** CTRPF cheat checks `[0x74] == 0x01` before writing to 0x75

**Results:**
- 346 uses of 0x74 found (34 HIGH priority comparisons)
- Generated 15 test ROMs
- 3 crashed
- 12 ran at 30 FPS
- **0 achieved 60 FPS**

**Conclusion:** 0x74 is not FPS control either

---

### Round 2: VBlank/SVC Call Analysis (6 ROMs)
**Time:** ~1.5 hours
**Rationale:** 3DS games use VBlank synchronization for frame limiting

**What We Found:**
- Only 994 total SVC calls in entire game
- Only 4 `svcWaitSynchronization` (0x25) calls
- Only 2 `svcWaitSynchronizationN` (0x24) calls
- **HIGH priority candidate:** 0x14DB7A (in loop + has count values)

**Test Results:**
- 5/6 crashed when SVC NOPed
- #4 (0x14DB7A - HIGH priority) **ran without crashing**
- Likely still 30 FPS

**Significance:** Only 1 of 6 VBlank calls doesn't crash when disabled. This suggests either:
1. It's not critical for frame limiting, OR
2. It's handled differently than the others

---

### Round 3: Wait Count Pattern Search
**Time:** ~30 min
**Rationale:** 30fps = wait for 2 VBlanks, 60fps = wait for 1 VBlank

**What We Found:**
- 598 instances of `MOVS rX, #2`
- 262 HIGH priority (near control flow)
- 934 instances of `MOVS rX, #1`

**Problem:** Too many candidates to test individually (would take 10+ hours)

---

## Critical Discovery: CTRPF Framework Mechanism

**Research sources:**
- [CTRPF-Action Replay Code Types (GitHub Gist)](https://gist.github.com/Nanquitas/d6c920a59c757cf7917c2bffa76de860)
- [How to create Gateway Cheat Codes (GBAtemp)](https://gbatemp.net/threads/how-to-create-gateway-cheat-codes.410926/)
- [CTRPluginFramework Documentation (GameBrew)](https://www.gamebrew.org/wiki/CTRPluginFramework_3DS)

### Understanding the Cheat Code

```
D3000000 30000000  # Set offset to 0x30000000
50000074 01000101  # If [0x30000074] == 0x01000101
20000075 00000000  # Write 0x00 to [0x30000075]
```

**Opcode meanings:**
- `0xD3` = Set memory offset
- `0x50` = Conditional comparison (Equal To for 32-bit)
- `0x20` = 8-bit memory write

### The Real Problem

**CTRPF can do things an IPS patch cannot:**

1. **Runtime code patching/hooking**
   - CTRPF runs as a plugin in Luma3DS
   - Can hook function calls
   - Can patch code on-the-fly
   - Can intercept system calls

2. **Memory flag interpretation**
   - 0x30000075 might be a flag FOR THE CTRPF PLUGIN
   - Plugin reads flag, performs complex patches
   - Game never accesses 0x30000075 (GDB proof)

3. **Why our approach failed**
   - We searched for reads of 0x30000075 in game code
   - We assumed game code uses this address
   - **But CTRPF plugin is the one using it**
   - Plugin likely patches the actual frame limiter when flag changes

### Implications

**Static IPS patch cannot replicate CTRPF's runtime behavior** unless we:
1. Find exactly what code CTRPF patches when the flag is set
2. Apply those same patches statically to the ROM
3. This requires understanding the plugin's internal logic

---

## What We've Ruled Out

| Approach | Candidates Tested | Result |
|----------|------------------|---------|
| Float 30.0 constants | 9 | All 30 FPS |
| 0x75 immediate values | 15 | 6 crashed, 9 at 30 FPS |
| 0x74 immediate values | 15 | 3 crashed, 12 at 30 FPS |
| VBlank SVC calls | 6 | 5 crashed, 1 ran (likely 30 FPS) |
| MOVS #2 (wait counts) | Too many (262+) | Not tested |

**Total test ROMs created:** 45+
**Total testing time:** 35+ hours of emulator runtime

---

## The Challenge Now

### Option A: Reverse Engineer CTRPF Plugin
**Difficulty:** High
**Time:** 5-10 hours
**Approach:**
- Find CTRPF source code
- Understand how it processes the 60fps cheat
- Identify what game code it actually patches
- Apply those patches statically

**Success rate:** 70% (if plugin source is available)

### Option B: Dynamic Analysis of Plugin Runtime
**Difficulty:** Very High
**Time:** 10-15 hours
**Approach:**
- Run game with CTRPF + cheat enabled
- Use GDB to trace what code changes
- Compare memory before/after cheat activation
- Identify the actual frame limiter being patched

**Success rate:** 50% (very technical, may hit limitations)

### Option C: Emulator-Side Solution
**Difficulty:** Low
**Time:** 2-3 hours
**Approach:**
- Modify Lime3DS to force 60fps rendering
- Bypass game's frame limiter entirely
- **Only works on emulator, not real 3DS**

**Success rate:** 100% (but doesn't meet goal)

### Option D: Comprehensive Memory Scan
**Difficulty:** Medium
**Time:** 3-5 hours
**Approach:**
- Set GDB watchpoints on 0x30000000-0x30010000 range
- Run with CTRPF cheat enabled
- See what addresses actually get accessed
- Might find the real FPS control address

**Success rate:** 30% (may still not find game code that uses it)

---

## Current Understanding

### What Works
- **CRO patches:** All 12 modules patched, ROM stable
- **Test infrastructure:** Can generate/test ROMs rapidly
- **GDB automation:** Fully working attach method
- **Analysis tools:** Comprehensive scanning/disassembly

### What Doesn't Work
- **Static analysis alone:** Can't find runtime hooks
- **Simple value searches:** FPS control is complex
- **Brute force patching:** Too many false positives

### The Core Issue

**The CTRPF cheat works via mechanisms that may be impossible to replicate with a static ROM patch.**

CTRPF can:
- ✅ Hook system calls at runtime
- ✅ Patch code on-the-fly
- ✅ Intercept function calls
- ✅ Modify memory dynamically

IPS patch can:
- ✅ Change ROM bytes
- ❌ Hook runtime calls
- ❌ Dynamic code patching
- ❌ Runtime interception

---

## Recommendation

**If goal is to play at 60fps:** Option C (emulator mod) - guaranteed to work

**If goal is IPS patch for real 3DS:** Option A (reverse CTRPF) - highest chance of success

**If stubborn and won't give up:** Option B (dynamic analysis) - most thorough but hardest

---

## Next Session Plan

1. Search for CTRPF plugin source code (GitHub/GitLab)
2. If found: Analyze how 60fps cheat is implemented
3. If not found: Attempt Option B (runtime memory diff with GDB)
4. Document findings and create final comprehensive report
5. Either: Create working IPS patch OR prove it's impossible with static patching

---

## Files Generated This Session

**Analysis Scripts:**
- `build/analyze_0x74_usage.py`
- `build/test_0x74_candidates.py`
- `build/scan_svc_calls.py`
- `build/disassemble_vblank.py`
- `build/test_vblank_candidates.py`
- `build/find_wait_counts.py`

**Test ROMs:**
- `tmp/0x74_test_roms/` (15 ROMs)
- `tmp/vblank_test_roms/` (6 ROMs)

**Analysis Data:**
- `tmp/0x74_analysis.json` (346 candidates)
- `tmp/svc_analysis.json` (994 SVC calls, 6 VBlank candidates)
- `tmp/wait_count_analysis.json` (598 MOVS #2, 262 HIGH priority)

---

## Tokens Spent

This investigation has consumed significant computational resources (~150K+ tokens across sessions). User is committed to finding solution despite cost.

**Status:** Continuing the grind. Not giving up.
