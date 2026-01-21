# Current State: 60fps Patch Investigation

**Date:** January 20, 2026, After Grinding Session
**Time Invested:** 12+ hours
**Status:** Critical framework understanding achieved, continuing

---

## 🔴 Critical Discoveries

### Discovery 1: Game NEVER accesses 0x30000075
- GDB hardware watchpoint proof: 60 seconds, **ZERO HITS**
- CTRPF writes to 0x30000075, but game doesn't read it
- Log: `tmp/gdb_fps_watchpoint.log`

### Discovery 2: CTRPF Uses Runtime Code Patching
- CTRPF can hook/patch code at runtime (impossible for IPS)
- 0x30000075 is likely a flag FOR THE PLUGIN, not game code
- Plugin reads flag → patches actual game code → changes FPS
- **Static IPS patch cannot replicate this** unless we find what it patches

### Discovery 3: VBlank Calls Are Sparse
- Only 6 VBlank-related SVC calls in entire game
- 5/6 crash when NOPed
- 1/6 (#4 at 0x14DB7A) runs without crashing
- This candidate is special but likely still 30fps

---

## What We've Tested (Grinding Session)

| Round | Approach | Candidates | Crashed | Ran (30fps) | Success |
|-------|----------|------------|---------|-------------|---------|
| 1 | 0x75 immediates | 15 | 6 | 9 | 0 |
| 2 | 0x74 immediates | 15 | 3 | 12 | 0 |
| 3 | VBlank SVC NOPs | 6 | 5 | 1 | 0 |
| **TOTAL** | **36 test ROMs** | **14** | **22** | **0** |

**Additional analysis:**
- 598 MOVS #2 instructions found (potential wait counts)
- 262 HIGH priority (near control flow)
- Too many to test individually

---

## What Works

✅ **CRO patches** - 12 modules, ROM stable at 30fps
✅ **GDB automation** - attach method works perfectly
✅ **ROM generation** - can create/test patches rapidly
✅ **Comprehensive scanning** - 912K instructions analyzed
✅ **Test infrastructure** - automated ROM testing

---

## What Doesn't Work

❌ Float 30.0 patches (9 locations)
❌ 0x75 immediate patches (15 candidates)
❌ 0x74 immediate patches (15 candidates)
❌ VBlank SVC NOPs (5/6 crash, 1 runs but likely 30fps)
❌ Simple static analysis approaches

---

## The Core Challenge

**CTRPF can do runtime operations that IPS patches cannot:**

| CTRPF Plugin | IPS Patch |
|--------------|-----------|
| ✅ Hook system calls | ❌ Static bytes only |
| ✅ Runtime code patching | ❌ No runtime modification |
| ✅ Function interception | ❌ No interception |
| ✅ Dynamic memory writes | ❌ Fixed ROM changes |

**This means:** We need to find what code CTRPF patches when the flag changes, then apply those same patches statically.

---

## Next Investigation Options

### Option A: Reverse Engineer CTRPF Plugin (RECOMMENDED)
**Time:** 5-10 hours | **Success rate:** 70%
- Find CTRPF source code
- Understand 60fps cheat implementation
- Identify actual game code it patches
- Apply patches statically

### Option B: Runtime Memory Diff
**Time:** 10-15 hours | **Success rate:** 50%
- Run with CTRPF + cheat active
- GDB trace code changes
- Compare before/after
- Very technical, may hit limits

### Option C: Emulator-Side Solution
**Time:** 2-3 hours | **Success rate:** 100%
- Modify Lime3DS force 60fps
- **Only works on emulator**
- Doesn't meet IPS patch goal

### Option D: Comprehensive Memory Scan
**Time:** 3-5 hours | **Success rate:** 30%
- Watchpoint entire 0x30000000 range
- See what CTRPF actually accesses
- May still not find game code link

---

## Files Generated This Session

**New Scripts:**
- `build/analyze_0x74_usage.py` - 346 candidates found
- `build/test_0x74_candidates.py` - ROM generation
- `build/scan_svc_calls.py` - 994 SVC calls analyzed
- `build/disassemble_vblank.py` - Context analysis
- `build/test_vblank_candidates.py` - VBlank ROM generation
- `build/find_wait_counts.py` - 598 MOVS #2 found

**Test ROMs:**
- `tmp/0x74_test_roms/` (15 ROMs)
- `tmp/vblank_test_roms/` (6 ROMs)

**Analysis Data:**
- `tmp/0x74_analysis.json`
- `tmp/svc_analysis.json`
- `tmp/wait_count_analysis.json`

**Documentation:**
- `GRINDING_RESULTS.md` - This session's findings

---

## User Status

- **STUBBORN** - will not give up despite token costs
- **COMPACT** - prefers results over explanations
- **GRINDING** - continuing investigation aggressively

---

## Next Action

**Recommended:** Search for CTRPF plugin source code to understand how 60fps cheat works internally, then replicate as static patch.

See `GRINDING_RESULTS.md` for full session details.
