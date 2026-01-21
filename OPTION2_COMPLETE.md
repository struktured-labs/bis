# Option 2 Complete: Automated LDRB Scanner

**Date:** January 20, 2026
**Status:** ✅ Analysis Complete - Ready for Testing

---

## What We Did

### ✅ Phase 1: Comprehensive Code Scan (COMPLETE)
- Scanned entire code.bin (1.9MB, 912,210 Thumb instructions)
- Found 371 instructions using immediate value 0x75
- Analyzed memory access patterns for all 371 candidates

### ✅ Phase 2: Pattern Analysis (COMPLETE)
- Filtered to 15 high-priority candidates where:
  - Register is loaded with 0x75
  - That register is used in memory access within 10 instructions
- Ranked by priority (HIGH/MEDIUM/LOW)

### ✅ Phase 3: Test ROM Generation (COMPLETE)
- Created 15 test ROMs (one per candidate)
- Each ROM patches a different candidate location
- All ROMs include CRO patches + candidate patch
- Saved in: `tmp/fps_candidate_roms/`

---

## The 15 Candidates

**High Priority (7):** Most likely FPS control locations
- Candidate #2: 0x00012588 - `movs r1, #0x75` → `str r3, [r1]`
- Candidate #7: 0x000280CA - `movs r0, #0x75` → `str r2, [r0, #4]`
- Candidate #8: 0x000404AA - `movs r0, #0x75` → `ldr r0, [r0, #4]` ⭐ READ op
- Candidate #11: 0x0004A5D4 - `adds r3, #0x75` → `str r0, [r3, #0x10]`
- Candidate #13: 0x000588F2 - `movs r2, #0x75` → `ldrsb r2, [r2, r4]` ⭐ BYTE READ
- Candidate #14: 0x0005A8AC - `adds r1, #0x75` → `str r2, [r1, r0]`
- Candidate #15: 0x0005C298 - `movs r0, #0x75` → `ldr r0, [r2, r4]`

**Medium Priority (5):** Less common patterns
- Candidates #1, #6, #9, #10, #12

**Low Priority (3):** Unlikely but possible
- Candidates #3, #4, #5

---

## Test ROMs Created

```
tmp/fps_candidate_roms/
├── test_cand02_a.3ds  (HIGH priority)
├── test_cand07_a.3ds  (HIGH priority)
├── test_cand08_a.3ds  (HIGH priority - READ operation)
├── test_cand11_a.3ds  (HIGH priority)
├── test_cand13_a.3ds  (HIGH priority - BYTE READ) ⭐ Top candidate
├── test_cand14_a.3ds  (HIGH priority)
├── test_cand15_a.3ds  (HIGH priority)
├── test_cand01_a.3ds  (MEDIUM priority)
├── test_cand06_a.3ds  (MEDIUM priority)
├── test_cand09_a.3ds  (MEDIUM priority)
├── test_cand10_a.3ds  (MEDIUM priority)
├── test_cand12_a.3ds  (MEDIUM priority)
├── test_cand03_a.3ds  (LOW priority)
├── test_cand04_a.3ds  (LOW priority)
├── test_cand05_a.3ds  (LOW priority)
└── manifest.json
```

Each ROM has the instruction at that candidate location changed to `movs rX, #0` (zeroing the 0x75 value).

---

## Next Step: Testing

### Quick Manual Test (Recommended, ~30 minutes)

Test ROMs in priority order:

**Start with these 2 most promising:**
1. **test_cand13_a.3ds** - BYTE READ operation (most likely)
2. **test_cand08_a.3ds** - WORD READ operation

**For each ROM:**
```bash
# Launch ROM
~/.local/bin/citra.AppImage tmp/fps_candidate_roms/test_cand13_a.3ds

# Observe:
# - Does it crash immediately?
# - Does title screen load?
# - Does FPS seem different?
# - Any graphical glitches?
```

**Expected Results:**
- **If FPS control found:** ROM behaves differently (crash, different FPS, glitches)
- **If not FPS control:** ROM works normally at 30 FPS

### Automated Test (If you want headless)

We can create a script that:
1. Launches each ROM
2. Measures FPS
3. Detects crashes
4. Reports which candidate affects behavior

But this requires a working automated test setup (emulator stability issues earlier).

---

## Most Promising Candidates

### #1: Candidate 13 (0x000588F2)
```assembly
movs r2, #0x75
adds r5, #0x70
ldrsb r2, [r2, r4]    ← Signed byte load
```

**Why it's promising:**
- **BYTE** load (not word) - FPS control is 1 byte
- **Signed** byte (ldrsb) - unusual, suggests specific purpose
- Uses register offset [r2 + r4] - dynamic addressing
- If r4 = base address and r2 becomes offset...

### #2: Candidate 8 (0x000404AA)
```assembly
movs r0, #0x75
subs r5, r3, r6
strb r3, [r5, #0x17]
ldr r0, [r0, #4]      ← Word load
```

**Why it's promising:**
- Loads from [0x75 + 4] = 0x79
- Could be loading FPS state struct
- Surrounded by other memory operations

---

## What Happens When We Find It

Once we identify which candidate affects FPS:

1. **Verify it's the right one:**
   - Test multiple times
   - Confirm behavior change is related to FPS
   - Check if it matches CTRPF cheat behavior

2. **Analyze the instruction:**
   - Disassemble surrounding code
   - Understand what it's checking
   - Determine exact patch needed

3. **Create final patch:**
   - If it's a branch: NOP the branch
   - If it's a value check: Change comparison value
   - If it's a load: Modify what it loads
   - Create IPS patch format

4. **Test final patch:**
   - Verify 60 FPS achieved
   - Test in different game modes
   - Ensure no crashes or glitches

---

## Time Estimate

**Manual testing (recommended):**
- 2 candidates: ~10 minutes
- All 7 HIGH priority: ~30 minutes
- All 15 candidates: ~1 hour

**Analysis & final patch:**
- Once found: 1-2 hours
- Testing: 30 minutes

**Total to completion:** 2-4 hours from now

---

## Your Decision Needed

**Option A: Quick Manual Test** (30 min, best chance of success)
- I can walk you through testing the top 2-7 candidates
- Just launch each ROM and tell me what happens
- Fastest path to finding the FPS control

**Option B: Continue Automated** (2-4 hours, fully headless)
- Create automated test script
- Run all 15 ROMs unattended
- Risk: Emulator stability issues from earlier

**Option C: Hybrid Approach** (1 hour)
- You test top 2-3 manually (10 minutes)
- If those fail, I create automated testing for remaining 12

---

## Files Ready

All analysis files in project root:
- `FPS_CANDIDATES_FOUND.md` - Detailed analysis
- `OPTION2_COMPLETE.md` - This document
- `DYNAMIC_ANALYSIS_FINDINGS.md` - Full investigation log
- `tmp/fps_candidate_roms/` - 15 test ROMs
- `tmp/0x75_analysis.json` - Raw analysis data

---

## Recommendation

**Start with manual test of top 2 candidates** (10 minutes):
1. Launch `test_cand13_a.3ds`
2. Launch `test_cand08_a.3ds`

If either behaves differently → we found it!
If both work normally → test remaining 5 HIGH priority (20 more minutes)

**This is the fastest path to success.**

Ready to proceed when you are!
