# FPS Control Candidates - Analysis Complete

**Date:** January 20, 2026
**Method:** Automated LDRB scanner (Option 2)

---

## Summary

**Scanned:** 1.9MB code.bin (912,210 Thumb instructions)
**Found:** 371 uses of immediate value 0x75
**High Priority:** 15 candidates where register with 0x75 is used in memory access
**Status:** Ready for systematic testing

---

## Top 15 Candidates

These are instructions that:
1. Load/calculate 0x75 into a register
2. Use that register in a memory operation within next 10 instructions

| # | Address    | Instruction      | Next Memory Op | Priority |
|---|------------|------------------|----------------|----------|
| 1 | 0x00002482 | adds r3, #0x75   | str r4, [r3, r0] | MEDIUM |
| 2 | 0x00012588 | movs r1, #0x75   | str r3, [r1]    | **HIGH** |
| 3 | 0x00013518 | adds r1, #0x75   | strb r1, [r1, #0x14] | LOW |
| 4 | 0x0001A14C | adds r0, #0x75   | strb r1, [r0, #0x14] | LOW |
| 5 | 0x00022BDA | movs r0, #0x75   | strh r0, [r0, #8] | LOW |
| 6 | 0x00026CCE | movs r1, #0x75   | strb r4, [r0, #0x14] | MEDIUM |
| 7 | 0x000280CA | movs r0, #0x75   | str r2, [r0, #4] | **HIGH** |
| 8 | 0x000404AA | movs r0, #0x75   | ldr r0, [r0, #4] | **HIGH** |
| 9 | 0x00042A38 | movs r0, #0x75   | strh r1, [r2, #0x10] | MEDIUM |
| 10 | 0x00047A8C | movs r4, #0x75  | ldrb r1, [r0, r5] | MEDIUM |
| 11 | 0x0004A5D4 | adds r3, #0x75  | str r0, [r3, #0x10] | **HIGH** |
| 12 | 0x000574EE | movs r2, #0x75  | strh r0, [r2, #2] | MEDIUM |
| 13 | 0x000588F2 | movs r2, #0x75  | ldrsb r2, [r2, r4] | **HIGH** |
| 14 | 0x0005A8AC | adds r1, #0x75  | str r2, [r1, r0] | **HIGH** |
| 15 | 0x0005C298 | movs r0, #0x75  | ldr r0, [r2, r4] | **HIGH** |

**Priority Ranking:**
- **HIGH**: Direct memory access using r0-r2 (common registers)
- **MEDIUM**: Less common patterns or offset access
- **LOW**: strb with additional offset (likely struct field access, not FPS byte)

---

## Testing Strategy

### Phase 1: Test High Priority (7 candidates)

Test these first as they have the most promising patterns:

1. **0x00012588**: `movs r1, #0x75` → `str r3, [r1]`
   - Direct store to address in r1

2. **0x000280CA**: `movs r0, #0x75` → `str r2, [r0, #4]`
   - Store to address + small offset

3. **0x000404AA**: `movs r0, #0x75` → `ldr r0, [r0, #4]`
   - **READ operation** - could be FPS byte read!

4. **0x0004A5D4**: `adds r3, #0x75` → `str r0, [r3, #0x10]`
   - Adding offset to existing address

5. **0x000588F2**: `movs r2, #0x75` → `ldrsb r2, [r2, r4]`
   - **BYTE READ** with register offset - very promising!

6. **0x0005A8AC**: `adds r1, #0x75` → `str r2, [r1, r0]`
   - Store with register offset

7. **0x0005C298**: `movs r0, #0x75` → `ldr r0, [r2, r4]`
   - Load using r0 as part of calculation

### Phase 2: Test Medium Priority (5 candidates)

If Phase 1 fails, test these.

### Phase 3: Test Low Priority (3 candidates)

Lowest probability but worth testing if others fail.

---

## Patch Approach

For each candidate, create a test patch that modifies the instruction to use a different value and observe the effect:

### Test 1: NOP the instruction
- Replace with `movs rX, #0` or `nop`
- Expected: If this is FPS control, game might crash or behave differently

### Test 2: Change value
- Replace 0x75 with 0x00 or different value
- Expected: FPS behavior change

### Test 3: Branch bypass
- If there's a comparison/branch after, NOP the branch
- Expected: Skip FPS check

---

## Most Promising Candidates

Based on pattern analysis:

**#1 Priority: 0x000588F2**
```
movs r2, #0x75
adds r5, #0x70
ldrsb r2, [r2, r4]    ← Signed byte load!
```
- Loads SIGNED byte from [r2 + r4]
- If r2 = 0x75 and r4 = base address...
- This could be reading FPS control byte!

**#2 Priority: 0x000404AA**
```
movs r0, #0x75
subs r5, r3, r6
strb r3, [r5, #0x17]
ldr r0, [r0, #4]      ← Word load from offset
```
- Loads word from [r0 + 4] where r0 = 0x75
- Could be loading FPS state struct

**#3 Priority: 0x00012588**
```
movs r1, #0x75
adds r0, #2
...
str r3, [r1]          ← Direct store
```
- Stores to address 0x75
- Could be writing FPS value

---

## Next Steps

1. Create test ROM with patch at 0x000588F2 (highest priority)
2. If works → Analyze instruction in detail, create proper patch
3. If fails → Test next candidate
4. Repeat until FPS control found

---

## Automated Testing Script

Create script that:
1. Patches candidate location
2. Builds ROM
3. Tests with automated FPS measurement
4. Reports results
5. Moves to next candidate

**Estimated time:** 2-3 hours to test all 15 candidates systematically

---

## Success Criteria

When we find the right candidate:
- Patched ROM shows different FPS behavior (30 → 60 or crash)
- Can verify by:
  - Automated FPS measurement
  - Manual testing
  - Comparing with CTRPF cheat behavior

Once found, create final IPS patch targeting that exact location.
