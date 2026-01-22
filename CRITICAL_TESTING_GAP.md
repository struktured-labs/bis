# CRITICAL TESTING GAP DISCOVERED

## The Problem

**All testing has been on TITLE SCREEN only** (no save state available)

## Why This Matters

The 60fps cheat code has **4 separate memory write blocks:**

```
Block 1: 0x30000075 (Plugin memory)
Block 2: 0x0DA3AD   (Game code - THIS IS KEY)
Block 3: 0x30000065 (Plugin memory)
Block 4: 0x30000045 (Plugin memory)
```

### Hypothesis: Each Block Controls Different Game States

| Block | Likely Controls | Test Location |
|-------|----------------|---------------|
| 0x75  | Title screen / Menus | ✅ Tested (title screen) |
| **0xDA3AD** | **Gameplay / Overworld** | ❌ NOT TESTED |
| 0x65  | Battles | ❌ NOT TESTED |
| 0x45  | Cutscenes | ❌ NOT TESTED |

## Evidence

1. **Cheat has multiple conditional blocks** - suggests different states
2. **Block 2 writes to actual game memory** (0xDA3AD) not plugin memory
3. **Documentation says "turn off before giant battles"** - implies battle-specific behavior
4. **"Crashes at scene transitions"** - implies different FPS states per scene

## What This Means

### For Our 36 Test ROMs
- **All tested on title screen only**
- **May have been working in gameplay but we never checked**
- **Need to re-test IN ACTUAL GAMEPLAY**

### For GDB Watchpoints
- **Watchpoints run for 60 seconds on title screen**
- **FPS control might only trigger during gameplay**
- **Need to run watchpoints DURING GAMEPLAY**

## Immediate Action Required

### Option A: Get Save File (FASTEST)
```bash
# Download save file from:
# - GameFAQs saves
# - GBAtemp forums
# - Personal collection
# Place in Citra save directory
```

### Option B: Fast Playthrough (15-20 min)
```bash
# 1. Start new game
# 2. Skip cutscenes (if possible)
# 3. Get to first save point
# 4. Test there
```

### Option C: Use Cheat to Skip to Gameplay
```bash
# Action Replay codes often have:
# - "Start in overworld" cheats
# - "All items" (to test menus)
# - "Battle mode" triggers
```

## Re-Test Priority List

### Test #1: VBlank Candidate #4 (0x14DB7A)
- This was the ONLY one that didn't crash
- **Re-test in gameplay, not title screen**
- Might actually work!

### Test #2: Direct 0xDA3AD Patch
- We tested patching this to 0x00
- **Only tested on title screen**
- Might work in gameplay!

### Test #3: Float 30.0 Patches
- **Some might only affect gameplay FPS**
- Re-test top 3 candidates in overworld

### Test #4: GDB Watchpoint on 0xDA3AD
- Run for 60 seconds **during active gameplay**
- Not on title screen!

## Why No One Caught This

### Testing Methodology
```bash
# Our test script:
env DISPLAY=:0 ... citra rom.3ds &
sleep 40  # Game loads, shows title screen
kill      # Kill without ever entering gameplay
```

**We never got past the title screen in automated tests!**

### Human Testing
User said: "btw 30 fps for test 1 (assuming title screen is a sufficient test)"

**Title screen is NOT a sufficient test!**

## Documentation from Cheat Code

Looking at the "Hold R for 30FPS" version:
```
DD000000 00000100  # If R button pressed
# ... set everything to 0x01 (30fps)
```

This **toggleable** behavior suggests:
- Default: 60fps in gameplay
- Hold R: 30fps for stability during transitions/battles
- **Implies title screen might stay 30fps regardless**

## Next Steps

1. **Get into gameplay** (save file or playthrough)
2. **Re-test top candidates IN GAMEPLAY**
3. **Run GDB watchpoints DURING GAMEPLAY**
4. **Document FPS separately for:**
   - Title screen
   - Overworld
   - Battles
   - Menus
   - Cutscenes

## Expected Outcome

**One or more of our 36 test ROMs probably WORKS in gameplay!**

We just never tested them properly.

---

## Lessons Learned

1. **Always test in target environment** (gameplay, not title screen)
2. **Read cheat documentation carefully** (multiple blocks = multiple states)
3. **Don't assume automated tests caught everything**
4. **FPS control can be scene-specific**

---

## The Silver Lining

We have:
- ✅ Perfect ROM (v1.0, matching cheat)
- ✅ 36 test ROMs ready to re-test
- ✅ GDB automation working
- ✅ Infrastructure for rapid testing

We just need to **test in the right place!**
