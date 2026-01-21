# Current State: 60fps Patch Investigation

**Date:** January 20, 2026, End of Day
**Time Invested:** 8+ hours
**Status:** Taking break, will return

---

## 🔴 Critical Discovery

**GDB watchpoint proof: Game NEVER accesses 0x30000075**

- Set hardware watchpoint (read + write) on address 0x30000075
- Ran for 60 seconds during gameplay
- **ZERO HITS** - game never reads or writes this address
- Log: `tmp/gdb_fps_watchpoint.log`
- Script: `build/gdb_attach_watchpoint.sh`

**Implication:** Our entire investigation was searching for the wrong thing. The CTRPF cheat writes to 0x30000075, but the game doesn't use it.

---

## What We Know Works

✅ **CRO patches** - all 12 modules patched at offset 0x76
✅ **ROM stable** - loads without corruption, plays at 30 FPS
✅ **GDB automation** - fully working attach method
✅ **Custom emulator** - Lime3DS with FPS logging
✅ **ROM generation pipeline** - can create/test patches rapidly

---

## What We Know Doesn't Work

❌ Float 30.0 → 60.0 patches (9 locations tested)
❌ Immediate value 0x75 patches (15 candidates, 6 crashed, 9 still 30fps)
❌ Searching for reads from 0x30000075 (game never accesses it)

---

## Files to Read When Returning

1. **NEXT_INVESTIGATION.md** - 5 investigation paths with detailed plans
2. **FILE_REFERENCE.md** - All scripts and what they do
3. **FINAL_STATUS.md** - Full 8-hour summary

---

## Quick Restart Options

**Option A (Quick - 1 hour):** Test 0x74 candidates instead of 0x75
**Option B (Best - 2 hours):** Analyze VBlank/GSP calls (1042 SVC instructions)
**Option C (Deep - 4 hours):** Research CTRPF framework mechanism
**Option D (Fallback):** Emulator-side unlock (guaranteed but emulator-only)

Recommended: **Start with B (VBlank), then A (0x74)**

---

## Key Files Ready to Use

```bash
# GDB watchpoint (working perfectly)
./build/gdb_attach_watchpoint.sh

# Scan instructions (comprehensive)
uv run build/scan_thumb_mode.py

# Test ROM manually
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    $HOME/.local/bin/citra.AppImage "build/Mario_Luigi_BIS_60fps_FINAL.3ds"
```

---

## User Preferences (Updated)

- **STUBBORN** - won't give up despite setbacks
- **COMPACT** - wants code changes and results, not verbose explanations
- **CRITICAL:** Use `uv` ONLY for Python (never raw python3)
- Headless testing unless requesting human test
- Local tmp folder, not /tmp

---

## The Real Problem

The CTRPF cheat probably doesn't just write memory - it likely:
1. Hooks game code at runtime
2. Uses 0x30000075 as a flag for the framework
3. Patches the actual frame limiter when flag changes

**This means:** We need to find WHERE the frame limiter actually is (VBlank calls, GSP, etc), not where 0x30000075 is accessed.

---

## Next Session Action Items

1. Create `build/scan_svc_calls.py` - find VBlank waits
2. Create `build/test_0x74_candidates.py` - test the conditional check byte
3. Run tests, document findings
4. If both fail, analyze CTRPF source code

**Goal:** Find the REAL frame limiter mechanism
