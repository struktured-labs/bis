- headless testing only unless you want a human test
- use sdl dummy audio driver
- static analysis is not good enough for this problem. you will need to debug dynamically by modding the emulator, with gdb, whatever you can!
- the goal is an ips patch for 30->60fps change. I know the cheat exists, we are looking for better here
- **CRITICAL: Use uv ONLY for all Python operations - NEVER use raw python3, pip, or python commands**
- Make local tmp folder, not /tmp
- **User is STUBBORN** - will not give up despite token costs or setbacks. Come back to hard problems.
- **User prefers COMPACT updates** - focus on code changes and test results, not verbose explanations

## Latest Findings (Jan 20, 2026)

### 🔴 CRITICAL DISCOVERY: GDB Watchpoint Proof (8+ hours investigation)

**THE GAME NEVER ACCESSES ADDRESS 0x30000075**

- Hardware watchpoint set on 0x30000075 (read + write)
- Ran for 60 seconds during gameplay
- **ZERO HITS** - game code never reads or writes this address
- Proof: `tmp/gdb_fps_watchpoint.log` and `build/gdb_attach_watchpoint.sh`

**What This Means:**
- CTRPF cheat writes to 0x30000075, but game doesn't read it
- The cheat likely hooks/patches game code at RUNTIME (not just memory writes)
- 0x30000075 may be a flag for CTRPF framework itself to trigger patches
- Our 8 hours of static analysis searching for 0x75 reads was wrong approach

**Address 0x30000075 is in PLUGIN MEMORY (0x30000000-0x30010000)**
- Runtime-allocated by Luma3DS/CTRPF framework
- NOT in ROM - cannot be directly patched in game files

### What We Tried (All Failed)

**Phase 1: CRO Module Patches** ✅ Stable but 30 FPS
- Patched all 12 CRO modules at offset 0x76
- ROM loads perfectly, no crashes
- Still 30 FPS (main code frame limiter overrides)

**Phase 2: Float Constant Patches** ❌ Failed
- Found 9 float 30.0 constants, created 8 test ROM combinations
- ALL still 30 FPS - these are not the frame limiter

**Phase 3: LDRB Scanner (0x75 immediate)** ❌ Failed
- Scanned 912,210 Thumb instructions
- Found 371 uses of immediate 0x75
- Tested 15 high-priority candidates
- Results: 6 crashed, 9 ran at 30 FPS, **0 achieved 60 FPS**
- Crash analysis: All used 0x75 for struct offsets, not FPS control

**Phase 4: GDB Watchpoint** ✅ Working, Revealed Truth
- `build/gdb_attach_watchpoint.sh` - fully automated
- Proved game never accesses 0x30000075

### Infrastructure Built
- Custom Lime3DS with FPS logging (working)
- Automated ROM generation pipeline (working)
- GDB attach methodology (working)
- Comprehensive analysis scripts (see `build/scan_*.py`, `build/analyze_*.py`)

### Next Approaches (When We Return)
1. **Analyze CTRPF framework code** - understand how runtime hooking works
2. **Search VBlank/GSP calls** - 1042 SVC instructions found, analyze for frame limiting
3. **Try 0x74 candidates** - CTRPF checks this before 0x75, maybe it's the real control
4. **Emulator-side unlock** - Modify Citra to force 60fps (emulator-only solution)
