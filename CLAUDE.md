- headless testing only unless you want a human test
- **AUDIO: ALWAYS use `SDL_AUDIODRIVER=dummy` AND set `volume=0` + `volume\default=false` in `~/.config/azahar-emu/qt-config.ini` before ANY emulator launch. The config resets itself so check EVERY time.**
- static analysis is not good enough for this problem. you will need to debug dynamically by modding the emulator, with gdb, whatever you can!
- the goal is an ips patch for 30->60fps change. I know the cheat exists, we are looking for better here
- **CRITICAL: Use uv ONLY for all Python operations - NEVER use raw python3, pip, or python commands**
- Make local tmp folder, not /tmp
- **NEVER ask user to manually test/capture things. AUTOMATE IT. Build infrastructure for permanent automated testing. User should enable you to test, not do testing themselves.**
- **User is STUBBORN** - will not give up despite token costs or setbacks. Come back to hard problems.
- **User prefers COMPACT updates** - focus on code changes and test results, not verbose explanations

## SOLVED: 60fps IPS Patch

### v1.0 Patch: `patches/60fps.ips` (26 bytes)

| File Offset | Virtual Addr | Original | Patched | Description |
|-------------|-------------|----------|---------|-------------|
| 0x03E918 | 0x13E918 | `E5D4103D` LDRB R1,[R4,#0x3D] | `E3A01000` MOV R1,#0 | Main frame loop FPS check |
| 0x180A84 | 0x280A84 | `E5D4003D` LDRB R0,[R4,#0x3D] | `E3A00000` MOV R0,#0 | Init-time FPS check |

**Result:** 29.8 FPS -> 59.7 FPS (verified 4 automated headless runs)

### v1.2 (latest update) Patch: `patches/60fps_update_v1.2.ips` (26 bytes)
Note: CIA/TMD internal version is "v2080" (2.2), but Nintendo's official game version is 1.2.

| File Offset | Virtual Addr | Original | Patched | Description |
|-------------|-------------|----------|---------|-------------|
| 0x03E8E8 | 0x13E8E8 | `E5D4103D` LDRB R1,[R4,#0x3D] | `E3A01000` MOV R1,#0 | Main frame loop FPS check |
| 0x180A5C | 0x280A5C | `E5D4003D` LDRB R0,[R4,#0x3D] | `E3A00000` MOV R0,#0 | Init-time FPS check |

**Result:** 28.7 FPS -> 57.6 FPS (verified automated headless A/B test)

**How it works:** Game stores FPS mode byte at heap struct offset +0x3D (address 0x320DA3AD at runtime). Value 0x01 = 30fps, 0x00 = 60fps. The patch replaces both LDRB reads with MOV #0, forcing 60fps mode regardless of the stored value.

**IPS patch applies via emulator mod system:** Place at `~/.local/share/azahar-emu/load/mods/00040000001D1400/exefs/code.ips`

### v2 Enhanced Patch: `patches/60fps_v2.ips` (v1.0) / `patches/60fps_v2_update_v1.2.ips` (v1.2) (53 bytes each)

Fixes dynamic FPS control — the original 2-patch only forces 2 read sites to 60fps, but the game has a **4-level dynamic FPS setter** that writes 0/1/2/3 to the FPS byte. 14 other read sites still see the memory value (30fps), causing inconsistencies during scene transitions, particle effects, etc.

The v2 patch adds 3 writer-side patches to force the FPS setter to always write 0 (60fps):

| File Offset (v1.2) | File Offset (v1.0) | Original | Patched | Description |
|---------------------|---------------------|----------|---------|-------------|
| 0x03E8E8 | 0x03E918 | `E5D4103D` LDRB R1,[R4,#0x3D] | `E3A01000` MOV R1,#0 | Main frame loop read |
| 0x180A5C | 0x180A84 | `E5D4003D` LDRB R0,[R4,#0x3D] | `E3A00000` MOV R0,#0 | Init-time read |
| 0x17C224 | 0x17C24C | `E3A00003` MOV R0,#3 | `E3A00000` MOV R0,#0 | FPS setter: level 3→0 |
| 0x17C238 | 0x17C260 | `E3A00002` MOV R0,#2 | `E3A00000` MOV R0,#0 | FPS setter: level 2→0 |
| 0x17C24C | 0x17C274 | `E3A00001` MOV R0,#1 | `E3A00000` MOV R0,#0 | FPS setter: level 1→0 |

**FPS setter function** (v1.2 at vaddr 0x27C220): Compares scene complexity thresholds at [R1,#0xA] and [R1,#0xC], sets FPS level 0-3. The STRB at 0x27C260 writes to struct+0x3D. By patching all MOV Rx,#N to MOV Rx,#0, the memory always holds 0 (60fps), so ALL 16 reader sites see consistent 60fps.

**Result:** 52.4 avg FPS (75% of frames >50fps). Prevents dynamic 30fps drops during particle effects and scene transitions.

**Total LDRB [Rx, #0x3D] sites found:** 16 (only 2 patched in v1, all covered by writer patch in v2)

### v3 Comprehensive Patch: `patches/60fps_v3_update_v1.2.ips` (89 bytes, 9 sites)

Full coverage of ALL +0x3D readers and writers in code.bin. Generator: `build/gen_60fps_v3.py`

| File Offset | Type | Original | Patched | Description |
|-------------|------|----------|---------|-------------|
| 0x012B54 | Reader | LDRB R2,[R4,#0x3D] | MOV R2,#0 | Render flag setter 1 |
| 0x012CB0 | Reader | LDRB R2,[R4,#0x3D] | MOV R2,#0 | Render flag setter 2 |
| 0x03E8E8 | Reader | LDRB R1,[R4,#0x3D] | MOV R1,#0 | Main frame loop |
| 0x0828DC | Writer | STRBNE R0,[R4,#0x3D] | NOP | Conditional FPS writer |
| 0x14B44C | Writer | STRB R0,[R4,#0x3D] (R0=0xFF) | STRB R5,[R4,#0x3D] (R5=0) | Init writer |
| 0x17C260 | Writer | STRB R0,[R4,#0x3D] | STRB R2,[R4,#0x3D] (R2=0) | FPS setter writer |
| 0x180A5C | Reader | LDRB R0,[R4,#0x3D] | MOV R0,#0 | Init-time reader |
| 0x263250 | Reader | LDRB R0,[R4,#0x3D] | MOV R0,#0 | FPS wrapper (FUN_00263244) |
| 0x26C114 | Reader | LDRB R1,[R4,#0x3D] | MOV R1,#0 | Render flag setter 3 |

**Result:** avg 60.2 FPS, min 58.5, 0 sub-50 FPS drops (verified `build/test_v3_patch.sh`)

### Giant Battle CRO Fix: `tmp/HugeBattle_patched.cro`

HugeBattle.cro (dynamically loaded CRO module) has its own STRB to +0x3D that bypasses code.bin patches.
Generator: `build/patch_hugebattle_cro.py`

| CRO Offset | Original | Patched | Description |
|------------|----------|---------|-------------|
| 0x0EFC60 | STRB R1,[R0,#0x3D] (R1=1=30fps) | NOP | Giant battle FPS writer |
| 0x0A90A8 | STRB R4,[R0,#0x3D] | NOP | Unknown value writer |

Install: `~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/RO/HugeBattle.cro`

### How We Found It (Investigation Chain)
1. SVC instrumentation -> game uses WaitSync1 on VBlank for frame timing
2. VBlank patches break game -> can't bypass sync directly
3. Cheat engine instrumentation -> only ONE byte write matters (0x320DA3AD = 0x00)
4. Disabled dynarmic fastmem + memory watchpoints -> found reader PCs
5. Disassembled readers -> both LDRB from struct+0x3D
6. IPS patch: replace LDRB with MOV #0 -> forces 60fps
7. Found 16 total LDRB [Rx, #0x3D] sites, only 2 patched -> FPS byte mismatch during transitions
8. Found 4-level dynamic FPS setter (writes 0/1/2/3) -> patched writer to always write 0
9. Found 31 total +0x3D instructions in code.bin -> v3 patches all relevant readers AND writers
10. Found HugeBattle.cro has own 30fps writer (0x0efc60) -> patched CRO directly

### Halfspeed Patch: `patches/60fps_halfspeed_v1.2.ips` (44 bytes, 4 records)

**60fps rendering + 30Hz game logic** - correct game speed at 60fps. Self-contained IPS patch, no emulator mods.

| File Offset | Original | Patched | Description |
|-------------|----------|---------|-------------|
| 0x03E8E8 | LDRB R1,[R4,#0x3D] | MOV R1,#0 | Force 60fps mode (main) |
| 0x180A5C | LDRB R0,[R4,#0x3D] | MOV R0,#0 | Force 60fps mode (init) |
| 0x03DF7C | CPY R10,R5 | B 0x3E900 | Branch to trampoline |
| 0x03E900 | (dead code) | 8-instr trampoline | Self-contained toggle + skip |

**Trampoline** (in dead mode-2 code space 0x3E900-0x3E91C):
```
LDRB R0,[R4,#0x48]   ; load toggle
EOR R0,R0,#1          ; flip 0↔1
STRB R0,[R4,#0x48]   ; store
CMP R0,#0             ; check
BEQ skip_logic        ; if 0, skip
CPY R10,R5            ; replicate replaced instruction
B 0x3DF80             ; run full game logic (1060 bytes)
skip_logic:
B 0x3E3A4             ; skip entire game logic block
```

**Result:** 29.8-30.1 game fps, 59.6-60.1 system fps (verified automated headless test)
**Gameplay verified:** Dialogue, character animation, NPC interaction all working correctly in new game intro (Toad house scene). Game runs at correct 1x speed.

**Key insight:** Previous v1 approach skipped only vtable[0x1C]/[0x20] (40 bytes) - those aren't the real game logic. The REAL frame-skip (mode 2) jumps from 0x3DF74 to 0x3E3A4, skipping the full 1060-byte game logic block. The halfspeed patch replicates this skip on alternating frames.

Generator: `build/make_halfspeed_patch.py`

### Testing Infrastructure
- Custom Lime3DS with FPS CSV logging (build/emulator/)
- `build/test_60fps_patch.sh` - A/B headless FPS verification
- `build/test_v3_patch.sh` - v3 + CRO patch test (3 min, PASSED)
- `build/test_skip_counter.sh` - halfspeed trampoline verification
- Headless stack: `DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe QT_QPA_PLATFORM=xcb SDL_AUDIODRIVER=dummy`

### IPS Format Reference
- Header: `PATCH` (5 bytes)
- Records: 3-byte BE offset + 2-byte BE size + LE data
- Footer: `EOF` (3 bytes)
- Offsets are into decompressed code.bin (vaddr = offset + 0x100000)
