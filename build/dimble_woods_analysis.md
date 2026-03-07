# Dimble Woods One-Way Path Bug Analysis

## Bug Description
At 60fps, a path near the carrot minigame area in Dimble Woods becomes one-directional.
- Reproducible on emulator AND real 3DS hardware at 60fps
- Does NOT happen at 30fps
- Video: https://drive.proton.me/urls/TBVPXYVTHG#iKpElZgwBU7o

## Internal Game Data
- **Internal name**: "Ekubon" = Dimble Woods
- **Area ID**: Ekubon_15 (carrot minigame area)
- **Event scripts**: `o_ekubon_15.fev` (overworld), `k_o_ekubon_15.fev` (Bowser)
- **Sub-area**: `o_ekubon_15_SA_giganin_01_U.fev` (giant carrot event)
- **Archive**: FEvent.dat (BG4 format, 6.4MB packed event scripts)

## Root Cause Hypothesis
The game uses **fixed timestep without delta-time compensation**. At 60fps:
- Frame-counted timers complete in half the real time
- Event scripts execute at double rate
- Position updates happen twice as often with same per-frame displacement

This creates timing asymmetries where:
1. A collision toggle/trigger with a frame-counted enable window is too short at 60fps
2. A moving obstacle completes its cycle twice as fast
3. An event script "wait N frames" command gates passage, closing too early

## Key Engine Classes
| Class | Role |
|-------|------|
| `fld::EventSystem` | Field event execution |
| `fld::EventSystemBaseImplementCommand` | Event command processor |
| `fld::TimerObj` | Frame-based timer objects |
| `kj::ObjTimer` | Generic timer |
| `kj::ObjCountDown` | Countdown timer |
| `fld::MoveC/F/V` | Character movement |
| `fld::PlayerPartyMario/Koopa` | Player character state machines |
| `fld::System_StateMain_Process_BeginMapJump` | Area transitions |

## Collision System
- `$col_chr` - Character collision
- `$col_map` - Map collision
- `SET_COL` - Set collision
- `SET_COL_AREA` - Set collision area
- 16+ collision layer types (col_00 through col_15)

## What We Need to Proceed
1. **USA save file at Dimble Woods** (EUR save incompatible with USA ROM)
2. OR: **EUR base ROM** to use with existing EUR save
3. OR: **Memory hack/cheat** to warp to Ekubon_15 area
4. OR: **FEvent.dat format documentation** to decode area 15 event scripts

## Potential Fixes
### Option A: Per-area timer fix (targeted)
- Decode FEvent.dat format, find the specific timer in Ekubon_15
- Patch the timer threshold to double its value
- Requires understanding the FEvent binary scripting format

### Option B: Global timer speed compensation (broad)
- Find the base timer tick/increment function used by event scripts
- When FPS mode = 0 (60fps), increment by 2 instead of 1
- Would fix ALL frame-dependent timing bugs but might break things that already work

### Option C: Game logic tick rate separation (ideal but complex)
- Run game logic at 30 ticks/sec regardless of rendering rate
- Requires finding the main game update dispatch and adding frame-skip logic
- Most robust but high complexity and risk of breaking other things

## Files
- `build/scan_0x3d_accesses.py` - Scans for FPS byte accesses
- `build/dimble_woods_analysis.md` - This document
- `tmp/romfs_v10/` - Extracted v1.0 ROM filesystem
