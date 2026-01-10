# Mario & Luigi: BIS+BJJ - Comprehensive 60fps Patch

## What Changed

**Previous attempts**: Only patched AttackMiniGame.cro → only affected attack minigames

**This solution**: Patched **ALL 12 CRO modules** that control FPS across different game modes:

| CRO Module | Game Mode | Status |
|------------|-----------|--------|
| AttackMiniGame.cro | Attack minigames | ✓ Patched |
| Battle.cro | Battle sequences | ✓ Patched |
| BCat.cro | StreetPass/SpotPass | ✓ Patched |
| Colosseum.cro | Arena mode | ✓ Patched |
| **HugeBattle.cro** | **Boss battles** | ✓ Patched |
| **KJMenu.cro** | **Bowser Jr menus** | ✓ Patched |
| **KJRPG.cro** | **Bowser Jr gameplay** | ✓ Patched |
| **LoadMenu.cro** | **Loading screens** | ✓ Patched |
| **MainMenu.cro** | **Main menus** | ✓ Patched |
| SaveLoad.cro | Save/Load screens | ✓ Patched |
| SaveMenu.cro | Save menu | ✓ Patched |
| ShopMenu.cro | Shop interface | ✓ Patched |

**Shared code modules** (don't need separate patches):
- Field.cro → shares with HugeBattle.cro
- KJGuide.cro → shares with KJMenu.cro  
- MenuGuide.cro → shares with SaveLoad.cro

## Technical Details

**Patch**: MOV R2, #1 → MOV R2, #0 (0xE3A02001 → 0xE3A02000)
- Changes FPS flag from 30fps to 60fps
- Applied at specific offset in each CRO module
- Uses LayeredFS for easy testing/reversal

**Installation**: LayeredFS mods in:
- `~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/`
- `~/.local/share/lime3ds-emu/load/mods/00040000001D1400/romfs/`

## Testing

Run: `./build/test_all_cro_patches.sh`

**What to test:**
1. **Title screen** - should feel smoother
2. **Overworld** - walking around
3. **Battle** - enter a battle
4. **Menus** - navigate menus
5. **Attack minigames** - try an attack

**Expected behavior:**
- Game runs at 60fps in ALL modes
- No crashes or freezes
- Smoother animations
- More responsive controls

## Why This Should Work

The expert was right - we were missing the central problem:

1. **Each game mode** loads its own CRO module
2. **Each CRO** initializes its own FPS value
3. **Patching just one** only fixes that specific mode
4. **Patching all 12** fixes the entire game

## Verification Needed

⚠️ **Important**: We need to actually measure FPS to confirm this works!

The CTRPF cheat continuously writes to memory, suggesting:
- Game might reset FPS every frame
- May need additional patches beyond CRO initialization
- Frame limiter in main code might also need patching

## Next Steps if This Doesn't Work

1. **Add FPS measurement** to emulator
2. **Check main code.bin** for frame limiter
3. **Patch float constants** (30.0 → 60.0) if needed
4. **Consider ROM rebuild** for permanent solution

## Files

**Patched CROs**: `tmp/cro_files_patched/*.cro`
**Test script**: `build/test_all_cro_patches.sh`
**This document**: `COMPREHENSIVE_60FPS_PATCH.md`

🤖 Generated with Claude Code
