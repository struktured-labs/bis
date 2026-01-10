# Mario & Luigi: BIS+BJJ - FINAL 60fps Solution

## The Working Approach

After trying LayeredFS (CRO integrity failures) and ROM rebuilds (corruption issues), the solution is:

**Direct binary patching of the original ROM**

## What Was Patched

All **12 unique CRO module locations** covering every game mode:

| Offset in ROM | CRO Module | Game Mode |
|---------------|------------|-----------|
| 0x192ABD1C | AttackMiniGame.cro | Attack minigames |
| 0x192BD16C | Battle.cro | Regular battles |
| 0x1933DB70 | BCat.cro | StreetPass |
| 0x19348640 | Colosseum.cro | Arena |
| 0x193626DC | Field/HugeBattle | Overworld & bosses |
| 0x1952D388 | KJGuide/KJMenu | BJ menus |
| 0x1958F7CC | KJRPG.cro | BJ gameplay |
| 0x195F1794 | LoadMenu.cro | Loading |
| 0x196091E4 | MainMenu.cro | Main menus |
| 0x1964297C | MenuGuide/SaveLoad | Save menus |
| 0x19649A14 | SaveMenu.cro | Save screen |
| 0x1965472C | ShopMenu.cro | Shop |

**Each patch**: Changes 1 byte (0x01 → 0x00) to convert `MOV R2, #1` to `MOV R2, #0`

## Result

**File**: `build/Mario_Luigi_BIS_60fps_FINAL.3ds` (1.0 GB)
- ✓ All 12 CRO modules patched
- ✓ Original ROM structure preserved
- ✓ No rebuilding (no corruption)
- ✓ No LayeredFS (no integrity issues)

## Testing

```bash
./build/test_60fps_FINAL.sh
```

## Why This Works

1. **Direct patching** preserves all ROM structure, headers, signatures
2. **No LayeredFS** means no CRO integrity checks
3. **No 3dstool rebuild** means no potential corruption from re-signing
4. **Patches all game modes** not just one CRO module

## Technical Notes

- ROM offset calculation: `IVFC_offset (0x227000) + romfs_file_offset`
- Cannot use standard IPS format (3-byte offset limit = 16MB max)
- Python script applies patches directly to binary

## Next: Verification

⚠️ **Still need to measure actual FPS to confirm this works!**

The expert was right - measurement is paramount. We need to:
1. Add FPS logging to emulator, OR
2. Use external FPS counter, OR
3. Visually verify smoothness increase

🤖 Generated with Claude Code
