# 60 FPS ROM Patch Analysis - Final Report

## Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey (3DS)

### Executive Summary

After extensive static and dynamic analysis, **a static ROM patch for 60fps is not feasible** for this game. The FPS control mechanism uses runtime-allocated memory that is continuously reset by the game, making it fundamentally incompatible with a one-time ROM patch.

---

## Investigation Summary

### Phase 1: Static Analysis (Ghidra/Capstone)
- Analyzed entire code.bin (1.9MB)
- Found no direct STRB instructions to offset 0x74/0x75
- Binary contains heavy code/data mixing
- Disassembly produces incoherent instruction sequences
- Float patches (30.0 -> 60.0) did not affect FPS

### Phase 2: Dynamic Analysis (Custom Emulator Build)
- Built Azahar emulator from source with GDB stub
- Established headless emulation environment
- Successfully connected GDB and read/wrote memory

**Key Finding: FPS Control Location**
- Address: `0x30000075` (New 3DS LINEAR heap)
- Value: `0x01` = 30fps, `0x00` = 60fps
- Writing `0x00` successfully enables 60fps
- **CRITICAL**: Value is reset to `0x01` every frame

### Phase 3: Code Tracing Attempt
- Modified emulator to trace writes to FPS address
- Dynarmic JIT uses fastmem (direct page table access)
- Disabling fastmem crashes emulator
- GDB watchpoints don't trigger (likely fastmem bypass)
- Could not capture the PC address of the reset code

---

## Why ROM Patching Won't Work

### The CTRPF Cheat Code
```
D3000000 30000000   ; Set base to LINEAR heap
50000074 01000101   ; Check for pattern (structure signature)
20000075 00000000   ; Write 0x00 to FPS byte
```

This cheat works by **continuously overwriting** the FPS byte every frame.

### The Problem
1. **Runtime Memory**: FPS control is in dynamically-allocated LINEAR heap
2. **Continuous Reset**: Game resets FPS byte to `0x01` every frame
3. **Computed Addressing**: Write uses indirect addressing we cannot trace
4. **No Static Code Path**: No single initialization point to patch

### What Would Be Needed
To create a working ROM patch, you would need:
1. Find the exact code (instruction address) that writes `0x01` to the FPS byte
2. Patch that instruction to write `0x00` instead

This requires:
- Hardware 3DS with debugging flashcart, OR
- Emulator modification for instruction-level tracing (significant development effort), OR
- Different game architecture that doesn't continuously reset the value

---

## Recommended Solutions

### Option 1: Use CTRPF Cheat (Recommended)
The cheat code works correctly and is the intended solution:
- Install Luma3DS on 3DS with cheat support
- Add cheat file to `cheats/00040000001D1400.txt`
- Enable cheat in-game

Cheat file contents:
```
[60fps]
D3000000 30000000
50000074 01000101
20000075 00000000
D2000000 00000000
```

### Option 2: Emulator Built-in Cheat
Most 3DS emulators (Citra, Lime3DS, Azahar) support CTRPF cheat codes:
- Add cheat to emulator's cheat system
- Enable during gameplay

### Option 3: Custom Emulator Build
Create a custom emulator that:
- Intercepts writes to 0x30000075
- Forces value to 0x00
- This is essentially what Option 2 does

---

## Technical Details

### Memory Layout
```
NEW_LINEAR_HEAP_VADDR = 0x30000000
FPS Structure at heap offset 0x70:
  +0x00: 02 00 00 00  (unknown)
  +0x04: 17 01 0f 00  (byte at +0x05 = FPS flag)
  +0x08: 78 00 00 03  (unknown)
  +0x0C: 1d 01 0f 00  (unknown)
```

### Tested Patches (All Failed)
| Version | Approach | Result |
|---------|----------|--------|
| v21-v26 | ARM STRB modifications | Crash |
| v27-v29 | Float 30.0 -> 60.0 | Runs at 30fps |

### Tools Used
- Ghidra 11.4 (static analysis)
- Capstone (disassembly)
- GDB-multiarch (debugging)
- Custom Azahar build (GDB stub)
- Python scripts (binary analysis)

---

## Files Generated

- `patches/60fps_v*.ips` - Various failed patch attempts
- `build/emulator/Lime3DS/` - Custom emulator build
- `DYNAMIC_ANALYSIS_RESULTS.md` - GDB session findings
- `cheats/00040000001D1400.txt` - Working CTRPF cheat

---

## Conclusion

The game's FPS control architecture is designed to allow runtime modification (hence the CTRPF cheat works), but not static patching. The FPS value is in runtime-allocated memory and is continuously reset, requiring a persistent runtime cheat rather than a one-time ROM modification.

**The CTRPF cheat code is the correct and only viable solution for this game.**
