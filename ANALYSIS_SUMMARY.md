# Mario & Luigi: BIS+BJJ 60fps ROM Patch Analysis

## Summary

After extensive analysis using Ghidra, Capstone, and manual binary inspection, 
we were **unable to create a working permanent ROM patch** for 60fps on this game.

## Key Findings

### 1. ARM STRB Instructions Found but Are DATA, Not Code

Found 6 locations that decode as valid ARM STRB instructions with FPS-related offsets:

| Address    | Instruction              | Note |
|------------|--------------------------|------|
| 0x013B20   | strbeq r0,[r4,#0x75]    | Crashes when modified |
| 0x013B24   | strbne r5,[r4,#0x75]    | Crashes when modified |
| 0x01DB6C   | strbeq r5,[r4,#0x64]    | Crashes when modified |
| 0x1028E4   | strb r6,[r0,#0x74]      | Crashes when modified |
| 0x15B0D4   | strb r5,[r4,#0x64]      | Crashes when modified |
| 0x184BE8   | strbeq r0,[r4,#0x64]    | Crashes when modified |

**Problem**: These bytes are NOT executable code - they are data that happens to 
decode as ARM instructions. Any modification crashes the game.

### 2. No Thumb Code Found for FPS Access

- Searched entire binary for Thumb STRB/LDRB to offsets 0x64/0x65/0x74/0x75
- Found 0 matches
- The actual FPS control code uses indirect addressing we cannot trace statically

### 3. Float Constants Found but Not Patchable

Found float 30.0 (0x41F00000) at 9 locations, including one referenced by code:
- 0x0C6EE4: Referenced by LDR at 0x0C6BAC

Patching 30.0 → 60.0 also crashes the game.

### 4. CTRPF Cheat Mechanism

The working CTRPF cheat operates at RUNTIME:
```
D3000000 30000000   # Set base to LINEAR heap (0x30000000)
50000074 01000101   # Check if pattern exists
20000075 00000000   # Write 0x00 to enable 60fps
```

The cheat works by continuously overwriting runtime memory, which we cannot 
replicate with a static ROM patch.

## Tested Patches (All Failed)

| Version | Approach | Result |
|---------|----------|--------|
| v21     | Make STRB unconditional + NOP | Crash |
| v22     | Selective STRB changes | Crash |
| v23     | Single instruction change | Crash |
| v24     | NOP all FPS STRB | Crash |
| v25     | Float 30.0 → 60.0 | Crash |

## Recommendation

**Continue using the CTRPF runtime cheat code.** The game's architecture does not 
allow for a simple static ROM patch to change FPS. The FPS control:

1. Uses dynamically-allocated memory at runtime
2. Is continuously reset every frame
3. Cannot be traced to a single code location

The CTRPF cheat is specifically designed for this scenario and remains the only 
viable solution for 60fps on this title.

## Files Generated

- `patches/60fps_v21.ips` through `v25.ips` - All crash
- `ghidra_analysis/*.py` - Analysis scripts
- Various log files documenting the investigation

## Technical Details

- Binary: code.bin (1,914,892 bytes)
- Processor: ARM v7, mixed ARM/Thumb code
- 4,685 Thumb functions identified
- 4 SVC #0x25 (WaitSynchronization) calls found
- LINEAR heap base: 0x30000000

The code.bin contains mostly Thumb code but the bytes that decode as FPS-related 
ARM instructions are in data sections. Modifying them corrupts the game's data 
structures causing immediate crashes.

## Additional Deep Dive Findings (v26 attempt)

### Memory Allocation Analysis
- Found 12 SVC #0x01 (svcControlMemory) calls
- None showed FPS-related initialization after allocation
- STRB instructions near allocation are unrelated to FPS

### Pattern Searches
- Found STRB.W R7, [R1, #0x76] at 0x1C1592
- Preceded by MOVS R7, R0 at 0x1C1590
- Patching to MOVS R7, #0 crashes the game
- The 0x76 offset is adjacent to target 0x75 but not the actual control

### Code Quality Issues  
- Most of the binary does not disassemble coherently
- Thumb disassembly produces invalid instruction sequences
- This suggests heavy data/code interleaving or obfuscation

### Conclusion
The game's architecture makes static patching extremely difficult.
The FPS control uses runtime-allocated memory with values that are
continuously refreshed, requiring a runtime cheat rather than a ROM patch.
