# 60fps Patch: Complete Analysis

**Game:** Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey (USA)
**Title ID:** 00040000001D1400
**Patch:** `patches/60fps.ips` (26 bytes)
**Result:** 29.8 FPS → 59.7 FPS

## The Patch

Two ARM instructions replaced in decompressed code.bin:

| File Offset | Virtual Addr | Original | Patched | Description |
|-------------|-------------|----------|---------|-------------|
| 0x03E918 | 0x13E918 | `E5D4103D` LDRB R1,[R4,#0x3D] | `E3A01000` MOV R1,#0 | Main frame loop FPS check |
| 0x180A84 | 0x280A84 | `E5D4003D` LDRB R0,[R4,#0x3D] | `E3A00000` MOV R0,#0 | Init-time FPS check |

### How It Works

The game allocates a control struct on the heap (NEW_LINEAR_HEAP at 0x30000000). At struct offset +0x3D (runtime address ~0x320DA3AD), a single byte controls the frame rate:
- `0x01` = 30fps (default)
- `0x00` = 60fps

Two code locations read this byte every frame. The patch replaces both LDRB (load byte) instructions with MOV #0, forcing the game to always run in 60fps mode.

### Installation

Copy to emulator mod directory:
```bash
cp patches/60fps.ips ~/.local/share/azahar-emu/load/mods/00040000001D1400/exefs/code.ips
```

For Citra:
```bash
cp patches/60fps.ips ~/.local/share/citra-emu/load/mods/00040000001D1400/exefs/code.ips
```

## Investigation Timeline

### Phase 1: Static Analysis (Failed)
- Patched all 12 CRO modules at offset 0x76 — stable but still 30fps
- Found 9 float 30.0 constants, tested 8 combinations — all 30fps
- Scanned 912,210 Thumb instructions for 0x75 immediate — 371 matches, 15 tested, 0 worked

### Phase 2: GDB Watchpoints (Misleading)
- Set hardware watchpoint on 0x30000075 (the CTRPF cheat target address)
- 300+ seconds monitoring: ZERO hits from game code
- Conclusion: game never accesses that address directly

### Phase 3: SVC Instrumentation (Narrowing Down)
- Instrumented SleepThread → only 4ms polling sleeps, not frame timing
- Instrumented WaitSynchronization1 → game waits on VBlank events (42% of calls)
- VBlank patches all broke the game (0 FPS) — game requires VBlank sync

### Phase 4: Cheat Engine Analysis (Breakthrough)
- Enabled the known-working CTRPF 60fps cheat in emulator
- Instrumented gateway_cheat.cpp Write8/Write16/Write32
- **Only ONE write executed:** address 0x320DA3AD, value 0x00, old value 0x01
- All other cheat blocks (0x30000075, 0x30000065, 0x30000045) failed their conditions

### Phase 5: Memory Watchpoints (Solution)
- Disabled dynarmic fastmem (JIT direct memory bypasses read/write callbacks)
- Added file-based watchpoint logging for address range 0x320DA3A0-0x320DA3B0
- 10,000 hits captured:
  - PC 0x30B8FC: First init writes 0x320DA3AD = 0x00 (60fps initially!)
  - PC 0x301928: Second init writes 32-bit 0x01000101 to 0x320DA3AC, **overwriting 0x320DA3AD to 0x01** (30fps!)
  - PC 0x13E8E8: Reads 0x320DA3AD **every frame** (1663 reads in ~55s)
- Disassembled reader at 0x13E918: `LDRB R1, [R4, #0x3D]`
- Created IPS patch replacing LDRB with MOV #0

## CTRPF Cheat Decoded

```
D3000000 30000000     ; Set offset = 0x30000000 (NEW_LINEAR_HEAP)
50000074 01000101     ; IF [0x30000074] == 0x01000101
20000075 00000000     ;   Write 0x00 to [0x30000075]
D0000000 00000000     ; END IF
520DA3AC 01000101     ; IF [0x300DA3AC] == 0x01000101  ← THIS IS THE ONE THAT FIRES
220DA3AD 00000000     ;   Write 0x00 to [0x300DA3AD]  ← THE ACTUAL WRITE
D0000000 00000000     ; END IF
50000064 01000101     ; IF [0x30000064] == 0x01000101
20000065 01000000     ;   Write 0x00 to [0x30000065]
D0000000 00000000     ; END IF
50000044 01000101     ; IF [0x30000044] == 0x01000101
20000045 00000000     ;   Write 0x00 to [0x30000045]
D0000000 00000000     ; END IF
D2000000 00000000     ; END ALL
```

The cheat continuously overwrites the byte every ~50ms. Our IPS patch is better: it patches the game code itself so the byte is never read, making the fix permanent without runtime patching.

## Key Technical Details

- **0x30000000** is NEW_LINEAR_HEAP_VADDR (game heap), NOT CTRPF plugin memory
- **Fastmem** (dynarmic `config.page_table`) must be disabled for memory watchpoints to work
- **IPS format:** offsets are into decompressed code.bin, data is little-endian ARM
- **Address mapping:** virtual_addr = file_offset + 0x100000

## Infrastructure

- Custom Lime3DS/Azahar with FPS CSV logging
- Automated headless testing: `build/test_60fps_patch.sh`
- Memory watchpoint system in `arm_dynarmic.cpp`
- SVC instrumentation in `svc.cpp`
- Cheat engine logging in `gateway_cheat.cpp`

## 36+ ROMs Tested, Only 1 Worked

| Approach | ROMs Tested | Result |
|----------|-------------|--------|
| CRO module patches | 1 | Stable, 30fps |
| Float 30.0 → 60.0 | 8 | All 30fps |
| LDRB #0x75 NOPs | 15 | 6 crashed, 9 at 30fps |
| VBlank/frame skip | 6 | All 0fps or 30fps |
| LDRB reader → MOV #0 | 1 | **59.7 FPS** |
