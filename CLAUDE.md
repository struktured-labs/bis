- headless testing only unless you want a human test
- use sdl dummy audio driver
- static analysis is not good enough for this problem. you will need to debug dynamically by modding the emulator, with gdb, whatever you can!
- the goal is an ips patch for 30->60fps change. I know the cheat exists, we are looking for better here
- **CRITICAL: Use uv ONLY for all Python operations - NEVER use raw python3, pip, or python commands**
- Make local tmp folder, not /tmp
- **NEVER ask user to manually test/capture things. AUTOMATE IT. Build infrastructure for permanent automated testing. User should enable you to test, not do testing themselves.**
- **User is STUBBORN** - will not give up despite token costs or setbacks. Come back to hard problems.
- **User prefers COMPACT updates** - focus on code changes and test results, not verbose explanations

## SOLVED: 60fps IPS Patch (Feb 16, 2026)

### Working Patch: `patches/60fps.ips` (26 bytes)

**Two ARM instruction patches in decompressed code.bin:**

| File Offset | Virtual Addr | Original | Patched | Description |
|-------------|-------------|----------|---------|-------------|
| 0x03E918 | 0x13E918 | `E5D4103D` LDRB R1,[R4,#0x3D] | `E3A01000` MOV R1,#0 | Main frame loop FPS check |
| 0x180A84 | 0x280A84 | `E5D4003D` LDRB R0,[R4,#0x3D] | `E3A00000` MOV R0,#0 | Init-time FPS check |

**Result:** 29.8 FPS -> 59.7 FPS (verified 4 automated headless runs)

**How it works:** Game stores FPS mode byte at heap struct offset +0x3D (address 0x320DA3AD at runtime). Value 0x01 = 30fps, 0x00 = 60fps. The patch replaces both LDRB reads with MOV #0, forcing 60fps mode regardless of the stored value.

**IPS patch applies via emulator mod system:** Place at `~/.local/share/azahar-emu/load/mods/00040000001D1400/exefs/code.ips`

### How We Found It (Investigation Chain)
1. SVC instrumentation -> game uses WaitSync1 on VBlank for frame timing
2. VBlank patches break game -> can't bypass sync directly
3. Cheat engine instrumentation -> only ONE byte write matters (0x320DA3AD = 0x00)
4. Disabled dynarmic fastmem + memory watchpoints -> found reader PCs
5. Disassembled readers -> both LDRB from struct+0x3D
6. IPS patch: replace LDRB with MOV #0 -> forces 60fps

### Testing Infrastructure
- Custom Lime3DS with FPS CSV logging (build/emulator/)
- `build/test_60fps_patch.sh` - A/B headless FPS verification
- Headless stack: `DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe QT_QPA_PLATFORM=xcb SDL_AUDIODRIVER=dummy`

### IPS Format Reference
- Header: `PATCH` (5 bytes)
- Records: 3-byte BE offset + 2-byte BE size + LE data
- Footer: `EOF` (3 bytes)
- Offsets are into decompressed code.bin (vaddr = offset + 0x100000)
