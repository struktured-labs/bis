# Dynamic Analysis Results - 60 FPS ROM Patch Investigation

## Session Summary

Built Azahar emulator from source with GDB stub support and conducted dynamic analysis.

## Key Findings

### 1. FPS Control Mechanism Confirmed
- **FPS byte address**: `0x30000075` (in 3DS LINEAR heap)
- **Value meanings**: 
  - `0x01` = 30 FPS
  - `0x00` = 60 FPS
- Successfully read this value via GDB
- Successfully wrote `0x00` to change to 60fps temporarily
- **CRITICAL**: Game continuously resets value back to `0x01` every frame

### 2. Memory Structure at 0x30000070
```
Offset  Value      Meaning
0x70    02 00 00 00  Unknown
0x74    17 01 0f 00  Byte at +5 is FPS flag
0x78    78 00 00 03  Unknown
0x7C    1d 01 0f 00  Unknown
```

### 3. Static Analysis Attempts

#### Float 30.0 Patches (Failed)
- Found float 30.0 at: 0x0c6ee4, 0x178a44
- Patched to 60.0 - game runs but FPS unchanged
- These floats are likely unrelated to frame timing

#### STRB.W Search (No Matches)
- No STRB.W instructions write to offset 0x75
- FPS write likely uses computed/indirect addressing

#### CTRPF Pattern Search
- Searched for `0x01000101` in LINEAR heap - NOT FOUND
- Pattern may only exist during active gameplay (not title screen)
- Or emulator memory layout differs from hardware

### 4. GDB Watchpoint Issue
- Write watchpoints were accepted by stub (returned OK)
- But never triggered despite value being constantly reset
- Possible causes:
  - GDB stub doesn't fully implement watchpoints
  - Write happens via DMA
  - Write happens in different CPU context

## Emulator Setup (Working)

```bash
# Start headless with GDB stub
cd /home/struktured/projects/bis
env DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 QT_QPA_PLATFORM=offscreen SDL_AUDIODRIVER=dummy \
  ./build/emulator/Lime3DS/build/bin/Release/azahar \
  -g 24689 \
  "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"

# Connect with GDB
gdb-multiarch -ex "set architecture arm" -ex "target remote localhost:24689"
```

## Python GDB Protocol Example

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 24689))

def send_packet(data):
    checksum = sum(ord(c) for c in data) & 0xFF
    packet = f'${data}#{checksum:02x}'
    sock.send(packet.encode())
    return sock.recv(4096)

# Read memory
send_packet('m30000070,10')

# Write memory
send_packet('M30000075,1:00')  # Write 0 to FPS byte
```

## Conclusion

The CTRPF runtime cheat works by continuously overwriting the FPS byte. 
A static ROM patch requires finding the CODE that initializes/resets this value.
Standard debugging (breakpoints, watchpoints) hasn't been able to catch this code.

### Possible Next Steps
1. Use more advanced tracing (instruction tracing)
2. Examine game's vsync/frame timing code
3. Look for memory allocation code that creates the FPS structure
4. Try hardware 3DS with debugging flashcart
