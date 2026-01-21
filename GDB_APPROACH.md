# GDB Watchpoint Approach - FPS Control Discovery

**Status:** Ready to execute
**Time Required:** 10-15 minutes of manual interaction

---

## What This Does

Sets a **memory watchpoint** on address `0x30000075` (the FPS control byte) and captures:
- Program Counter (PC) when the address is accessed
- Full backtrace showing call chain
- Disassembly of the code accessing it
- Register state at that moment

This will **definitively** find the FPS control code.

---

## How to Run

```bash
./build/gdb_fps_watchpoint.sh
```

## Steps During Execution

1. **Script starts** → GDB launches Citra with the ROM
2. **Game loads** → Wait for title screen to appear
3. **Press Ctrl+C** → Break into GDB debugger
4. **Type:** `watch_fps` → Sets watchpoint on 0x30000075
5. **Press Enter** → Game continues
6. **Watchpoint hits** → GDB breaks with analysis
7. **Results saved** → `tmp/gdb_fps_watchpoint.log`

**Alternative Quick Mode:**
- Instead of Ctrl+C + `watch_fps`, just type `auto_watch`
- Automatically sets watchpoint after 10 seconds

---

## What We'll Get

When the watchpoint hits, we'll see:

```
===================================================================
  WATCHPOINT HIT - FPS Control Code Found!
===================================================================

--- Registers ---
rax            0x30000075
...

--- Call Stack ---
#0  0x0040ABCD in <function>
#1  0x00123456 in <caller>
...

--- Disassembly ---
0x0040ABC0: ldr r0, =0x30000000
0x0040ABC4: add r0, #0x75
0x0040ABC8: ldrb r1, [r0]        ← This is the FPS read!
0x0040ABCA: cmp r1, #0x01
0x0040ABCC: beq fps_30_branch
...
```

The PC address (e.g., `0x0040ABC8`) tells us exactly where in code.bin the FPS byte is being accessed.

---

## After We Find It

Once we have the PC:

1. **Calculate code.bin offset:**
   ```
   code_offset = PC_address - game_base_address
   ```

2. **Analyze the instruction:**
   - What is it doing with the FPS byte?
   - Is it a comparison? A branch?
   - What values is it checking?

3. **Create targeted patch:**
   - **If it's a branch:** NOP the conditional branch
   - **If it's a comparison:** Change the comparison value
   - **If it's loading a value:** Modify what gets loaded

4. **Test the patch:**
   - Apply patch to code.bin
   - Rebuild ROM
   - Verify 60 FPS achieved

---

## Expected Timeline

- **GDB setup:** 2 minutes
- **Get to title screen:** 1 minute
- **Set watchpoint:** 30 seconds
- **Watchpoint hits:** Immediately (FPS checked every frame)
- **Analyze results:** 5 minutes
- **Create patch:** 30 minutes
- **Test patch:** 10 minutes

**Total:** ~50 minutes to working 60fps patch

---

## Troubleshooting

**Q: Watchpoint never hits?**
- The address might be wrong or not accessed during title screen
- Try playing briefly (enter game, walk around)
- FPS control might only activate during gameplay

**Q: GDB shows "Cannot access memory"?**
- Address might not be mapped yet
- Wait longer before setting watchpoint
- Try `auto_watch` with longer delay

**Q: Multiple watchpoints hit?**
- Good! Each hit shows a different access point
- Analyze all of them to find the FPS control logic
- Look for comparisons or branches

---

## Files

**Script:** `build/gdb_fps_watchpoint.sh`
**GDB Commands:** `tmp/gdb_commands.gdb` (auto-generated)
**Output Log:** `tmp/gdb_fps_watchpoint.log`

---

## Ready?

Run this when ready:
```bash
./build/gdb_fps_watchpoint.sh
```

This is the most reliable method and WILL find the FPS control code if the address 0x30000075 is correct.
