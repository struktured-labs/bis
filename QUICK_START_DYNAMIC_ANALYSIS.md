# Quick Start: Improved Dynamic Analysis

This guide helps you get started with the new dynamic analysis tooling.

## 🎯 Goal

Identify exactly which code writes to the FPS flag at `0x30000075` by tracing execution at runtime.

## 🚀 Quick Wins (Choose One)

### Option 1: Emulator Memory Tracing (RECOMMENDED)
**Time**: 30 minutes | **Difficulty**: Easy | **Output**: PC addresses writing to FPS flag

1. **Set up the patch**:
   ```bash
   cd /home/user/bis
   ./tools/setup_memory_tracing.sh
   ```

2. **Apply patch to emulator**:
   ```bash
   cd build/emulator/Lime3DS
   git apply ../../tools/emulator_patches/memory_trace.patch
   ```

3. **Rebuild with tracing enabled**:
   ```bash
   cd build
   cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_MEMORY_TRACING=ON
   make -j$(nproc)
   ```

4. **Run and capture trace**:
   ```bash
   cd /home/user/bis
   export CITRA_LOG=memory:warning
   ./build/emulator/Lime3DS/build/bin/citra-qt build/Mario_Luigi_BIS.3ds \
       2>&1 | grep MEM_TRACE | tee tmp/memory_trace.log
   ```

5. **Analyze results**:
   ```bash
   uv run tools/analyze_memory_trace.py tmp/memory_trace.log
   ```

**Expected output**: List of PC values that write to `0x30000075`, which you can then analyze in Ghidra.

---

### Option 2: rr Record and Replay
**Time**: 15 minutes | **Difficulty**: Medium | **Output**: Full backtrace with reverse execution

1. **Run the automated setup**:
   ```bash
   cd /home/user/bis
   ./tools/setup_rr_trace.sh build/Mario_Luigi_BIS.3ds
   ```

2. **Follow the interactive prompts** - it will:
   - Record a test session
   - Replay with GDB attached
   - Set watchpoint on `0x30000075`
   - Show you backtraces when it's written

3. **Use reverse execution**:
   ```gdb
   (gdb) continue          # Run until FPS flag is written
   (gdb) backtrace         # See call stack
   (gdb) reverse-continue  # GO BACKWARDS to previous write!
   (gdb) backtrace         # See what called it before
   ```

**Expected output**: Full call stacks showing which functions write to FPS flag, with ability to go backwards in time.

---

### Option 3: Frida Runtime Instrumentation
**Time**: 20 minutes | **Difficulty**: Hard | **Output**: Live tracing with backtraces

1. **Install Frida**:
   ```bash
   uv pip install frida-tools
   ```

2. **Ensure emulator has symbols**:
   ```bash
   # Rebuild with debug symbols if needed
   cd build/emulator/Lime3DS/build
   cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
   make -j$(nproc)
   ```

3. **Attach Frida**:
   ```bash
   cd /home/user/bis
   frida -l tools/frida_fps_trace.js -f build/emulator/Lime3DS/build/bin/citra-qt \
         -- build/Mario_Luigi_BIS.3ds
   ```

4. **Watch live output** - Frida will print:
   - Every write to FPS flag
   - Backtraces showing calling functions
   - Statistics on exit

**Expected output**: Real-time trace of FPS flag writes with full backtraces.

---

## 📊 After Getting PC Values

Once you have PC addresses that write to the FPS flag:

1. **Open Ghidra** with your game code binary (extracted CRO or game code)

2. **Navigate to each PC**:
   - Press `G` (Go To)
   - Enter address (e.g., `0x001a2b3c`)
   - Analyze the surrounding code

3. **Look for**:
   - Function boundaries (what function is this in?)
   - Loops (is it writing every frame?)
   - Conditional branches (what controls whether it writes 0x00 or 0x01?)
   - Function calls (what other functions are involved?)

4. **Trace backwards**:
   - Find cross-references (Ctrl+Shift+F)
   - Follow the call graph up
   - Identify the "frame timing loop"

---

## 🎓 Next Steps

### Understanding the Results

After running any of the above tools, you should have:

1. **PC addresses** that write to `0x30000075`
2. **Call stacks** showing which functions are involved
3. **Frequency data** - how often each write happens

### Finding the Root Cause

Your goal is to answer:
- **Where** does the game decide to set FPS to 30 vs 60?
- **What** logic controls this decision?
- **Can** we patch the decision point instead of all 12 CRO modules?

### Potential Discoveries

You might find:
- A central "SetFPS()" function that writes to all CRO modules
- A configuration read from ROM that could be patched once
- Additional memory locations that need patching
- A better understanding of why the cheat code works

---

## 🐛 Troubleshooting

### Emulator crashes with trace enabled
- Try reducing trace scope (only log writes to `0x30000070-0x30000080` range)
- Use `RelWithDebInfo` instead of `Debug` build type

### rr says "perf_event_paranoid too high"
```bash
sudo sysctl kernel.perf_event_paranoid=1
```

### Frida can't find Memory::Write8 function
- Ensure emulator has debug symbols: `file citra-qt` should show "not stripped"
- Try rebuilding with `-DCMAKE_BUILD_TYPE=RelWithDebInfo`
- Use `frida-trace -i 'Memory::*' citra-qt` to see available functions

### No writes detected
- Make sure you're testing with the **original** ROM (not patched)
- The FPS flag is only written during gameplay, not menus
- Load a save and get into actual gameplay

---

## 📚 Reference

- Full analysis: [DYNAMIC_ANALYSIS_IMPROVEMENTS.md](DYNAMIC_ANALYSIS_IMPROVEMENTS.md)
- Current status: [STATUS.md](STATUS.md)
- Previous GDB work: [DYNAMIC_ANALYSIS_RESULTS.md](DYNAMIC_ANALYSIS_RESULTS.md)

---

## 💡 Pro Tips

1. **Start with Option 1** (emulator tracing) - it's the most reliable
2. **Test on original ROM** - patched ROM won't write to FPS flag (that's why the patch works!)
3. **Record your findings** - document what you discover in a new analysis file
4. **Cross-reference with Ghidra** - memory trace gives you addresses, Ghidra gives you meaning
5. **Consider the cheat code** - it writes 0x00 every frame; your goal is to make the game do that itself

Good luck! 🎮
