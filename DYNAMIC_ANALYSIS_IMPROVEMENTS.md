# Dynamic Analysis Tooling Improvements

## Current Limitations

Based on the existing setup:
1. **GDB watchpoints fail** - JIT fastmem bypass prevents memory access tracing
2. **Static analysis insufficient** - Computed addressing and indirect jumps limit pattern matching
3. **Limited runtime visibility** - Can't trace instruction-level execution paths
4. **Manual emulator instrumentation** - Requires rebuilding for each new logging point

## Recommended Tooling Upgrades

### 1. **Emulator-Level Instrumentation** (HIGHEST PRIORITY)

#### A. Citra/Lime3DS Memory Access Logging
**What**: Add comprehensive memory access hooks at the emulator level, bypassing JIT limitations.

**Implementation**:
```cpp
// In src/core/memory.cpp or dynarmic interface
void LogMemoryWrite(u32 addr, u32 value, u32 size, u32 pc) {
    if (addr >= 0x30000000 && addr < 0x30001000) {  // LINEAR_HEAP range
        fprintf(stderr, "[MEM_WRITE] PC=%08x ADDR=%08x VAL=%08x SIZE=%d\n",
                pc, addr, value, size);
    }
}
```

**Benefits**:
- Captures ALL memory accesses including JIT-compiled code
- Can log caller PC to trace instruction flow
- No GDB overhead, runs at near-native speed

**Files to modify**:
- `src/core/memory.cpp` - Memory subsystem hooks
- `src/core/arm/dynarmic/arm_dynarmic.cpp` - JIT memory callbacks
- Add compile flag: `-DENABLE_MEMORY_TRACING`

---

#### B. JIT Disassembly Logging
**What**: Log ARM instructions as Dynarmic JIT compiles them.

**Implementation**:
```cpp
// In arm_dynarmic.cpp
void LogJITBlock(u32 start_addr, const std::vector<u32>& instructions) {
    for (size_t i = 0; i < instructions.size(); i++) {
        u32 addr = start_addr + (i * 4);
        u32 instr = instructions[i];
        // Disassemble and log
        if (addr >= target_code_range_start && addr <= target_code_range_end) {
            fprintf(stderr, "[JIT_COMPILE] %08x: %08x  ; %s\n",
                    addr, instr, disassemble(instr).c_str());
        }
    }
}
```

**Benefits**:
- See exactly what code is executing in game code regions
- Identify hot paths and frame timing loops
- No runtime overhead after compilation

---

### 2. **Dynamic Binary Instrumentation Frameworks**

#### A. Frida (RECOMMENDED)
**What**: Runtime instrumentation framework that can hook into running processes.

**Why it's better than GDB**:
- Can intercept JIT-compiled code
- JavaScript-based scripting (fast iteration)
- Works with ARM targets
- Can modify behavior at runtime

**Setup**:
```bash
# Install Frida
uv pip install frida-tools

# Run emulator with Frida attached
frida-trace -i "Memory::Write*" -i "ARM_Dynarmic::*" ./citra
```

**Example Frida script** (`trace_fps_writes.js`):
```javascript
// Hook memory writes to 0x30000075
Interceptor.attach(Module.findExportByName(null, "Memory::Write8"), {
    onEnter: function(args) {
        var addr = args[0].toInt32();
        var value = args[1].toInt32();

        if (addr === 0x30000075) {
            console.log("[FPS_WRITE]", "PC:", this.context.pc,
                       "Value:", value, "Backtrace:", Thread.backtrace());

            // Optionally modify value to force 60fps
            args[1] = ptr(0x00);
        }
    }
});
```

**Benefits**:
- Can trace actual calling code, not just memory addresses
- Can generate backtraces to find writer functions
- Can be used for live patching/testing without rebuilding ROM

---

#### B. Intel Pin / DynamoRIO
**What**: Academic-grade DBI frameworks with comprehensive instrumentation APIs.

**Why consider**:
- More powerful than Frida for instruction-level analysis
- Can generate full execution traces
- Built-in cache simulation and memory access tracking

**Limitation**:
- Pin doesn't support ARM hosts easily (x86/x64 only)
- DynamoRIO has better ARM support but steeper learning curve

**Skip for now** - Frida + emulator hooks are more practical.

---

### 3. **Specialized Memory Tracing**

#### A. rr (Record and Replay Debugger)
**What**: Records full program execution for deterministic replay.

**Use case**:
```bash
# Record a test run
rr record ./citra-qt path/to/rom.3ds

# Replay with full reverse execution
rr replay
(rr) reverse-continue
(rr) watch *0x30000075
(rr) reverse-continue  # Go backwards to find who wrote it!
```

**Benefits**:
- **Reverse execution** - Find who wrote to FPS flag by going backwards
- Perfect for "who writes to this address?" questions
- Can replay same execution multiple times

**Limitations**:
- Only works on Linux x86_64 (not ARM)
- Can't record GPU operations (but 3DS emulation is CPU-only)
- Requires syscall interception (may affect emulator)

**Verdict**: Worth testing if GDB watchpoints continue to fail.

---

#### B. Valgrind with Custom Tools
**What**: Add custom Valgrind instrumentation for memory access tracing.

**Skip** - Too slow for emulation (would run at 10-50x slower).

---

### 4. **Custom Tracing Infrastructure**

#### A. Execution Trace Generation
**Implementation**: Add `-DTRACE_EXECUTION` mode to emulator:

```cpp
// trace_execution.cpp
struct TraceEntry {
    u32 pc;
    u32 instruction;
    u32 target_addr;  // For loads/stores
    u32 value;        // For stores
    u64 timestamp;
};

std::vector<TraceEntry> execution_trace;

void LogInstruction(u32 pc, u32 instr, u32 addr, u32 val) {
    if (pc >= game_code_start && pc <= game_code_end) {
        execution_trace.push_back({pc, instr, addr, val, get_ticks()});
    }
}

void DumpTrace(const char* filename) {
    FILE* f = fopen(filename, "wb");
    fwrite(execution_trace.data(), sizeof(TraceEntry),
           execution_trace.size(), f);
    fclose(f);
}
```

**Analysis script** (`analyze_trace.py`):
```python
import struct
from capstone import *

def analyze_trace(trace_file):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    with open(trace_file, 'rb') as f:
        while True:
            data = f.read(24)  # sizeof(TraceEntry)
            if not data: break

            pc, instr, addr, val, ts = struct.unpack('IIIQQ', data)

            # Find writes to FPS address
            if addr == 0x30000075:
                dis = next(md.disasm(struct.pack('I', instr), pc))
                print(f"[{ts}] {pc:08x}: {dis.mnemonic} {dis.op_str} -> {val:02x}")
```

**Benefits**:
- Offline analysis (don't slow down emulation)
- Can replay and analyze multiple times
- Can correlate with game state

---

#### B. Function Call Tracing
**What**: Log all function entry/exit in game code regions.

**Implementation**: Hook ARM BL/BLX instructions:
```cpp
void OnBranchWithLink(u32 pc, u32 target) {
    if (target >= 0x00100000 && target <= 0x00400000) {  // Game code
        fprintf(stderr, "[CALL] %08x -> %08x\n", pc, target);
        call_stack.push(target);
    }
}
```

**Benefits**:
- Build call graph of game code
- Identify hot functions related to frame timing
- Can instrument specific functions of interest

---

### 5. **Differential Analysis Tools**

#### A. Game State Dumper
**Implementation**: Dump entire 3DS memory state at key points:

```bash
# tools/dump_memory_state.py
def dump_state(emulator, timestamp):
    """Dump full memory state via GDB remote protocol"""
    memory_regions = [
        (0x00100000, 0x03F00000, "APPLICATION"),
        (0x08000000, 0x08000000 + 0x08000000, "VRAM"),
        (0x10000000, 0x10000000 + 0x10000000, "IO"),
        (0x18000000, 0x18000000 + 0x00600000, "VRAM"),
        (0x1FF00000, 0x1FF00000 + 0x00080000, "DSP"),
        (0x30000000, 0x30000000 + 0x08000000, "LINEAR"),
    ]

    for start, size, name in memory_regions:
        data = gdb.read_memory(start, size)
        with open(f"state_{timestamp}_{name}.bin", "wb") as f:
            f.write(data)
```

**Analysis**: Compare 30fps vs 60fps memory states:
```python
def find_differences(state_30fps, state_60fps):
    """Find all differing bytes between states"""
    diffs = []
    for i, (a, b) in enumerate(zip(state_30fps, state_60fps)):
        if a != b:
            diffs.append((i, a, b))
    return diffs
```

**Benefits**:
- Can find ALL differences between 30fps and 60fps states
- Not limited to known addresses
- Can discover related configuration bytes

---

#### B. Automated Differential Testing
**Implementation**: Automated binary search for minimal patch:

```python
# tools/binary_search_patch.py
def test_patch_combination(patch_locations):
    """Test if given combination of patches achieves 60fps"""
    rom = load_rom("original.3ds")
    for loc in patch_locations:
        rom[loc] = 0x00  # Apply patch
    save_rom(rom, "test.3ds")

    fps = run_emulator_and_measure("test.3ds")
    return fps >= 55  # Success threshold

def find_minimal_patch(candidate_locations):
    """Find minimal set of locations that must be patched"""
    # Binary search through power set
    ...
```

**Benefits**:
- Automatically find if subset of patches is sufficient
- Can optimize patch size
- Validates each patch's necessity

---

## Prioritized Implementation Plan

### Phase 1: Low-Hanging Fruit (1-2 days)
1. **Add memory write logging to Lime3DS** at emulator level
   - Hook `Memory::Write8/16/32` for LINEAR_HEAP region (0x30000000-0x38000000)
   - Log caller PC from Dynarmic context
   - Compile flag: `-DMEMORY_TRACE_LINEAR_HEAP`

2. **Add JIT block compilation logging**
   - Log each JIT-compiled block's start address and size
   - Dump disassembly of blocks in game code region
   - Output to `jit_blocks.log`

3. **Test rr record/replay**
   - Record test session: `rr record ./citra-qt rom.3ds`
   - Use reverse execution to trace FPS writes backwards
   - Document whether it works with emulator

### Phase 2: Advanced Tooling (3-5 days)
4. **Set up Frida instrumentation**
   - Install frida-tools
   - Write `trace_fps.js` to hook memory writes
   - Generate backtraces for all writes to 0x30000075
   - Document which game functions write FPS value

5. **Build execution trace infrastructure**
   - Add trace recording mode to emulator
   - Capture PC, instruction, memory ops for game code
   - Write Python analyzer for offline trace analysis
   - Generate call graphs and hot path visualization

### Phase 3: Differential Analysis (2-3 days)
6. **Implement memory state dumper**
   - Dump full memory at frame boundaries
   - Compare 30fps vs 60fps states
   - Identify all differing addresses (not just 0x30000075)

7. **Automated patch minimization**
   - Test if subset of 12 CRO patches is sufficient
   - Find minimal patch set via binary search
   - Validate each patch's individual effect

---

## Expected Outcomes

With these improvements:
1. **Identify exact caller functions** that write FPS flag (currently unknown)
2. **Trace instruction-level execution** to find frame timing loop
3. **Discover related configuration** bytes that might need patching
4. **Optimize patch** to minimal necessary changes
5. **Better understand** game's frame timing architecture

---

## Quick Wins to Try First

### Option A: Memory Write Logging (30 minutes to implement)
```cpp
// Add to src/core/memory.cpp
void Write8(VAddr addr, u8 data) {
    if (addr >= 0x30000000 && addr <= 0x30001000) {
        u32 pc = Core::CPU().GetPC();  // Get current PC
        LOG_WARNING(Memory, "Write8: PC={:08x} Addr={:08x} Val={:02x}", pc, addr, data);
    }
    // ... existing write logic
}
```

Then:
```bash
cd build/emulator/Lime3DS/build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
make -j$(nproc)
./bin/citra-qt /path/to/rom.3ds 2>&1 | grep "Write8.*30000075"
```

This will immediately show you which PC values write to the FPS flag.

---

### Option B: Try rr (15 minutes to test)
```bash
# Install rr
sudo apt install rr

# Record session
rr record ./build/emulator/Lime3DS/build/bin/citra-qt rom.3ds
# (Let it run for a few seconds, then close)

# Replay with reverse execution
rr replay
(rr) watch *0x30000075
(rr) continue
# When watchpoint hits:
(rr) backtrace
(rr) reverse-continue  # Go backwards to previous write!
```

If rr works, you can instantly find who writes to FPS address by going backwards in time.

---

## Conclusion

The current tooling focuses on **static analysis** (Ghidra) and **basic runtime measurement** (FPS logging). The missing piece is **instruction-level dynamic analysis** that can:
- Trace execution through JIT-compiled code
- Identify calling functions for memory writes
- Generate comprehensive execution profiles

**Recommended immediate action**: Implement memory write logging in Lime3DS (Option A above) - this gives you the PC values that write to 0x30000075, which you can then analyze in Ghidra to understand the calling functions and logic.
