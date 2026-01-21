# File Reference: 60fps Investigation

Quick reference for all files created during investigation.

---

## Documentation

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Project rules, latest findings, user preferences |
| `FINAL_STATUS.md` | Comprehensive 8-hour investigation summary |
| `NEXT_INVESTIGATION.md` | Fresh start plan with 5 investigation paths |
| `FILE_REFERENCE.md` | This file - quick reference |
| `FPS_CANDIDATES_FOUND.md` | Details on 15 0x75 candidates tested |
| `DYNAMIC_ANALYSIS_FINDINGS.md` | Memory region analysis, CTRPF mechanism |
| `DIAGNOSIS.md` | Early analysis notes |
| `EMULATOR_TEST_PLAN.md` | Emulator testing strategy |

---

## Working Scripts

### Static Analysis
| File | Purpose | Status |
|------|---------|--------|
| `build/find_frame_limiter.py` | Find float 30.0 constants | ✅ Found 9 locations |
| `build/patch_frame_limiter.py` | Patch float constants | ✅ Works but didn't help |
| `build/scan_thumb_mode.py` | **Main scanner** - 912K instructions | ✅ Comprehensive |
| `build/analyze_0x75_usage.py` | Analyze 0x75 patterns | ✅ Found 15 candidates |
| `build/analyze_crash_locations.py` | Understand why ROMs crashed | ✅ Struct offsets |

### Dynamic Analysis
| File | Purpose | Status |
|------|---------|--------|
| `build/gdb_attach_watchpoint.sh` | **GDB automation** - attach method | ✅ Working perfectly |
| `build/gdb_python_watchpoint.py` | GDB Python API approach | ⚠️ Alternative method |
| `build/run_gdb_python.sh` | Wrapper for Python GDB | ⚠️ Not tested |

### ROM Generation
| File | Purpose | Status |
|------|---------|--------|
| `build/generate_test_roms.py` | Generate 8 float patch combos | ✅ Created test ROMs |
| `build/test_fps_candidates.py` | Generate 15 0x75 patch ROMs | ✅ All tested |

### Testing (Deprecated - agent had false positives)
| File | Purpose | Status |
|------|---------|--------|
| `build/test_all_cro_patches.sh` | Test ROM loading | ⚠️ Manual testing required |
| `build/test_fps_complete.sh` | Comprehensive FPS test | ⚠️ Needs human verification |

---

## ROM Files

| File | Description | FPS |
|------|-------------|-----|
| `Mario & Luigi - Bowser's Inside Story + Bowser Jr's Journey (USA).3ds` | Original ROM | 30 |
| `build/Mario_Luigi_BIS_60fps_FINAL.3ds` | CRO patches (12 modules @ 0x76) | 30 |
| `tmp/fps_candidate_roms/test_cand##_a.3ds` | 15 test ROMs for 0x75 candidates | 6 crash, 9 at 30fps |

---

## Log Files

| File | Purpose |
|------|---------|
| `tmp/gdb_fps_watchpoint.log` | **PROOF**: 0x30000075 never accessed (60s, 0 hits) |
| `tmp/gdb_attach_output.txt` | GDB console output |
| `tmp/0x75_analysis.json` | All 371 0x75 instruction uses |
| `tmp/thumb_scan_results.json` | Full 912K instruction scan |
| `tmp/crash_analysis.txt` | Why 6 ROMs crashed |
| `tmp/citra_fps.csv` | FPS measurements from custom emulator |

---

## Emulator Source (Modified)

| File | Changes |
|------|---------|
| `build/emulator/Lime3DS/src/citra_qt/citra_qt.h` | FPS measurement infrastructure |
| `build/emulator/Lime3DS/src/citra_qt/citra_qt.cpp` | Background logging thread |
| `build/emulator/Lime3DS/src/core/memory.cpp` | FPS watchpoint logging (unused) |

**Build:**
```bash
cd build/emulator/Lime3DS/build
ninja -j16 azahar
```

**Binary:** `build/emulator/Lime3DS/build/bin/Release/azahar`

---

## Data Files

| Location | Contents |
|----------|----------|
| `tmp/fps_candidate_roms/` | 15 test ROMs + manifest.json |
| `build/extracted/` | Extracted ROM contents (code.bin, CROs, etc) |
| `tmp/` | All analysis outputs, logs |

---

## Quick Commands

### Run Custom Emulator
```bash
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    build/emulator/Lime3DS/build/bin/Release/azahar "build/Mario_Luigi_BIS_60fps_FINAL.3ds"
```

### GDB Watchpoint (Automated)
```bash
./build/gdb_attach_watchpoint.sh
# Check: tmp/gdb_fps_watchpoint.log
```

### Scan for Instructions
```bash
uv run build/scan_thumb_mode.py
# Output: tmp/thumb_scan_results.json
```

### Test a ROM (Manual)
```bash
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    $HOME/.local/bin/citra.AppImage "path/to/rom.3ds" &
sleep 40
pkill -9 citra
```

---

## Key Offsets (ROM Structure)

| Component | Offset in ROM | Size/Notes |
|-----------|---------------|------------|
| NCSD Header | 0x0000 | 0x4000 |
| Partition 0 (CXI) | 0x4000 | Main executable |
| ExeFS (in CXI) | +0x6C00 | Executable filesystem |
| code.bin (in ROM) | 0x6E00 (28160) | Main code |
| ExeFS hash | 0x6CA0 | SHA-256 (must update after patch) |

**CRO Module Patches:**
- Offset 0x76 in each module
- 12 modules patched
- Changes FPS initialization (but main code overrides)

---

## What Worked vs Failed

### ✅ Working Infrastructure
- Custom emulator with FPS logging
- GDB attach watchpoint automation
- ROM patching pipeline
- Comprehensive instruction scanning

### ❌ Failed Patches
- All float 30.0 → 60.0 (9 locations)
- All 0x75 immediate patches (15 candidates)
- CRO-only patches (stable but 30fps)

### 🔍 Critical Discovery
- **0x30000075 never accessed by game** (GDB proof)
- Invalidates 8 hours of static analysis
- Need new approach (see NEXT_INVESTIGATION.md)

---

## Next Steps (When Returning)

1. Test 0x74 candidates (not 0x75)
2. Analyze VBlank/GSP calls (1042 SVC instructions)
3. Research CTRPF framework mechanism
4. Try multiple memory addresses with GDB
5. Emulator-side unlock (last resort)

See `NEXT_INVESTIGATION.md` for detailed plan.
