#!/bin/bash
# Self-verification pipeline for v1.0 IPS patches
# Tests: baseline, known-good 2-site, cave BL, cave-only
# Checks: emulator doesn't crash, game FPS is correct
set -e
cd /home/struktured/projects/bis

EMU="build/emulator/Lime3DS/build/bin/Release/azahar"
XDG="$PWD/config/headless"
MODS="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
UVR="/home/struktured/.local/bin/uv run python"
DURATION=25  # seconds per test
PASS=0
FAIL=0
RESULTS=""

# Generate A-mash input script (advance through menus)
python3 -c "
lines = []
for i in range(0, 12000, 4):
    lines.append(f'{i} 2 0x001')   # A press
    lines.append(f'{i+2} 2 0x000') # release
with open('input_script.txt', 'w') as f:
    f.write('\n'.join(lines) + '\n')
"

run_test() {
    local name="$1" ips_file="$2" expect_fps="$3"
    echo ""
    echo "================================================================"
    echo "TEST: $name"
    echo "  IPS: ${ips_file:-NONE}"
    echo "  Expect: ~${expect_fps} game_fps"
    echo "================================================================"

    # Install or remove IPS
    if [ -n "$ips_file" ] && [ -f "$ips_file" ]; then
        mkdir -p "$MODS"
        cp "$ips_file" "$MODS/code.ips"
    else
        rm -f "$MODS/code.ips"
    fi

    rm -f tmp/citra_fps.csv

    # Launch headless
    XDG_CONFIG_HOME="$XDG" DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe \
        QT_QPA_PLATFORM=xcb SDL_AUDIODRIVER=dummy "$EMU" bis.3DS > tmp/emu_test.log 2>&1 &
    local pid=$!

    # Wait for startup, check it's still alive
    sleep 5
    if ! kill -0 $pid 2>/dev/null; then
        echo "  CRASH: emulator died within 5 seconds"
        FAIL=$((FAIL+1))
        RESULTS="$RESULTS\n  FAIL $name: CRASH"
        return 1
    fi

    # Wait remaining time
    sleep $((DURATION - 5))

    # Check still alive
    if ! kill -0 $pid 2>/dev/null; then
        echo "  CRASH: emulator died during test"
        FAIL=$((FAIL+1))
        RESULTS="$RESULTS\n  FAIL $name: CRASH"
        return 1
    fi

    # Read FPS
    local game_fps="N/A" sys_fps="N/A" samples=0
    if [ -f tmp/citra_fps.csv ]; then
        game_fps=$(awk -F',' 'NR>6 && $2+0>0.5 && $2+0<200 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "N/A"}' tmp/citra_fps.csv)
        sys_fps=$(awk -F',' 'NR>6 && $3+0>0.5 && $3+0<200 {sum+=$3; count++} END {if(count>0) printf "%.1f", sum/count; else print "N/A"}' tmp/citra_fps.csv)
        samples=$(awk -F',' 'NR>6 && $2+0>0.5 && $2+0<200 {count++} END {print count+0}' tmp/citra_fps.csv)
    fi

    kill $pid 2>/dev/null
    sleep 2

    echo "  Result: game_fps=$game_fps sys_fps=$sys_fps samples=$samples"

    # Verdict
    if [ "$game_fps" = "N/A" ] || [ "$samples" -lt 3 ]; then
        echo "  FAIL: insufficient data"
        FAIL=$((FAIL+1))
        RESULTS="$RESULTS\n  FAIL $name: no data (game_fps=$game_fps samples=$samples)"
        return 1
    fi

    # Check FPS is in expected range
    local low high
    if [ "$expect_fps" = "30" ]; then
        low=20; high=40
    elif [ "$expect_fps" = "60" ]; then
        low=45; high=70
    else
        low=1; high=200
    fi

    local fps_int=$(echo "$game_fps" | awk '{printf "%d", $1}')
    if [ "$fps_int" -ge "$low" ] && [ "$fps_int" -le "$high" ]; then
        echo "  PASS: $game_fps fps in range [$low-$high]"
        PASS=$((PASS+1))
        RESULTS="$RESULTS\n  PASS $name: ${game_fps} fps"
    else
        echo "  FAIL: $game_fps fps NOT in range [$low-$high]"
        FAIL=$((FAIL+1))
        RESULTS="$RESULTS\n  FAIL $name: ${game_fps} fps (expected ~${expect_fps})"
    fi
    return 0
}

echo "=== IPS SELF-VERIFICATION PIPELINE ==="
echo "ROM: bis.3DS (v1.0)"
echo "Emulator: $EMU"
echo ""

# Generate test IPS files
echo "Generating test IPS files..."

# Test IPS 1: Known-good 2-site MOV #0 (proven to work)
$UVR -c "
import struct, os
CODE_BIN = os.path.expanduser('~/projects/bis/tmp/v10_extract/exefs_dir/code.bin')
with open(CODE_BIN, 'rb') as f: code = f.read()
records = [(0x03E918, struct.pack('<I', 0xE3A01000)), (0x180A84, struct.pack('<I', 0xE3A00000))]
buf = b'PATCH'
for off, data in sorted(records):
    buf += struct.pack('>I', off)[1:] + struct.pack('>H', len(data)) + data
buf += b'EOF'
with open('tmp/test_2site_60fps.ips', 'wb') as f: f.write(buf)
print(f'  2-site: {len(buf)} bytes')
"

# Test IPS 2: Cave BL only (no other patches) — minimal test of cave mechanism
$UVR -c "
import struct, os
CODE_BIN = os.path.expanduser('~/projects/bis/tmp/v10_extract/exefs_dir/code.bin')
with open(CODE_BIN, 'rb') as f: code = f.read()
records = []
# Cave: just MOV R1,#0 and return (simplest possible cave)
cave_foff = 0x0660BC
cave = struct.pack('<3I', 0xE92D4000, 0xE3A01000, 0xE8BD8000)  # PUSH LR; MOV R1,#0; POP PC
records.append((cave_foff, cave))
# BL to cave at main reader
cave_vaddr = 0x1660BC
bl_offset = (cave_vaddr - (0x13E918 + 8)) // 4
bl_instr = 0xEB000000 | (bl_offset & 0x00FFFFFF)
records.append((0x03E918, struct.pack('<I', bl_instr)))
buf = b'PATCH'
for off, data in sorted(records):
    buf += struct.pack('>I', off)[1:] + struct.pack('>H', len(data)) + data
buf += b'EOF'
with open('tmp/test_cave_simple.ips', 'wb') as f: f.write(buf)
print(f'  cave-simple: {len(buf)} bytes (BL to MOV R1,#0 cave)')
"

# Test IPS 3: Full R-toggle cave (current gen script)
$UVR build/gen_60fps_v10_full_r.py 2>&1 | sed 's/^/  /'

echo ""
echo "Running tests..."

# TEST 1: Baseline — no IPS
run_test "baseline_no_ips" "" "30"

# TEST 2: Known-good 2-site 60fps
run_test "2site_60fps" "tmp/test_2site_60fps.ips" "60"

# TEST 3: Simple cave (BL to MOV R1,#0) — tests BL mechanism
run_test "cave_simple_60fps" "tmp/test_cave_simple.ips" "60"

# TEST 4: Full R-toggle cave (no R button = 60fps default from init reader)
run_test "full_r_toggle" "patches/60fps_v10_full_r.ips" "any"

# Cleanup
rm -f "$MODS/code.ips" input_script.txt

echo ""
echo "================================================================"
echo "SUMMARY: $PASS passed, $FAIL failed"
echo -e "$RESULTS"
echo "================================================================"
