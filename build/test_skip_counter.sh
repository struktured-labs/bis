#!/bin/bash
# Test if the halfspeed trampoline's skip counter increments
# This proves the trampoline actually executes and skips game logic
set -e
cd "$(dirname "$0")/.."
source setenv.sh 2>/dev/null || true

EMU="build/emulator/Lime3DS/build/bin/Release/bis_emu"
ROM="tmp/rom_v22_build/bis_v22_merged.3ds"
MOD_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CONFIG="$HOME/.config/azahar-emu/qt-config.ini"

export DISPLAY=:99
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
export QT_QPA_PLATFORM=xcb
export SDL_AUDIODRIVER=dummy

# Kill everything first
killall -9 bis_emu azahar 2>/dev/null || true
sleep 2

# Ensure audio is muted
if [ -f "$CONFIG" ]; then
    sed -i 's/^volume=.*/volume=0/' "$CONFIG"
    sed -i 's/^volume\\default=.*/volume\\default=false/' "$CONFIG"
fi

# Simple input script - just A-mash to get past menus
cat > input_script.txt << 'SCRIPT'
1 1 4000 0.0 0.0
SCRIPT

run_test() {
    local label=$1
    local patch=$2

    echo "=== Test: $label ==="
    mkdir -p "$MOD_DIR"
    cp "$patch" "$MOD_DIR/code.ips"

    # Clean data files
    rm -f tmp/pos_track.csv tmp/patch_verify.txt tmp/citra_fps.csv
    echo "hid_frame,fps_byte,fps_shadow,fps_toggle,game_frame_ctr,skip_ctr,cpx,cpy" > tmp/pos_track.csv

    echo "  Running for 50s..."
    timeout 50 "$EMU" "$ROM" 2>/dev/null || true
    sleep 2
    killall -9 bis_emu 2>/dev/null || true
    sleep 1

    # Save results
    cp tmp/pos_track.csv "tmp/skip_${label}.csv"
    cp tmp/patch_verify.txt "tmp/verify_${label}.txt" 2>/dev/null || true

    echo "  Patch verify:"
    cat "tmp/verify_${label}.txt" 2>/dev/null || echo "  N/A"

    echo ""
    echo "  Skip counter values (last 10 rows):"
    tail -10 "tmp/skip_${label}.csv"

    echo ""
    # Analyze skip counter
    echo "  Skip counter summary:"
    awk -F, 'NR>1 && $6!="" {
        if(NR==2) first=$6;
        last=$6;
        if($6>0) nonzero++;
        total++;
    } END {
        printf "    first=%s last=%s nonzero=%d/%d\n", first, last, nonzero, total
    }' "tmp/skip_${label}.csv"
    echo ""
}

# Test 1: Original 60fps patch (no trampoline - skip counter should stay 0)
run_test "original" "patches/60fps_update_v1.2.ips"

# Test 2: Halfspeed patch (trampoline should increment skip counter)
run_test "halfspeed" "patches/60fps_halfspeed_v1.2.ips"

echo "=== Comparison ==="
echo "Original skip counter (should be 0):"
awk -F, 'NR>1{print $6}' tmp/skip_original.csv | sort -u | head -5
echo ""
echo "Halfspeed skip counter (should be >0 if trampoline works):"
awk -F, 'NR>1{print $6}' tmp/skip_halfspeed.csv | sort -u | head -10
