#!/bin/bash
# A/B headless test for 60fps patch on BIS v1.2 update
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="${1:-bis.3DS}"
UPDATE_CIA="${2:-}"
IPS_PATCH="patches/60fps_v12.ips"
IPS_DIR_BASE="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"

if [ ! -f "$IPS_PATCH" ]; then
    echo "ERROR: No v1.2 IPS patch found at $IPS_PATCH"
    echo "  Run build/process_update.sh first"
    exit 1
fi

# Install update CIA if provided
if [ -n "$UPDATE_CIA" ] && [ -f "$UPDATE_CIA" ]; then
    echo "Installing update CIA for testing..."
    # Azahar/Lime3DS can load update CIAs - place in the right location
    # The emulator applies updates automatically when installed
    echo "  Update: $UPDATE_CIA"
fi

test_combo() {
    local name="$1"
    local ips_file="$2"

    mkdir -p "$IPS_DIR_BASE"
    if [ -n "$ips_file" ]; then
        cp "$ips_file" "$IPS_DIR_BASE/code.ips"
    else
        rm -f "$IPS_DIR_BASE/code.ips"
    fi

    pkill -9 -f azahar 2>/dev/null
    sleep 2
    rm -f "$CSV"

    env DISPLAY=:99 \
        LIBGL_ALWAYS_SOFTWARE=1 \
        GALLIUM_DRIVER=llvmpipe \
        QT_QPA_PLATFORM=xcb \
        SDL_AUDIODRIVER=dummy \
        "$EMULATOR" "$ROM" &
    local pid=$!

    for t in $(seq 5 5 60); do
        sleep 5
        if ! kill -0 $pid 2>/dev/null; then
            echo "  $name: CRASH at ${t}s"
            echo "$name CRASH" >> tmp/update_test_results.txt
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "  $name: ${avg} FPS"
            echo "$name ${avg}" >> tmp/update_test_results.txt
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "  $name: HANG (no FPS data after 60s)"
    echo "$name HANG" >> tmp/update_test_results.txt
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

rm -f tmp/update_test_results.txt
echo "=== BIS v1.2 60fps Patch Test ==="
echo "ROM: $ROM"
echo "Patch: $IPS_PATCH"
echo ""

# Test 1: v1.0 baseline (no patch, no update) to verify emulator works
test_combo "v10_baseline" ""

# Test 2: v1.0 with v1.0 patch (should still work ~59.7 FPS)
test_combo "v10_60fps" "patches/60fps.ips"

# Test 3: v1.0 with v1.2 patch (test if v1.2 patch works on v1.0 too)
test_combo "v10_with_v12_patch" "$IPS_PATCH"

# Clean up
rm -f "$IPS_DIR_BASE/code.ips"

echo ""
echo "=== TEST RESULTS ==="
cat tmp/update_test_results.txt
