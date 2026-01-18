#!/bin/bash

# Automated 60fps Verification Script
# Tests both original and patched ROMs with automated FPS measurement
# NO user interaction required

set -e

cd /home/struktured/projects/bis

# Configuration
EMULATOR="/home/struktured/.local/bin/citra.AppImage"
ORIGINAL_ROM="Mario & Luigi - Bowser's Inside Story + Bowser Jr's Journey (USA).3ds"
PATCHED_ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
TEST_DURATION=60  # seconds per test
RESULTS_DIR="tmp/fps_test_results"

mkdir -p "$RESULTS_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Automated 60fps Verification Test                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  - Test duration: ${TEST_DURATION}s per ROM"
echo "  - Emulator: ${EMULATOR}"
echo "  - Results: ${RESULTS_DIR}"
echo ""

# Function: Run ROM and measure performance
test_rom() {
    local rom="$1"
    local test_name="$2"
    local output="$RESULTS_DIR/${test_name}_$(date +%Y%m%d_%H%M%S)"

    echo "════════════════════════════════════════════════════════════════"
    echo "  Testing: $test_name"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    # Launch emulator in background
    env DISPLAY=:0 \
        MESA_GL_VERSION_OVERRIDE=4.6 \
        __GLX_VENDOR_LIBRARY_NAME=nvidia \
        SDL_AUDIODRIVER=dummy \
        "$EMULATOR" "$rom" > "${output}.log" 2>&1 &

    EMU_PID=$!
    echo "Emulator PID: $EMU_PID"
    echo "Running for ${TEST_DURATION} seconds..."
    echo ""

    # Monitor window title for FPS (if available)
    local fps_samples=()
    local start_time=$(date +%s)
    local sample_count=0

    while [ $(( $(date +%s) - start_time )) -lt $TEST_DURATION ]; do
        # Try to get FPS from window title using xdotool
        if command -v xdotool &> /dev/null; then
            local window_title=$(xdotool search --name "Citra" getwindowname 2>/dev/null | head -1)
            # Extract FPS if present in title (format: "... | XX FPS")
            if echo "$window_title" | grep -q "FPS"; then
                local fps=$(echo "$window_title" | grep -oP '\d+(?= FPS)')
                if [ -n "$fps" ]; then
                    fps_samples+=("$fps")
                    sample_count=$((sample_count + 1))
                fi
            fi
        fi
        sleep 2
    done

    # Kill emulator
    kill $EMU_PID 2>/dev/null || true
    sleep 2
    pkill -9 -f "citra.*${rom}" 2>/dev/null || true

    # Calculate average FPS if we got samples
    if [ ${#fps_samples[@]} -gt 0 ]; then
        local sum=0
        for fps in "${fps_samples[@]}"; do
            sum=$((sum + fps))
        done
        local avg_fps=$((sum / ${#fps_samples[@]}))
        echo "  Samples collected: ${#fps_samples[@]}"
        echo "  Average FPS: $avg_fps"
        echo "$avg_fps" > "${output}_fps.txt"
    else
        echo "  ⚠️  Could not measure FPS automatically"
        echo "  Samples: ${#fps_samples[@]}"
        echo "  (xdotool available: $(command -v xdotool &> /dev/null && echo 'yes' || echo 'no'))"

        # Fallback: assume success if emulator didn't crash
        if [ -f "${output}.log" ]; then
            local log_size=$(wc -c < "${output}.log")
            if [ $log_size -gt 100 ]; then
                echo "  Emulator ran successfully (log: ${log_size} bytes)"
                echo "0" > "${output}_fps.txt"  # 0 = unknown but ran
            else
                echo "  Emulator may have crashed (log: ${log_size} bytes)"
                echo "-1" > "${output}_fps.txt"  # -1 = failed
            fi
        fi
    fi

    echo ""
}

# Main test sequence
echo "Test 1: Original ROM (baseline - expecting ~30 FPS)"
echo ""
test_rom "$ORIGINAL_ROM" "original"
ORIGINAL_FPS=$(cat "$RESULTS_DIR"/original_*_fps.txt 2>/dev/null | tail -1)

echo ""
echo "Test 2: Patched ROM (target - expecting ~60 FPS)"
echo ""
test_rom "$PATCHED_ROM" "patched"
PATCHED_FPS=$(cat "$RESULTS_DIR"/patched_*_fps.txt 2>/dev/null | tail -1)

# Generate verdict
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  RESULTS                                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Original ROM FPS: ${ORIGINAL_FPS:-unknown}"
echo "Patched ROM FPS:  ${PATCHED_FPS:-unknown}"
echo ""

if [ "$ORIGINAL_FPS" = "-1" ] || [ "$PATCHED_FPS" = "-1" ]; then
    echo "❌ TEST FAILED: One or both ROMs crashed"
    exit 1
elif [ "$ORIGINAL_FPS" = "0" ] || [ "$PATCHED_FPS" = "0" ]; then
    echo "⚠️  INCONCLUSIVE: Could not measure FPS automatically"
    echo "    Both ROMs loaded successfully but FPS measurement unavailable"
    echo "    Manual verification recommended"
    exit 2
elif [ $PATCHED_FPS -ge 55 ] && [ $ORIGINAL_FPS -le 35 ]; then
    echo "✅ SUCCESS: Patched ROM achieves ~60 FPS!"
    echo "    Original: ~30 FPS (baseline)"
    echo "    Patched: ~60 FPS (2x improvement)"
    exit 0
elif [ $PATCHED_FPS -le 35 ] && [ $ORIGINAL_FPS -le 35 ]; then
    echo "❌ FAILED: Patched ROM still at ~30 FPS"
    echo "    Patches are not taking effect"
    echo "    Frame limiter may be overriding CRO patches"
    exit 1
else
    echo "❓ UNCLEAR: Unexpected FPS values"
    echo "    Requires investigation"
    exit 2
fi
