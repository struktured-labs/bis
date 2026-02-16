#!/bin/bash

# Automated ROM Testing Agent Script
# Tests multiple ROM variations to find working patch combinations

set -e
cd /home/struktured/projects/bis

EMULATOR="/home/struktured/.local/bin/citra.AppImage"
TEST_DURATION=25  # seconds per ROM test
RESULTS_FILE="tmp/test_roms/results.txt"

mkdir -p tmp/test_roms

echo "╔══════════════════════════════════════════════════════════════╗" | tee "$RESULTS_FILE"
echo "║  Automated ROM Patch Testing - Binary Search                 ║" | tee -a "$RESULTS_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
echo "Testing ROMs with different patch combinations..." | tee -a "$RESULTS_FILE"
echo "Goal: Find patches that work without crashing" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test ROMs in order
test_roms=(
    "Mario_Luigi_BIS_60fps_FINAL.3ds:BASELINE (CRO only)"
    "test_patch_0.3ds:Patch #0 (0x0007A413)"
    "test_patch_1.3ds:Patch #1 (0x000C6EE4)"
    "test_patch_2.3ds:Patch #2 (0x000F2373)"
    "test_patch_3.3ds:Patch #3 (0x0012C3AA)"
    "test_patch_4.3ds:Patch #4 (0x00151982)"
    "test_patch_0_1.3ds:Patches #0+#1"
    "test_patch_0_2.3ds:Patches #0+#2"
    "test_patch_0_1_2.3ds:Patches #0+#1+#2"
)

test_rom() {
    local rom_file="$1"
    local description="$2"
    local test_log="tmp/test_roms/${rom_file%.3ds}.log"

    echo "─────────────────────────────────────────────────────────────" | tee -a "$RESULTS_FILE"
    echo "Testing: $description" | tee -a "$RESULTS_FILE"
    echo "ROM: $rom_file" | tee -a "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"

    # Launch emulator
    DISPLAY=:0 \
        MESA_GL_VERSION_OVERRIDE=4.6 \
        __GLX_VENDOR_LIBRARY_NAME=nvidia \
        SDL_AUDIODRIVER=dummy \
        timeout ${TEST_DURATION}s "$EMULATOR" "build/$rom_file" \
        > "$test_log" 2>&1 &

    local emu_pid=$!
    echo "  Emulator PID: $emu_pid" | tee -a "$RESULTS_FILE"
    echo "  Testing for ${TEST_DURATION} seconds..." | tee -a "$RESULTS_FILE"

    # Monitor for crash indicators
    sleep 5

    # Check if process still exists
    if ! ps -p $emu_pid > /dev/null 2>&1; then
        echo "  ❌ CRASH: Emulator terminated early" | tee -a "$RESULTS_FILE"
        echo "" | tee -a "$RESULTS_FILE"
        return 1
    fi

    # Wait for test duration
    sleep $((TEST_DURATION - 5))

    # Check final status
    if ps -p $emu_pid > /dev/null 2>&1; then
        # Get CPU usage (high = running, low = frozen)
        local cpu_usage=$(ps -p $emu_pid -o %cpu --no-headers 2>/dev/null || echo "0")
        echo "  CPU Usage: ${cpu_usage}%" | tee -a "$RESULTS_FILE"

        # Kill emulator
        kill $emu_pid 2>/dev/null || true
        sleep 2
        pkill -9 -f "$rom_file" 2>/dev/null || true

        # Analyze result
        if (( $(echo "$cpu_usage > 5" | bc -l) )); then
            echo "  ✅ STABLE: ROM loaded and ran successfully" | tee -a "$RESULTS_FILE"
            echo "" | tee -a "$RESULTS_FILE"
            return 0
        else
            echo "  ⚠️  FROZEN: ROM loaded but froze (0% CPU)" | tee -a "$RESULTS_FILE"
            echo "" | tee -a "$RESULTS_FILE"
            return 2
        fi
    else
        echo "  ❌ CRASH: Emulator died during test" | tee -a "$RESULTS_FILE"
        echo "" | tee -a "$RESULTS_FILE"
        return 1
    fi
}

# Test each ROM
stable_roms=()
frozen_roms=()
crashed_roms=()

for rom_entry in "${test_roms[@]}"; do
    IFS=':' read -r rom_file description <<< "$rom_entry"

    if [ ! -f "build/$rom_file" ]; then
        echo "⚠️  Skipping $rom_file (not found)" | tee -a "$RESULTS_FILE"
        continue
    fi

    if test_rom "$rom_file" "$description"; then
        stable_roms+=("$rom_file")
    else
        exit_code=$?
        if [ $exit_code -eq 2 ]; then
            frozen_roms+=("$rom_file")
        else
            crashed_roms+=("$rom_file")
        fi
    fi

    # Brief pause between tests
    sleep 3
done

# Summary
echo "╔══════════════════════════════════════════════════════════════╗" | tee -a "$RESULTS_FILE"
echo "║  TEST RESULTS SUMMARY                                         ║" | tee -a "$RESULTS_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

echo "✅ STABLE ROMs (${#stable_roms[@]}):" | tee -a "$RESULTS_FILE"
for rom in "${stable_roms[@]}"; do
    echo "  - $rom" | tee -a "$RESULTS_FILE"
done
echo "" | tee -a "$RESULTS_FILE"

echo "⚠️  FROZEN ROMs (${#frozen_roms[@]}):" | tee -a "$RESULTS_FILE"
for rom in "${frozen_roms[@]}"; do
    echo "  - $rom" | tee -a "$RESULTS_FILE"
done
echo "" | tee -a "$RESULTS_FILE"

echo "❌ CRASHED ROMs (${#crashed_roms[@]}):" | tee -a "$RESULTS_FILE"
for rom in "${crashed_roms[@]}"; do
    echo "  - $rom" | tee -a "$RESULTS_FILE"
done
echo "" | tee -a "$RESULTS_FILE"

echo "═══════════════════════════════════════════════════════════════" | tee -a "$RESULTS_FILE"
echo "Detailed results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

if [ ${#stable_roms[@]} -gt 1 ]; then
    echo "✅ SUCCESS: Found working patch combinations!" | tee -a "$RESULTS_FILE"
    echo "Next: Test stable ROMs for FPS improvement" | tee -a "$RESULTS_FILE"
    exit 0
else
    echo "⚠️  Only baseline ROM is stable" | tee -a "$RESULTS_FILE"
    echo "All code.bin patches cause crashes or freezes" | tee -a "$RESULTS_FILE"
    echo "Recommend: Dynamic analysis (GDB) or alternative approach" | tee -a "$RESULTS_FILE"
    exit 1
fi
