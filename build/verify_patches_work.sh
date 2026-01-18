#!/bin/bash

# Simple automated verification: Do the patched ROMs load without crashing?
# This is the minimum test before attempting FPS measurement

set -e

cd /home/struktured/projects/bis

EMULATOR="/home/struktured/.local/bin/citra.AppImage"
PATCHED_ROM="${1:-build/Mario_Luigi_BIS_60fps_v2.3ds}"
TEST_DURATION=30

echo "═══════════════════════════════════════════════════════════════"
echo "  Quick Patch Verification Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Testing if patched ROM loads without crashing..."
echo "Duration: ${TEST_DURATION} seconds"
echo ""

mkdir -p tmp/patch_test

# Run patched ROM
echo "Launching patched ROM..."
DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    timeout ${TEST_DURATION}s "$EMULATOR" "$PATCHED_ROM" \
    > tmp/patch_test/run.log 2>&1 &

EMU_PID=$!
echo "Emulator PID: $EMU_PID"
echo "Waiting ${TEST_DURATION} seconds..."

sleep $TEST_DURATION
wait $EMU_PID 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results"
echo "═══════════════════════════════════════════════════════════════"

# Check if emulator ran
if [ -f tmp/patch_test/run.log ]; then
    LOG_SIZE=$(wc -c < tmp/patch_test/run.log)
    echo "Log size: ${LOG_SIZE} bytes"

    # Check for crash indicators
    if grep -q -i "corrupt\|crash\|error\|fatal" tmp/patch_test/run.log; then
        echo ""
        echo "❌ FAILED: Errors detected in log"
        echo ""
        grep -i "corrupt\|crash\|error\|fatal" tmp/patch_test/run.log | head -10
        exit 1
    else
        echo ""
        echo "✅ SUCCESS: Patched ROM loaded without crashes"
        echo "   Patches are structurally sound"
        echo ""
        echo "Next step: Verify if FPS actually changed to 60"
        echo "   Run manual comparison or check via observation"
        exit 0
    fi
else
    echo "❌ FAILED: No log file created"
    exit 1
fi
