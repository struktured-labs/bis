#!/bin/bash

# Minimal FPS test - just runs and captures FPS for a short time
# WARNING: This will show the emulator window (game freezes in true headless mode)

cd /home/struktured/projects/bis

ROM="${1:-Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds}"
TEST_NAME="${2:-quick_test}"
DURATION="${3:-20}"  # Default 20 seconds

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
LOG_DIR="tmp/fps_logs"
mkdir -p "$LOG_DIR"

OUTPUT_LOG="$LOG_DIR/${TEST_NAME}_$(date +%Y%m%d_%H%M%S).log"

echo "=== Minimal FPS Test ==="
echo "ROM: $ROM"
echo "Duration: ${DURATION}s"
echo ""
echo "NOTE: Emulator window will appear (minimize if needed)"
echo "      Press Ctrl+C to stop early"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# Run with same env as working test
timeout ${DURATION}s env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    QT_QPA_PLATFORM=xcb \
    "$EMULATOR" "$ROM" 2>&1 | tee "$OUTPUT_LOG"

echo ""
echo "=== Quick FPS Check ==="

# Count FPS measurements
FPS_COUNT=$(grep -c "\[FPS_MEASUREMENT\]" "$OUTPUT_LOG" 2>/dev/null || echo "0")

if [ "$FPS_COUNT" -gt 0 ]; then
    echo "✓ Found $FPS_COUNT FPS measurements"
    echo ""
    echo "Last 5 measurements:"
    grep "\[FPS_MEASUREMENT\]" "$OUTPUT_LOG" | tail -5
    echo ""

    # Quick average
    AVG=$(grep "\[FPS_MEASUREMENT\]" "$OUTPUT_LOG" | awk -F'[:|]' '{
        gsub(/[^0-9.]/, "", $2);
        if ($2 != "") { sum += $2; count++ }
    } END { if (count > 0) print sum/count; else print "N/A" }')

    echo "Average Game FPS: $AVG"
else
    echo "✗ No FPS measurements found"
    echo "Check log: $OUTPUT_LOG"
fi

echo ""
echo "Full log: $OUTPUT_LOG"
