#!/bin/bash

# Automated FPS Measurement Script
# Runs game for specified duration and captures FPS logs

ROM_PATH="$1"
TEST_NAME="$2"
DURATION="${3:-60}"  # Default 60 seconds

if [ -z "$ROM_PATH" ] || [ -z "$TEST_NAME" ]; then
    echo "Usage: $0 <ROM_PATH> <TEST_NAME> [DURATION_SECONDS]"
    echo "Example: $0 'original.3ds' 'clean_test' 60"
    exit 1
fi

EMULATOR="/home/struktured/projects/bis/build/emulator/Lime3DS/build/bin/Release/azahar"
LOG_DIR="/home/struktured/projects/bis/tmp/fps_logs"
mkdir -p "$LOG_DIR"

OUTPUT_LOG="$LOG_DIR/${TEST_NAME}_$(date +%Y%m%d_%H%M%S).log"

echo "=== FPS Measurement Test ==="
echo "ROM: $ROM_PATH"
echo "Test Name: $TEST_NAME"
echo "Duration: ${DURATION}s"
echo "Output: $OUTPUT_LOG"
echo ""

# Run emulator headless with FPS logging
timeout ${DURATION}s env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    QT_QPA_PLATFORM=offscreen \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM_PATH" 2>&1 | tee "$OUTPUT_LOG"

echo ""
echo "=== FPS Analysis ==="

# Extract FPS measurements from log
FPS_DATA=$(grep "\[FPS_MEASUREMENT\]" "$OUTPUT_LOG")

if [ -z "$FPS_DATA" ]; then
    echo "❌ No FPS data found in log!"
    echo "Check if game loaded properly or if logging is working."
    exit 1
fi

# Parse FPS values
echo "$FPS_DATA" | awk -F'[:|]' '{
    game_fps = $2
    system_fps = $3
    speed = $4
    gsub(/[^0-9.]/, "", game_fps)
    gsub(/[^0-9.]/, "", system_fps)
    gsub(/[^0-9.]/, "", speed)
    if (game_fps != "") {
        sum_game += game_fps
        sum_system += system_fps
        sum_speed += speed
        count++
        if (game_fps > max_game) max_game = game_fps
        if (game_fps < min_game || min_game == 0) min_game = game_fps
    }
}
END {
    if (count > 0) {
        avg_game = sum_game / count
        avg_system = sum_system / count
        avg_speed = sum_speed / count
        print ""
        print "Samples: " count
        print "Game FPS:"
        print "  Average: " sprintf("%.1f", avg_game) " FPS"
        print "  Min: " sprintf("%.1f", min_game) " FPS"
        print "  Max: " sprintf("%.1f", max_game) " FPS"
        print ""
        print "System FPS: " sprintf("%.1f", avg_system) " FPS (avg)"
        print "Emulation Speed: " sprintf("%.1f", avg_speed) "% (avg)"
        print ""

        # Determine verdict
        if (avg_game >= 55) {
            print "✅ VERDICT: Running at ~60 FPS"
        } else if (avg_game >= 25 && avg_game <= 35) {
            print "⚠️  VERDICT: Running at ~30 FPS (not patched or patch failed)"
        } else {
            print "❓ VERDICT: Unusual FPS (" sprintf("%.1f", avg_game) ") - investigate further"
        }
    }
}'

echo ""
echo "Full log saved to: $OUTPUT_LOG"
echo "Raw FPS data:"
echo "$FPS_DATA" | tail -10
