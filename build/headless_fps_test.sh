#!/bin/bash
# Headless FPS test using Xvfb + Mesa software OpenGL
# Runs emulator without any visible window, captures FPS data
set -e

cd /home/struktured/projects/bis

ROM="${1:-Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds}"
DURATION="${2:-30}"
FPS_CSV="tmp/citra_fps.csv"
EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"

echo "=== Headless FPS Test ==="
echo "ROM: $(basename "$ROM")"
echo "Duration: ${DURATION}s"

# Kill any previous instances
pkill -9 azahar 2>/dev/null || true
pkill -9 -f "Xvfb :99" 2>/dev/null || true
sleep 1
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true

# Start virtual display with GLX support
Xvfb :99 -screen 0 800x600x24 -ac +extension GLX &
XVFB_PID=$!
sleep 2

# Clear FPS log
rm -f "$FPS_CSV"

echo "Starting emulator (headless, mesa software GL)..."

# Run emulator headlessly with SIGKILL on timeout
env \
    -u WAYLAND_DISPLAY \
    DISPLAY=:99 \
    QT_QPA_PLATFORM=xcb \
    SDL_AUDIODRIVER=dummy \
    XDG_SESSION_TYPE=x11 \
    LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    "$EMULATOR" "$ROM" \
    >/dev/null 2>&1 &
EMU_PID=$!

# Wait for duration then force-kill
sleep "$DURATION"
kill -9 $EMU_PID 2>/dev/null || true
wait $EMU_PID 2>/dev/null || true

# Clean up Xvfb
kill -9 $XVFB_PID 2>/dev/null || true
sleep 1

# Report results
echo ""
echo "=== FPS Results ==="
if [ -f "$FPS_CSV" ]; then
    LINES=$(wc -l < "$FPS_CSV")
    if [ "$LINES" -gt 1 ]; then
        echo "Collected $((LINES - 1)) FPS samples"
        echo ""

        # Calculate stats - skip first 3 samples (warmup)
        SKIP=4  # skip header + 3 warmup
        AVG_GAME=$(awk -F',' -v skip="$SKIP" 'NR>skip && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$FPS_CSV")
        AVG_SPEED=$(awk -F',' -v skip="$SKIP" 'NR>skip && $4>0 {sum+=$4; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$FPS_CSV")
        NONZERO=$(awk -F',' 'NR>1 && $2>0 {count++} END {print count+0}' "$FPS_CSV")

        echo "Average Game FPS: $AVG_GAME (non-zero samples: $NONZERO)"
        echo "Average Speed: ${AVG_SPEED}%"
        echo ""
        echo "Last 10 samples:"
        tail -10 "$FPS_CSV"
        echo ""

        # Verdict
        if [ "$NONZERO" -eq 0 ]; then
            echo "RESULT: NO_RENDERING (all FPS = 0)"
            exit 2
        elif (( $(echo "$AVG_GAME >= 55" | bc -l 2>/dev/null || echo 0) )); then
            echo "RESULT: 60FPS"
            exit 0
        elif (( $(echo "$AVG_GAME >= 25" | bc -l 2>/dev/null || echo 0) )); then
            echo "RESULT: 30FPS"
            exit 1
        else
            echo "RESULT: LOW_FPS ($AVG_GAME)"
            exit 3
        fi
    else
        echo "No FPS data collected (only header row)"
        exit 2
    fi
else
    echo "No FPS CSV created - emulator may have crashed"
    exit 2
fi
