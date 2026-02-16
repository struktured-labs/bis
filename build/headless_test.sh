#!/bin/bash
# Truly headless emulator test - blocks ALL display access
set -e

cd /home/struktured/projects/bis

ROM="${1:-Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds}"
DURATION="${2:-20}"
FPS_CSV="tmp/citra_fps.csv"

# Kill any previous instances
pkill -9 azahar 2>/dev/null || true
pkill Xvfb 2>/dev/null || true
/bin/sleep 1

# Start virtual display
Xvfb :99 -screen 0 800x600x24 -ac &
XVFB_PID=$!
/bin/sleep 2

# Clear FPS log
rm -f "$FPS_CSV"

echo "Running headless test for ${DURATION}s..."
echo "ROM: $ROM"

# Run emulator with ALL real display access blocked
timeout "$DURATION" env -u WAYLAND_DISPLAY \
    DISPLAY=:99 \
    QT_QPA_PLATFORM=xcb \
    SDL_AUDIODRIVER=dummy \
    XDG_SESSION_TYPE=x11 \
    build/emulator/Lime3DS/build/bin/Release/azahar "$ROM" \
    >/dev/null 2>&1 || true

# Clean up
kill $XVFB_PID 2>/dev/null || true

# Report results
echo ""
echo "=== FPS Results ==="
if [ -f "$FPS_CSV" ]; then
    LINES=$(wc -l < "$FPS_CSV")
    if [ "$LINES" -gt 1 ]; then
        echo "Collected $((LINES - 1)) FPS samples"
        echo ""
        # Calculate average game FPS (column 2)
        AVG=$(awk -F',' 'NR>1 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "N/A"}' "$FPS_CSV")
        echo "Average Game FPS: $AVG"
        echo ""
        echo "Raw data (last 5):"
        tail -5 "$FPS_CSV"
    else
        echo "No FPS data collected (emulator may have failed to render)"
        echo "Check: ~/.local/share/azahar-emu/log/azahar_log.txt"
    fi
else
    echo "No FPS CSV created"
fi
