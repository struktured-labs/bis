#!/bin/bash

# Quick 10-second test to verify emulator loads without freezing

cd /home/struktured/projects/bis

ROM="${1:-Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds}"
EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"

echo "=== Quick Test (10 seconds) ==="
echo "ROM: $ROM"
echo ""
echo "Starting Xvfb..."
pkill -9 Xvfb 2>/dev/null || true
Xvfb :99 -screen 0 1024x768x24 -ac &
XVFB_PID=$!
sleep 2

echo "Starting emulator..."
timeout 10s env DISPLAY=:99 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    LIBGL_ALWAYS_SOFTWARE=1 \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" 2>&1 | grep -E "FPS_MEASUREMENT|Loading|Started|Error" || true

echo ""
echo "Cleaning up..."
pkill -9 azahar 2>/dev/null || true
kill $XVFB_PID 2>/dev/null || true

echo ""
echo "If you saw [FPS_MEASUREMENT] lines, it's working!"
echo "If not, check for errors above."
