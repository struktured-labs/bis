#!/bin/bash
# Test ROM in actual gameplay (not just title screen!)
set -e

ROM="${1:-build/Mario_Luigi_BIS_60fps_FINAL.3ds}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GAMEPLAY TEST - NOT TITLE SCREEN                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "ROM: $ROM"
echo ""
echo "INSTRUCTIONS:"
echo "1. Game will launch with visible window"
echo "2. Start new game or continue"
echo "3. GET TO ACTUAL GAMEPLAY (overworld/battle)"
echo "4. Observe FPS - does it feel different?"
echo "5. Press Ctrl+C here when done testing"
echo ""
echo "Starting in 5 seconds..."
sleep 5

# Launch with visible window so you can actually play
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    $HOME/.local/bin/citra.AppImage "$ROM"

echo ""
echo "Test complete!"
