#!/bin/bash

# Test with ORIGINAL unmodified emulator AppImage
# To verify if my custom build broke something

cd /home/struktured/projects/bis

ROM="${1:-Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds}"
DURATION="${2:-20}"

echo "=== Testing with ORIGINAL Lime3DS AppImage ==="
echo "ROM: $ROM"
echo "Duration: ${DURATION}s"
echo ""
echo "This uses the unmodified emulator (NOT the custom build with FPS logging)"
echo ""

timeout ${DURATION}s env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    /home/struktured/.local/bin/lime3ds.AppImage "$ROM"

echo ""
echo "Did it work? (y/n)"
