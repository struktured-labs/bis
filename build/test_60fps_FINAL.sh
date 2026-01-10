#!/bin/bash
echo "=== Mario & Luigi BIS+BJJ - Final 60fps Patched ROM ==="
echo ""
echo "ROM: build/Mario_Luigi_BIS_60fps_FINAL.3ds"
echo "Patches: ALL 12 CRO modules (Battle, Menu, Field, etc.)"
echo ""
echo "Starting emulator..."
echo ""

cd /home/struktured/projects/bis

env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    QT_QPA_PLATFORM=xcb \
    ./build/emulator/Lime3DS/build/bin/Release/azahar \
    build/Mario_Luigi_BIS_60fps_FINAL.3ds
