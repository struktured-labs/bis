#!/bin/bash
# Test script for 60fps patch with ALL 12 CRO modules patched

echo "=== Mario & Luigi BIS+BJJ - Comprehensive 60fps Patch Test ==="
echo ""
echo "Patched CRO modules (LayeredFS):"
ls ~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/*.cro 2>/dev/null | wc -l
ls ~/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/*.cro 2>/dev/null | xargs -n1 basename
echo ""

# Use original ROM (patches applied via LayeredFS)
ROM="Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
EMULATOR="/home/struktured/projects/bis/build/emulator/Lime3DS/build/bin/Release/azahar"

echo "ROM: $ROM"
echo "Emulator: $EMULATOR"
echo ""
echo "Starting emulator with display..."
echo "ALL game modes should now run at 60fps:"
echo "  - Title screen"
echo "  - Field/Overworld"
echo "  - Battles"
echo "  - Menus"
echo "  - Attack minigames"
echo ""
echo "Press Ctrl+C to exit when done testing"
echo ""

# Run with display and required OpenGL overrides
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=pulse \
    "$EMULATOR" "$ROM"
