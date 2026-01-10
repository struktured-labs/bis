#!/bin/bash

echo "=== Clean Test - NO Mods/Patches ==="
echo ""

# Temporarily disable ALL mods by renaming the mods folder
for emu in azahar lime3ds citra; do
    MODS_DIR=~/.local/share/${emu}-emu/load/mods
    if [ -d "$MODS_DIR" ]; then
        if [ ! -d "${MODS_DIR}.disabled" ]; then
            echo "Disabling $emu mods..."
            mv "$MODS_DIR" "${MODS_DIR}.disabled"
        fi
    fi
done

echo ""
echo "Mods disabled. Using 100% original ROM."
echo ""

# Use the ORIGINAL ROM (not any patched version)
ROM="/home/struktured/projects/bis/Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
EMULATOR="/home/struktured/projects/bis/build/emulator/Lime3DS/build/bin/Release/azahar"

echo "ROM: $ROM"
echo "Emulator: $EMULATOR"
echo ""
echo "Starting clean game (30fps, unmodded)..."
echo ""

# Launch with proper env vars
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    QT_QPA_PLATFORM=xcb \
    "$EMULATOR" "$ROM"

# Re-enable mods when done
echo ""
echo "Re-enabling mods..."
for emu in azahar lime3ds citra; do
    MODS_DIR=~/.local/share/${emu}-emu/load/mods
    if [ -d "${MODS_DIR}.disabled" ]; then
        mv "${MODS_DIR}.disabled" "$MODS_DIR"
    fi
done

echo "Mods re-enabled."
