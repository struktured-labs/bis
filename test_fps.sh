#!/bin/bash
# Automated FPS test script for BIS patches
# Uses xvfb to run emulator headlessly and capture screenshot

PATCH_FILE="${1:-}"
ROM="/home/struktured/projects/bis/Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
SCREENSHOT_DIR="/home/struktured/projects/bis/tmp"
TIMEOUT_SEC="${2:-15}"

mkdir -p "$SCREENSHOT_DIR"

# Install patch if provided
if [ -n "$PATCH_FILE" ] && [ -f "$PATCH_FILE" ]; then
    cp "$PATCH_FILE" ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/exefs/code.ips
    PATCH_NAME=$(basename "$PATCH_FILE" .ips)
    echo "Installed patch: $PATCH_FILE"
elif [ -n "$PATCH_FILE" ]; then
    echo "Patch file not found: $PATCH_FILE"
    exit 1
else
    rm -f ~/.local/share/lime3ds-emu/load/mods/00040000001D1400/exefs/code.ips
    PATCH_NAME="baseline"
    echo "No patch (baseline test)"
fi

# Start xvfb with a virtual display
export DISPLAY=:99
Xvfb :99 -screen 0 1280x720x24 &
XVFB_PID=$!
sleep 2

# Launch emulator
QT_QPA_PLATFORM=xcb __GLX_VENDOR_LIBRARY_NAME=nvidia /home/struktured/.local/bin/lime3ds.AppImage "$ROM" &
EMU_PID=$!

echo "Waiting ${TIMEOUT_SEC}s for game to boot..."
sleep "$TIMEOUT_SEC"

# Check if emulator is still running
if ! ps -p $EMU_PID > /dev/null 2>&1; then
    echo "RESULT: CRASH"
    echo "SCREENSHOT: none"
    kill $XVFB_PID 2>/dev/null
    exit 1
fi

# Capture screenshot
SCREENSHOT="$SCREENSHOT_DIR/${PATCH_NAME}_$(date +%s).png"
import -window root "$SCREENSHOT" 2>/dev/null

# Kill emulator
kill $EMU_PID 2>/dev/null
kill $XVFB_PID 2>/dev/null
wait 2>/dev/null

if [ ! -f "$SCREENSHOT" ]; then
    echo "RESULT: NO_SCREENSHOT"
    exit 1
fi

echo "RESULT: RUNNING"
echo "SCREENSHOT: $SCREENSHOT"
