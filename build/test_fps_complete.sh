#!/bin/bash

# Comprehensive FPS Testing
# Tests both original (30fps) and patched (60fps) ROMs with automated measurement

set -e

cd /home/struktured/projects/bis

# Define paths
ORIGINAL_ROM="Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
PATCHED_ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
MEASURE_SCRIPT="tmp/measure_fps.sh"
TEST_DURATION=60  # Run each test for 60 seconds

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Mario & Luigi BIS+BJJ - Comprehensive FPS Verification        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Verify files exist
if [ ! -f "$ORIGINAL_ROM" ]; then
    echo "❌ Original ROM not found: $ORIGINAL_ROM"
    exit 1
fi

if [ ! -f "$PATCHED_ROM" ]; then
    echo "❌ Patched ROM not found: $PATCHED_ROM"
    echo "Run the patching script first to create the patched ROM."
    exit 1
fi

# Ensure mods are disabled for clean testing
echo "Disabling LayeredFS mods for clean testing..."
for emu in azahar lime3ds citra; do
    MODS_DIR=~/.local/share/${emu}-emu/load/mods
    if [ -d "$MODS_DIR" ]; then
        if [ ! -d "${MODS_DIR}.disabled" ]; then
            mv "$MODS_DIR" "${MODS_DIR}.disabled" 2>/dev/null || true
        fi
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  TEST 1: Original ROM (Expected: ~30 FPS)"
echo "════════════════════════════════════════════════════════════════"
echo ""

$MEASURE_SCRIPT "$ORIGINAL_ROM" "original_30fps" $TEST_DURATION

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  TEST 2: Patched ROM (Expected: ~60 FPS)"
echo "════════════════════════════════════════════════════════════════"
echo ""

$MEASURE_SCRIPT "$PATCHED_ROM" "patched_60fps" $TEST_DURATION

# Re-enable mods
echo ""
echo "Re-enabling LayeredFS mods..."
for emu in azahar lime3ds citra; do
    MODS_DIR=~/.local/share/${emu}-emu/load/mods
    if [ -d "${MODS_DIR}.disabled" ]; then
        mv "${MODS_DIR}.disabled" "$MODS_DIR" 2>/dev/null || true
    fi
done

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Testing Complete!                                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Check tmp/fps_logs/ for detailed FPS measurements from both tests."
echo ""
echo "Expected results:"
echo "  - Original ROM: ~30 FPS (baseline)"
echo "  - Patched ROM: ~60 FPS (double the baseline)"
echo ""
echo "If patched ROM shows ~30 FPS, the patches did not take effect."
echo "If patched ROM shows ~60 FPS, SUCCESS! ✅"
