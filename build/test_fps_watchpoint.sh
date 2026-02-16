#!/bin/bash
# Test FPS Watchpoint - Capture writes to 0x30000075

set -e
cd /home/struktured/projects/bis

CUSTOM_EMU="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
WATCHPOINT_LOG="tmp/fps_watchpoint.log"
TEST_DURATION=30  # seconds

mkdir -p tmp

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  FPS Watchpoint Test - Find Frame Limiter Code              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "This will:"
echo "  1. Launch custom Lime3DS emulator with FPS watchpoint enabled"
echo "  2. Run Mario & Luigi BIS for ${TEST_DURATION} seconds"
echo "  3. Capture ALL writes to 0x30000075 (FPS control byte)"
echo "  4. Log Program Counter (PC) for each write"
echo "  5. Analyze logs to find frame limiter code"
echo ""

# Clean old log
rm -f "$WATCHPOINT_LOG"

echo "Starting emulator (will run for ${TEST_DURATION} seconds)..."
echo ""

# Launch emulator in background
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    "$CUSTOM_EMU" "$ROM" &

EMU_PID=$!
echo "Emulator PID: $EMU_PID"

# Wait for test duration
echo "Waiting ${TEST_DURATION} seconds for game to run..."
sleep $TEST_DURATION

# Kill emulator
echo "Stopping emulator..."
kill $EMU_PID 2>/dev/null || true
sleep 2
pkill -9 azahar 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  WATCHPOINT LOG ANALYSIS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ ! -f "$WATCHPOINT_LOG" ]; then
    echo "⚠️  No watchpoint log created"
    echo "This could mean:"
    echo "  - Address 0x30000075 was never written to"
    echo "  - Game didn't load properly"
    echo "  - Watchpoint logging failed"
    exit 1
fi

# Check log size
LOG_SIZE=$(wc -l < "$WATCHPOINT_LOG")
echo "Total writes captured: $((LOG_SIZE - 1))"
echo ""

if [ $LOG_SIZE -le 1 ]; then
    echo "⚠️  No writes detected to 0x30000075"
    echo "This is unexpected - the CTRPF cheat writes to this address every frame"
    exit 1
fi

echo "First 10 writes:"
head -11 "$WATCHPOINT_LOG"
echo ""

echo "Last 10 writes:"
tail -10 "$WATCHPOINT_LOG"
echo ""

# Analyze unique PC values
echo "═══════════════════════════════════════════════════════════════"
echo "  UNIQUE PROGRAM COUNTERS (PC)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "These are the code locations that write to 0x30000075:"
echo ""

awk -F',' 'NR>1 {print $2}' "$WATCHPOINT_LOG" | sort | uniq -c | sort -rn | head -20

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. Use Ghidra to disassemble code.bin"
echo "2. Navigate to the PC addresses shown above"
echo "3. Analyze the frame limiter logic"
echo "4. Create targeted patch to modify frame timing"
echo ""
echo "Full log saved to: $WATCHPOINT_LOG"
