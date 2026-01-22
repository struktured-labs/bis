#!/bin/bash
# Test ONLY 0x20DA3AD - the most critical address from 60fps cheat
set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
LOG_FILE="tmp/gdb_0x20DA3AD.log"

mkdir -p tmp
rm -f "$LOG_FILE"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Testing Critical Address: 0x20DA3AD                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Start emulator
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" &

EMU_PID=$!
echo "Emulator PID: $EMU_PID"
sleep 20

if ! ps -p $EMU_PID > /dev/null 2>&1; then
    echo "ERROR: Emulator crashed"
    exit 1
fi

# Create GDB commands
cat > tmp/gdb_single.gdb <<EOF
set pagination off
set confirm off
set logging file $LOG_FILE
set logging overwrite on
set logging on

attach $EMU_PID
handle SIGSEGV nostop noprint pass
handle SIGILL nostop noprint pass

echo ===================================================================\\n
echo   Watchpoint on 0x20DA3AD (FPS Control Address?)\\n
echo ===================================================================\\n

watch *(unsigned char*)0x20DA3AD
rwatch *(unsigned char*)0x20DA3AD

echo Continuing for 60 seconds...\\n
continue

echo \\nWatchpoint hit #1\\n
info registers
backtrace 10
x/32xb 0x20DA3AD

continue

echo \\nWatchpoint hit #2\\n
info registers
backtrace 10

detach
quit
EOF

timeout 70 gdb -batch -x tmp/gdb_single.gdb 2>&1 | tee tmp/gdb_single_output.txt || true

kill $EMU_PID 2>/dev/null || true
sleep 2
pkill -9 citra 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"

if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
    if grep -q "Watchpoint hit" "$LOG_FILE"; then
        echo "🎯 SUCCESS: Address 0x20DA3AD IS ACCESSED BY GAME!"
        echo ""
        echo "This is likely the REAL FPS control address!"
        grep -B 2 -A 10 "Watchpoint hit" "$LOG_FILE" | head -40
    else
        echo "No watchpoint hits - address not accessed"
    fi
else
    echo "Log file empty - checking output..."
    tail -30 tmp/gdb_single_output.txt
fi
