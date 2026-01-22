#!/bin/bash
# Test the newly discovered addresses from complete 60fps cheat
set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
LOG_FILE="tmp/gdb_new_addresses.log"

mkdir -p tmp
rm -f "$LOG_FILE"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Testing New Addresses from Complete 60fps Cheat            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Addresses to test:"
echo "  0x520DA3AD (0x20DA3AD + offset 0x30000000)"
echo "  0x20DA3AD  (without offset - might be in code.bin)"
echo "  0x30000065"
echo "  0x30000045"
echo ""

# Start emulator
echo "Starting emulator..."
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" &

EMU_PID=$!
echo "Emulator PID: $EMU_PID"
echo ""

echo "Waiting 20 seconds for game to load..."
sleep 20

if ! ps -p $EMU_PID > /dev/null 2>&1; then
    echo "ERROR: Emulator crashed"
    exit 1
fi

echo "Attaching GDB..."

# Create GDB commands
cat > tmp/gdb_new_addr.gdb <<EOF
set pagination off
set confirm off
set logging file $LOG_FILE
set logging overwrite on
set logging on

attach $EMU_PID

handle SIGSEGV nostop noprint pass
handle SIGILL nostop noprint pass

echo \\n
echo ===================================================================\\n
echo   Setting Watchpoints on New Addresses\\n
echo ===================================================================\\n
echo \\n

# Try 0x20DA3AD first (might be actual game address)
echo Attempting watchpoint on 0x20DA3AD...\\n
catch signal all
watch *(unsigned char*)0x20DA3AD
rwatch *(unsigned char*)0x20DA3AD

# Also try the other addresses
echo Attempting watchpoint on 0x30000065...\\n
watch *(unsigned char*)0x30000065
rwatch *(unsigned char*)0x30000065

echo Attempting watchpoint on 0x30000045...\\n
watch *(unsigned char*)0x30000045
rwatch *(unsigned char*)0x30000045

echo \\n
echo Watchpoints set, continuing for 60 seconds...\\n
echo \\n

continue

# This will run until watchpoint hits or timeout
EOF

# Run GDB with timeout
timeout 70 gdb -batch -x tmp/gdb_new_addr.gdb 2>&1 | tee tmp/gdb_new_addr_output.txt || true

# Kill emulator
kill $EMU_PID 2>/dev/null || true
sleep 2
pkill -9 citra 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Analysis Complete"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
    echo "SUCCESS: Log created"
    echo ""

    # Check for watchpoint hits
    if grep -q "Hardware watchpoint" "$LOG_FILE"; then
        echo "🎯 WATCHPOINT HIT DETECTED!"
        echo ""
        grep -A 5 "Hardware watchpoint" "$LOG_FILE" | head -20
    else
        echo "No watchpoint hits (addresses not accessed by game)"
    fi

    echo ""
    echo "Full log: $LOG_FILE"
else
    echo "WARNING: Log file empty"
    tail -30 tmp/gdb_new_addr_output.txt
fi
