#!/bin/bash
# GDB Attach Approach - Most Reliable
# Start emulator first, then attach GDB to it
set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
LOG_FILE="tmp/gdb_fps_watchpoint.log"

mkdir -p tmp
rm -f "$LOG_FILE"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GDB Attach Method - Fully Automated Watchpoint             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Step 1: Starting emulator..."
echo ""

# Start emulator in background
env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" &

EMU_PID=$!

echo "Emulator started with PID: $EMU_PID"
echo ""
echo "Step 2: Waiting 20 seconds for game to fully load..."
sleep 20

# Check if still running
if ! ps -p $EMU_PID > /dev/null 2>&1; then
    echo "ERROR: Emulator crashed during startup"
    exit 1
fi

echo ""
echo "Step 3: Attaching GDB to running process..."
echo ""

# Create GDB commands for attach
cat > tmp/gdb_attach.gdb <<EOF
set pagination off
set confirm off
set logging file $LOG_FILE
set logging overwrite on
set logging on

# Attach to process
attach $EMU_PID

# Handle signals
handle SIGSEGV nostop noprint pass
handle SIGILL nostop noprint pass

echo \n
echo ===================================================================\n
echo   GDB Attached - Setting Watchpoints\n
echo ===================================================================\n
echo \n

# Set watchpoints on FPS byte
watch *(unsigned char*)0x30000075
rwatch *(unsigned char*)0x30000075

echo Watchpoints set on 0x30000075\n
echo Continuing execution...\n
echo \n

# Continue execution
continue

# When watchpoint hits (first time)
echo \n
echo ===================================================================\n
echo   WATCHPOINT HIT #1\n
echo ===================================================================\n
echo \n

info registers
echo \n

backtrace 20
echo \n

disassemble \$pc-32,\$pc+64
echo \n

x/32xb 0x30000075
echo \n

# Continue for second hit
continue

# Second hit
echo \n
echo ===================================================================\n
echo   WATCHPOINT HIT #2\n
echo ===================================================================\n
echo \n

info registers
backtrace 20
disassemble \$pc-32,\$pc+64

# Continue for third hit
continue

# Third hit
echo \n
echo ===================================================================\n
echo   WATCHPOINT HIT #3\n
echo ===================================================================\n
echo \n

info registers
backtrace 20
disassemble \$pc-32,\$pc+64

# Detach and quit
echo \n
echo Collected 3 watchpoint hits, detaching...\n
detach
quit
EOF

# Run GDB in batch mode
timeout 60 gdb -batch -x tmp/gdb_attach.gdb 2>&1 | tee tmp/gdb_attach_output.txt || true

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
    echo "SUCCESS: Watchpoint log created"
    echo ""

    # Extract PC addresses
    echo "Program Counter (PC) addresses when FPS byte was accessed:"
    grep -E "pc\s+0x|rip\s+0x" "$LOG_FILE" | head -10 || echo "  (no PC found in log)"

    echo ""
    echo "Full log: $LOG_FILE"
    echo "Output: tmp/gdb_attach_output.txt"
else
    echo "WARNING: Log file empty or not created"
    echo ""
    echo "Checking GDB output for errors..."
    tail -30 tmp/gdb_attach_output.txt
fi
