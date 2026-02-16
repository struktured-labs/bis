#!/bin/bash
# Automated GDB Watchpoint - No interaction needed
set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
GDB_LOG="tmp/gdb_fps_watchpoint.log"

mkdir -p tmp
rm -f "$GDB_LOG"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Automated GDB Watchpoint - FPS Control Discovery           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Running fully automated - no interaction needed"
echo "Will set watchpoint after 15 seconds to allow game to load"
echo ""

# Create automated GDB commands
cat > tmp/gdb_auto.gdb <<'EOF'
set pagination off
set logging file tmp/gdb_fps_watchpoint.log
set logging overwrite on
set logging on
set logging redirect on

handle SIGSEGV nostop noprint pass
handle SIGILL nostop noprint pass

echo Starting emulator...\n
run &

# Wait for game to load
echo Waiting 15 seconds for game to load...\n
shell sleep 15

echo Setting watchpoint on 0x30000075...\n

# Try to set watchpoint (might fail if address not mapped yet)
catch exec
watch *(unsigned char*)0x30000075
rwatch *(unsigned char*)0x30000075

echo Watchpoints set, continuing execution...\n
echo Will break when FPS byte is accessed...\n

# Continue and wait for watchpoint
continue

# When first watchpoint hits
echo \n========================================\n
echo WATCHPOINT HIT #1\n
echo ========================================\n

info registers
echo \n

backtrace 20
echo \n

disassemble $pc-32,$pc+64
echo \n

x/32xb 0x30000075
echo \n

# Continue to catch more hits
continue

# Second hit
echo \n========================================\n
echo WATCHPOINT HIT #2\n
echo ========================================\n

info registers
backtrace 20
disassemble $pc-32,$pc+64

# Continue once more
continue

# Third hit
echo \n========================================\n
echo WATCHPOINT HIT #3\n
echo ========================================\n

info registers
backtrace 20
disassemble $pc-32,$pc+64

# Quit after 3 hits
echo \nCollected 3 watchpoint hits, exiting...\n
quit

EOF

# Run GDB with timeout
timeout 60 \
    env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    gdb -batch -x tmp/gdb_auto.gdb \
    "$EMULATOR" "$ROM" \
    2>&1 | tee tmp/gdb_output.txt || true

# Kill any remaining emulator
pkill -9 citra 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Analysis Complete"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -f "$GDB_LOG" ]; then
    echo "Results saved to: $GDB_LOG"
    echo ""

    # Extract key information
    echo "Searching for Program Counter addresses..."
    grep -E "pc\s+0x" "$GDB_LOG" | head -10

    echo ""
    echo "Full log available at: $GDB_LOG"
else
    echo "No log file created - watchpoint may not have hit"
    echo "Check tmp/gdb_output.txt for details"
fi
