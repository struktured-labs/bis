#!/bin/bash
# GDB Watchpoint - Find FPS Control Code Runtime
# This is the definitive way to find what accesses 0x30000075

set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"
GDB_LOG="tmp/gdb_fps_watchpoint.log"

mkdir -p tmp

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GDB Watchpoint Analysis - FPS Control Discovery            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "This will use GDB to watch memory address 0x30000075 and find"
echo "what code reads/writes to it during gameplay."
echo ""
echo "IMPORTANT: You'll need to interact with the game briefly."
echo ""

# Create GDB commands
cat > tmp/gdb_commands.gdb <<'EOF'
# GDB script for FPS watchpoint

set pagination off
set logging file tmp/gdb_fps_watchpoint.log
set logging overwrite on
set logging on

# Handle segfaults gracefully
handle SIGSEGV nostop noprint pass

echo \n=== Starting emulator ===\n
run

# User will manually trigger this after game loads
define watch_fps
  echo \n=== Setting memory watchpoint on 0x30000075 ===\n

  # Watch for any access to this address
  watch *(unsigned char*)0x30000075
  rwatch *(unsigned char*)0x30000075

  echo \n=== Watchpoints set ===\n
  echo Continuing execution...\n
  echo The debugger will break when FPS byte is accessed\n
  echo \n

  continue

  # When watchpoint hits
  echo \n\n
  echo ===================================================================\n
  echo   WATCHPOINT HIT - FPS Control Code Found!\n
  echo ===================================================================\n
  echo \n

  # Show current state
  echo --- Registers ---\n
  info registers
  echo \n

  # Show backtrace
  echo --- Call Stack ---\n
  backtrace 20
  echo \n

  # Disassemble around current location
  echo --- Disassembly (32 bytes before/after) ---\n
  disassemble $pc-32,$pc+32
  echo \n

  # Show memory at target address
  echo --- Memory at 0x30000075 ---\n
  x/16xb 0x30000075
  echo \n

  echo ===================================================================\n
  echo   Analysis saved to tmp/gdb_fps_watchpoint.log\n
  echo ===================================================================\n
  echo \n

  # Continue to see if there are more accesses
  echo Continuing to catch more accesses...\n
  continue
end

# Alternative: auto-watch after delay
define auto_watch
  echo \n=== Auto-watch mode: waiting 10 seconds for game to load ===\n
  shell sleep 10
  watch_fps
end

echo \n
echo ===================================================================\n
echo   GDB Ready - Game Starting\n
echo ===================================================================\n
echo \n
echo "Commands available:"\n
echo "  watch_fps    - Set watchpoint on 0x30000075 (use after title screen)"\n
echo "  auto_watch   - Automatically set watchpoint after 10 second delay"\n
echo "  continue     - Resume execution"\n
echo "  quit         - Exit"\n
echo \n
echo "INSTRUCTIONS:"\n
echo "  1. Wait for game to load (get past title screen)"\n
echo "  2. Press Ctrl+C in this terminal"\n
echo "  3. Type: watch_fps"\n
echo "  4. Press Enter"\n
echo "  5. Game will continue and break when FPS byte is accessed"\n
echo \n
echo "Or use 'auto_watch' to automate step 1-2"\n
echo \n

EOF

echo "Starting Citra under GDB..."
echo ""
echo "Press Enter when ready to start..."
read

# Launch with GDB
DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    gdb -x tmp/gdb_commands.gdb \
    --args "$EMULATOR" "$ROM"

echo ""
echo "GDB session ended"
echo ""

if [ -f "$GDB_LOG" ]; then
    echo "Results saved to: $GDB_LOG"
    echo ""
    echo "Searching for program counter (PC) in log..."
    grep -A 5 "pc " "$GDB_LOG" | head -20 || echo "No PC found yet"
fi
