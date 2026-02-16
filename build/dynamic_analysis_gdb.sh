#!/bin/bash

# Dynamic Analysis Script - Find Frame Limiter with GDB
# Sets watchpoint on 0x30000075 to find what's writing to FPS byte

set -e
cd /home/struktured/projects/bis

EMULATOR="/home/struktured/.local/bin/citra.AppImage"
ROM="Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"
GDB_LOG="tmp/gdb_analysis.log"

mkdir -p tmp

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Dynamic Analysis - Frame Limiter Discovery with GDB         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "This will:"
echo "  1. Launch Citra with GDB attached"
echo "  2. Set watchpoint on FPS control address (0x30000075)"
echo "  3. Run until watchpoint hits"
echo "  4. Capture backtrace and assembly"
echo "  5. Find the actual frame limiter code"
echo ""
echo "Note: This requires the game to be running (past title screen)"
echo ""

# Create GDB command script
cat > tmp/gdb_commands.txt <<'EOF'
# GDB commands for frame limiter analysis

# Set up for 3DS emulation
set pagination off
set logging file tmp/gdb_analysis.log
set logging on

# Run the emulator
run

# Wait for game to load (user must get past title screen)
echo \n=== Waiting for game to load ===\n
echo Press Ctrl+C when you're in-game (past title screen)\n

# After Ctrl+C, set watchpoint on FPS byte
define analyze_fps
  echo \n=== Setting watchpoint on 0x30000075 ===\n

  # This is the address the CTRPF cheat writes to
  watch *(unsigned char*)0x30000075

  echo \n=== Continuing execution - waiting for FPS write ===\n
  continue

  # When watchpoint hits
  echo \n=== WATCHPOINT HIT - Frame limiter found! ===\n

  # Show what wrote to it
  info registers

  # Show backtrace
  backtrace 20

  # Disassemble around current location
  disassemble $pc-32,$pc+32

  # Show memory at address
  x/16xb 0x30000075

  echo \n=== Analysis saved to tmp/gdb_analysis.log ===\n
end

# User will run 'analyze_fps' after Ctrl+C
EOF

echo "Starting Citra with GDB..."
echo ""
echo "INSTRUCTIONS:"
echo "  1. Game will launch in a moment"
echo "  2. Play until you're past the title screen (in-game)"
echo "  3. Press Ctrl+C in THIS terminal"
echo "  4. Type: analyze_fps"
echo "  5. Press Enter"
echo "  6. Wait for watchpoint to hit"
echo ""
echo "Press Enter to start..."
read

# Launch with GDB
DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    gdb -x tmp/gdb_commands.txt \
    --args "$EMULATOR" "$ROM"

echo ""
echo "Analysis complete. Check tmp/gdb_analysis.log for results"
