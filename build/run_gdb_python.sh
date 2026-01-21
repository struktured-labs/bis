#!/bin/bash
# Run GDB with Python script for automated watchpoint
set -e
cd /home/struktured/projects/bis

EMULATOR="$HOME/.local/bin/citra.AppImage"
ROM="build/Mario_Luigi_BIS_60fps_FINAL.3ds"

mkdir -p tmp
rm -f tmp/gdb_fps_watchpoint.log

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GDB Python Watchpoint - Fully Automated                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Using GDB Python API for proper timing and control"
echo "Will set watchpoint after 15 seconds, capture 3 hits"
echo ""

# Create GDB init file that sources our Python script
cat > tmp/gdb_init.gdb <<EOF
set pagination off
set confirm off
python
import sys
sys.path.insert(0, '/home/struktured/projects/bis/build')
exec(open('/home/struktured/projects/bis/build/gdb_python_watchpoint.py').read())
end
EOF

# Run GDB with Python script
timeout 90 \
    env DISPLAY=:0 \
    MESA_GL_VERSION_OVERRIDE=4.6 \
    __GLX_VENDOR_LIBRARY_NAME=nvidia \
    SDL_AUDIODRIVER=dummy \
    gdb -quiet \
    -x tmp/gdb_init.gdb \
    --args "$EMULATOR" "$ROM" \
    2>&1 | tee tmp/gdb_full_output.txt

# Cleanup
pkill -9 citra 2>/dev/null || true
pkill -9 azahar 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -f tmp/gdb_fps_watchpoint.log ]; then
    echo "Watchpoint log created: tmp/gdb_fps_watchpoint.log"
    echo ""

    # Extract key findings
    echo "Program Counter addresses found:"
    grep -E "Program Counter: 0x" tmp/gdb_fps_watchpoint.log || echo "  (none captured)"

    echo ""
    echo "View full log:"
    echo "  cat tmp/gdb_fps_watchpoint.log"
else
    echo "No log file created - checking error output..."
    tail -50 tmp/gdb_full_output.txt
fi
