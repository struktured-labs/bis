#!/bin/bash
# Setup and use rr (record and replay debugger) for FPS analysis

set -e

TMP_DIR="$(pwd)/tmp/rr_traces"
EMULATOR_BIN="$(pwd)/build/emulator/Lime3DS/build/bin/citra-qt"
ROM_PATH="${1:-$(pwd)/build/Mario_Luigi_BIS.3ds}"

mkdir -p "$TMP_DIR"

echo "=== rr (Record and Replay) Setup ==="
echo ""

# Check if rr is installed
if ! command -v rr &> /dev/null; then
    echo "rr not found. Installing..."
    sudo apt update
    sudo apt install -y rr
fi

echo "rr version: $(rr --version)"
echo ""

# Check system requirements
echo "Checking system requirements..."
if [ ! -f /proc/sys/kernel/perf_event_paranoid ]; then
    echo "Warning: perf_event_paranoid not found"
else
    PERF_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
    echo "perf_event_paranoid = $PERF_PARANOID"
    if [ "$PERF_PARANOID" -gt 1 ]; then
        echo "Warning: perf_event_paranoid > 1, rr may require root"
        echo "To fix: sudo sysctl kernel.perf_event_paranoid=1"
    fi
fi

echo ""
echo "=== Recording Test Session ==="
echo "ROM: $ROM_PATH"
echo "Emulator: $EMULATOR_BIN"
echo "Trace output: $TMP_DIR"
echo ""
echo "INSTRUCTIONS:"
echo "1. The emulator will start and be recorded by rr"
echo "2. Let the game run for ~10 seconds"
echo "3. Close the emulator (or press Ctrl+C here)"
echo "4. We'll then replay and analyze the trace"
echo ""

read -p "Press Enter to start recording..."

# Record the session (limit to 30 seconds)
cd "$TMP_DIR"
timeout 30 rr record "$EMULATOR_BIN" "$ROM_PATH" || true

# Check if recording exists
if [ ! -d "$(ls -td citra-qt-* 2>/dev/null | head -1)" ]; then
    echo "ERROR: No rr recording found!"
    exit 1
fi

TRACE_DIR=$(ls -td citra-qt-* | head -1)
echo ""
echo "=== Recording Complete ==="
echo "Trace saved to: $TMP_DIR/$TRACE_DIR"
echo ""

# Create GDB script for analysis
cat > analyze_fps.gdb << 'EOF'
# rr GDB script to analyze FPS flag writes

# Set up watchpoint on FPS flag
watch *(unsigned char*)0x30000075

# Define custom command to analyze write
define analyze_write
    echo \n=== FPS Flag Write Detected ===\n
    printf "Current value: 0x%02x\n", *(unsigned char*)0x30000075
    echo Backtrace:\n
    backtrace 10
    echo \nRegisters:\n
    info registers
    echo \nSearching for previous write (reverse execution)...\n
    reverse-continue
end

# Continue until first write
continue

# When watchpoint hits, analyze
analyze_write

# Continue finding more writes
# (user can repeat 'analyze_write' command)
EOF

echo "=== Starting Replay Analysis ==="
echo ""
echo "GDB commands available:"
echo "  continue             - Run until next write to 0x30000075"
echo "  reverse-continue     - Go backwards to PREVIOUS write"
echo "  backtrace            - Show call stack"
echo "  info registers       - Show CPU registers"
echo "  x/10i \$pc           - Disassemble at current PC"
echo "  analyze_write        - Analyze current write and go to previous"
echo ""
echo "Starting rr replay with GDB..."
echo ""

rr replay -x analyze_fps.gdb

echo ""
echo "=== Analysis Complete ==="
echo ""
echo "To replay again:"
echo "  cd $TMP_DIR"
echo "  rr replay"
echo "  (gdb) watch *(unsigned char*)0x30000075"
echo "  (gdb) continue"
echo "  (gdb) reverse-continue  # Go backwards!"
