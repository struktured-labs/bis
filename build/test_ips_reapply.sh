#!/bin/bash
# Quick test: verify IPS patches are re-applied after save state load
set -e
cd /home/struktured/projects/bis

echo "=== IPS Re-apply Test ==="

# Install save state and patches
STATES_DIR="$HOME/.local/share/azahar-emu/states"
mkdir -p "$STATES_DIR"
cp tmp/save_dimble_woods/00040000001D1400.02.cst "$STATES_DIR/00040000001D1400.02.cst"

SAVE_DIR="$HOME/.local/share/azahar-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000/001d1400/data/00000001"
mkdir -p "$SAVE_DIR"
cp tmp/save_dimble_woods/ML3R_00*.sav "$SAVE_DIR/"

IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
mkdir -p "$IPS_DIR"
cp patches/60fps_v3_update_v1.2.ips "$IPS_DIR/code.ips"

INI="$HOME/.config/azahar-emu/qt-config.ini"
if [ -f "$INI" ]; then
    sed -i 's/^volume=.*/volume=0/' "$INI"
    sed -i 's/^volume\\default=.*/volume\\default=false/' "$INI"
fi

# Input: load state at frame 1, then idle
cat > input_script.txt << 'SCRIPT'
# Load state from slot 2
1 1 4000 2.0 0.0
SCRIPT

pkill -f bis_emu 2>/dev/null || true
sleep 1

if ! pgrep -f "Xvfb :99" > /dev/null 2>&1; then
    rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
    Xvfb :99 -screen 0 800x600x24 &
    sleep 2
fi

export DISPLAY=:99
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
export QT_QPA_PLATFORM=xcb
export SDL_AUDIODRIVER=dummy

ROM="tmp/rom_v22_build/bis_v22_merged.3ds"
EMU="build/emulator/Lime3DS/build/bin/Release/bis_emu"

rm -f tmp/citra_fps.csv

echo "Starting emulator (capturing stderr)..."
$EMU "$ROM" 2>tmp/emu_stderr.log &
EMU_PID=$!
echo "PID: $EMU_PID"

# Wait 60 seconds for save state load + some gameplay
for i in $(seq 1 12); do
    sleep 5
    if ! kill -0 $EMU_PID 2>/dev/null; then
        echo "CRASH at ${i}x5s"
        break
    fi
    if [ -f tmp/citra_fps.csv ]; then
        LINES=$(wc -l < tmp/citra_fps.csv)
        AVG=$(tail -5 tmp/citra_fps.csv | awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}')
        echo "[${i}x5s] FPS: avg=$AVG ($LINES samples)"
    fi
done

kill $EMU_PID 2>/dev/null || true

echo ""
echo "=== Checking for IPS re-apply log ==="
grep -i "re-applied\|IPS\|patch" tmp/emu_stderr.log | tail -10
echo ""
echo "=== Checking for save state load ==="
grep -i "save.state\|load.*slot\|load.*complet" tmp/emu_stderr.log | tail -10
echo ""
echo "=== FPS Summary ==="
if [ -f tmp/citra_fps.csv ]; then
    TOTAL=$(wc -l < tmp/citra_fps.csv)
    AVG=$(awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}' tmp/citra_fps.csv)
    echo "Total: $TOTAL samples, avg=$AVG FPS"
    echo "Last 10 game_fps values:"
    tail -10 tmp/citra_fps.csv | awk -F',' '{print "  "$2}'
fi
