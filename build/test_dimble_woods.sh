#!/bin/bash
# Test Dimble Woods one-way path bug at 60fps vs 30fps
set -e
cd /home/struktured/projects/bis

MODE="${1:-60fps}"  # "60fps" or "30fps"
echo "=== Dimble Woods Bug Test (${MODE}) ==="

# Install Dimble Woods save state to slot 2
STATES_DIR="$HOME/.local/share/azahar-emu/states"
mkdir -p "$STATES_DIR"
cp tmp/save_dimble_woods/00040000001D1400.02.cst "$STATES_DIR/00040000001D1400.02.cst"

# Restore save files
SAVE_DIR="$HOME/.local/share/azahar-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000/001d1400/data/00000001"
mkdir -p "$SAVE_DIR"
cp tmp/save_dimble_woods/ML3R_00*.sav "$SAVE_DIR/"

pkill -f "bis_emu" 2>/dev/null || true
sleep 2

# Generate input script
uv run python3 build/test_dimble_woods.py

# Manage patches
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CRO_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/RO"
mkdir -p "$IPS_DIR" "$CRO_DIR"

if [ "$MODE" = "60fps" ]; then
    echo "Installing v3 60fps patch + CRO fix"
    cp patches/60fps_v3_update_v1.2.ips "$IPS_DIR/code.ips"
    cp tmp/HugeBattle_patched.cro "$CRO_DIR/HugeBattle.cro"
elif [ "$MODE" = "30fps" ]; then
    echo "Removing 60fps patch (30fps baseline)"
    rm -f "$IPS_DIR/code.ips"
    rm -f "$CRO_DIR/HugeBattle.cro"
fi

# Audio config
INI="$HOME/.config/azahar-emu/qt-config.ini"
if [ -f "$INI" ]; then
    sed -i 's/^volume=.*/volume=0/' "$INI"
    sed -i 's/^volume\\default=.*/volume\\default=false/' "$INI"
fi

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

rm -f tmp/citra_fps.csv tmp/area_log.txt
mkdir -p tmp/dimble_test_ss

echo "Starting emulator..."
$EMU "$ROM" &
EMU_PID=$!
echo "PID: $EMU_PID"

DURATION=180
START_TIME=$(date +%s)
LAST_REPORT=0
SS_COUNT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    if ! kill -0 $EMU_PID 2>/dev/null; then
        echo "FAIL: Emulator crashed!"
        exit 1
    fi
    ELAPSED=$(($(date +%s) - START_TIME))

    # Screenshot every 15 seconds
    if [ $((ELAPSED % 15)) -eq 0 ] && [ $ELAPSED -gt 0 ]; then
        SS_COUNT=$((SS_COUNT + 1))
        FNAME=$(printf "dimble_%s_%04d.png" "$MODE" $SS_COUNT)
        DISPLAY=:99 import -window root "tmp/dimble_test_ss/$FNAME" 2>/dev/null || true
    fi

    # Report every 30 seconds
    if [ -f tmp/citra_fps.csv ] && [ $((ELAPSED - LAST_REPORT)) -ge 30 ]; then
        LINES=$(wc -l < tmp/citra_fps.csv)
        AVG=$(tail -20 tmp/citra_fps.csv | awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}')
        echo "[$((ELAPSED))s] FPS: avg=$AVG ($LINES samples)"
        LAST_REPORT=$ELAPSED
    fi

    # Check area log
    if [ -f tmp/area_log.txt ]; then
        AREA=$(tail -1 tmp/area_log.txt 2>/dev/null | grep -o 'area=[^ ]*' | tail -1)
        ROOM=$(tail -1 tmp/area_log.txt 2>/dev/null | grep -o 'room=[^ ]*' | tail -1)
        if [ -n "$AREA" ] && [ $((ELAPSED - LAST_REPORT)) -ge 0 ]; then
            echo "  Area: $AREA $ROOM"
        fi
    fi

    sleep 5
done

echo ""
echo "=== RESULTS ($MODE) ==="
if [ -f tmp/citra_fps.csv ]; then
    TOTAL=$(wc -l < tmp/citra_fps.csv)
    AVG=$(awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}' tmp/citra_fps.csv)
    echo "FPS: avg=$AVG ($TOTAL samples)"
fi
if [ -f tmp/area_log.txt ]; then
    echo "Areas visited:"
    sort -u tmp/area_log.txt | tail -20
fi
echo "Screenshots: $SS_COUNT in tmp/dimble_test_ss/"

# Save area log with mode suffix
cp tmp/area_log.txt "tmp/area_log_dimble_${MODE}.txt" 2>/dev/null || true
cp tmp/citra_fps.csv "tmp/fps_dimble_${MODE}.csv" 2>/dev/null || true

kill $EMU_PID 2>/dev/null || true
echo "Done."
