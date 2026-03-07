#!/bin/bash
set -e
cd /home/struktured/projects/bis

echo "=== 60fps v3 Patch Test ==="
echo "Tests: code.bin v3 (9 sites) + HugeBattle.cro patch"
echo ""

# Restore EUR save
SAVE_DIR="$HOME/.local/share/azahar-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000/001d1400/data/00000001"
cp tmp/eur_save/ML3R_00*.sav "$SAVE_DIR/"

pkill -f "bis_emu\|azahar" 2>/dev/null || true
sleep 2

# Generate simple input: B spam for 30s, then idle
cat > input_script.txt << 'SCRIPT'
# Simple test: B to start, then idle for FPS measurement
234 5 002
468 5 002
702 5 002
936 5 002
1170 5 002
1404 5 002
1638 5 002
1872 5 002
2106 5 002
2340 5 002
2574 5 002
2808 5 002
3042 5 002
3276 5 002
3510 5 002
3744 5 002
3978 5 002
4212 5 002
4446 5 002
4680 5 002
4914 5 002
5148 5 002
5382 5 002
5616 5 002
5850 5 002
6084 5 002
6318 5 002
6552 5 002
6786 5 002
7020 5 001
SCRIPT

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

# Install v3 patch
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
mkdir -p "$IPS_DIR"
cp patches/60fps_v3_update_v1.2.ips "$IPS_DIR/code.ips"

# Install HugeBattle CRO patch
CRO_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/romfs/RO"
mkdir -p "$CRO_DIR"
cp tmp/HugeBattle_patched.cro "$CRO_DIR/HugeBattle.cro"

rm -f tmp/citra_fps.csv

echo "Starting emulator..."
$EMU "$ROM" &
EMU_PID=$!
echo "PID: $EMU_PID"

# Wait for FPS data
DURATION=180
START_TIME=$(date +%s)
LAST_REPORT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    if ! kill -0 $EMU_PID 2>/dev/null; then
        echo "FAIL: Emulator crashed!"
        exit 1
    fi
    ELAPSED=$(($(date +%s) - START_TIME))
    if [ -f tmp/citra_fps.csv ] && [ $((ELAPSED - LAST_REPORT)) -ge 30 ]; then
        LINES=$(wc -l < tmp/citra_fps.csv)
        AVG=$(tail -20 tmp/citra_fps.csv | awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}')
        MIN=$(tail -20 tmp/citra_fps.csv | awk -F',' '$2>0 {if(min==""||$2<min) min=$2} END {printf "%.1f", min}')
        echo "[$((ELAPSED))s] FPS: avg=$AVG min=$MIN ($LINES samples)"
        LAST_REPORT=$ELAPSED
    fi
    sleep 5
done

# Final report
echo ""
echo "=== RESULTS ==="
if [ -f tmp/citra_fps.csv ]; then
    TOTAL=$(wc -l < tmp/citra_fps.csv)
    AVG=$(awk -F',' '$2>0 {sum+=$2; cnt++} END {if(cnt>0) printf "%.1f", sum/cnt}' tmp/citra_fps.csv)
    MIN=$(awk -F',' '$2>0 {if(min==""||$2<min) min=$2} END {printf "%.1f", min}' tmp/citra_fps.csv)
    MAX=$(awk -F',' '$2>0 {if(max==""||$2>max) max=$2} END {printf "%.1f", max}' tmp/citra_fps.csv)
    LOW_COUNT=$(awk -F',' '$2>0 && $2<50 {cnt++} END {print cnt+0}' tmp/citra_fps.csv)
    echo "Samples: $TOTAL"
    echo "FPS: avg=$AVG min=$MIN max=$MAX"
    echo "Sub-50 FPS samples: $LOW_COUNT"
    if [ "$(echo "$AVG > 55" | bc)" -eq 1 ]; then
        echo "PASS: Average FPS > 55"
    else
        echo "FAIL: Average FPS <= 55"
    fi
else
    echo "FAIL: No FPS data collected"
fi

kill $EMU_PID 2>/dev/null || true
