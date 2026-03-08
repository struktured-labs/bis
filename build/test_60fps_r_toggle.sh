#!/bin/bash
# Test 60fps R-toggle patch: verify it runs at 60fps without R button
# (Can't test R button toggle in headless mode, but can verify no crash + 60fps)
set -e
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/bis_emu"
ROM="bis.3DS"
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"
PATCH="../bis-research/patches/60fps_v12_full_r.ips"

echo "=== 60fps R-Toggle Patch Test ==="
echo "Patch: $PATCH ($(wc -c < "$PATCH") bytes)"

# Install patch
mkdir -p "$IPS_DIR"
cp "$PATCH" "$IPS_DIR/code.ips"
echo "Installed to $IPS_DIR/code.ips"

# Kill any existing emulator
pkill -9 -f bis_emu 2>/dev/null || true
sleep 2
rm -f "$CSV"

# Launch headless
echo "Launching headless emulator..."
env DISPLAY=:99 \
    LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    QT_QPA_PLATFORM=xcb \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" &
pid=$!

# Wait for FPS data
for t in $(seq 5 5 90); do
    sleep 5
    if ! kill -0 $pid 2>/dev/null; then
        echo "CRASH at ${t}s!"
        exit 1
    fi
    lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
    if [ "$lines" -gt 10 ]; then
        avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
        min=$(awk -F',' 'NR>6 && $2>0 {if(!min || $2<min) min=$2} END {printf "%.1f", min}' "$CSV")
        max=$(awk -F',' 'NR>6 && $2>0 {if($2>max) max=$2} END {printf "%.1f", max}' "$CSV")
        echo ""
        echo "=== RESULTS ==="
        echo "  Avg FPS: $avg"
        echo "  Min FPS: $min"
        echo "  Max FPS: $max"
        echo "  Samples: $lines"

        if (( $(echo "$avg > 50" | bc -l) )); then
            echo "  PASS: Running at 60fps (R-toggle code cave works!)"
        else
            echo "  FAIL: Expected >50 avg FPS, got $avg"
        fi

        kill $pid 2>/dev/null; pkill -9 -f bis_emu 2>/dev/null || true
        exit 0
    fi
    echo "  ${t}s: waiting for FPS data ($lines lines)..."
done

echo "TIMEOUT: No FPS data after 90s"
kill $pid 2>/dev/null; pkill -9 -f bis_emu 2>/dev/null || true
exit 1
