#!/bin/bash
# Test R button effect on FPS with watchpoint-enabled emulator
# Uses save state to skip intro, presses R during gameplay
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="tmp/rom_v22_build/bis_v22_merged.3ds"
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"
WATCHLOG="tmp/fps_watchpoint.csv"

# Install full patch
mkdir -p "$IPS_DIR"
cp patches/60fps_v12_full.ips "$IPS_DIR/code.ips"

# Clean old logs
pkill -9 -f azahar 2>/dev/null
sleep 2
rm -f "$CSV" "$WATCHLOG"

# Create input script:
# Phase 1 (0-10s ~2340 frames): no R, establish baseline FPS
# Phase 2 (10-20s ~2340-4680): hold R button (0x100)
# Phase 3 (20-30s ~4680-7020): release R, check recovery
# Also walk around with circle pad to be in gameplay
cat > input_script.txt << 'SCRIPT'
# Walk right during entire test (circle pad)
0 7020 000 0.8 0.0
# Phase 2: hold R button (frames 2340-4680, ~10-20 seconds)
2340 2340 100
SCRIPT

echo "=== R Button FPS Test (v1.2 + full patch, watchpoints ON) ==="
echo "Phase 1: baseline (0-10s), Phase 2: R held (10-20s), Phase 3: R released (20-30s)"

env DISPLAY=:99 \
    LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    QT_QPA_PLATFORM=xcb \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" "$ROM" &
pid=$!

# Monitor FPS in 5-second intervals for 35 seconds
for t in $(seq 5 5 35); do
    sleep 5
    if ! kill -0 $pid 2>/dev/null; then
        echo "CRASH at ${t}s"
        break
    fi
    lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
    if [ "$lines" -gt 2 ]; then
        # Get FPS for last 5 seconds (~5 samples)
        recent_avg=$(tail -5 "$CSV" | awk -F',' '$2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}')
        echo "t=${t}s: ${recent_avg} FPS (${lines} total samples)"
    else
        echo "t=${t}s: waiting for FPS data..."
    fi
done

kill $pid 2>/dev/null
pkill -9 -f azahar 2>/dev/null
sleep 1

# Analyze watchpoint log
echo ""
echo "=== Watchpoint Analysis ==="
if [ -f "$WATCHLOG" ]; then
    total=$(wc -l < "$WATCHLOG")
    echo "Total watchpoint entries: $total"
    echo ""
    echo "Unique PCs writing to FPS byte range:"
    grep "^W" "$WATCHLOG" | awk -F',' '{print $2}' | sort | uniq -c | sort -rn | head -20
    echo ""
    echo "Unique PCs reading FPS byte range:"
    grep "^R" "$WATCHLOG" | awk -F',' '{print $2}' | sort | uniq -c | sort -rn | head -20
    echo ""
    echo "Writes to 0x320da3ad (FPS byte) specifically:"
    grep "0x320da3ad" "$WATCHLOG" | head -30
else
    echo "No watchpoint log found (fastmem may still be enabled)"
fi

# Also check FPS CSV for phase analysis
echo ""
echo "=== FPS Phase Analysis ==="
if [ -f "$CSV" ]; then
    # Split by time ranges
    total_lines=$(wc -l < "$CSV")
    third=$((total_lines / 3))
    echo "Phase 1 (baseline) avg:"
    head -$third "$CSV" | awk -F',' 'NR>1 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f FPS (%d samples)\n", sum/count, count; else print "no data"}'
    echo "Phase 2 (R held) avg:"
    head -$((third*2)) "$CSV" | tail -$third | awk -F',' '$2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f FPS (%d samples)\n", sum/count, count; else print "no data"}'
    echo "Phase 3 (R released) avg:"
    tail -$third "$CSV" | awk -F',' '$2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f FPS (%d samples)\n", sum/count, count; else print "no data"}'
fi

rm -f input_script.txt
rm -f "$IPS_DIR/code.ips"
echo "=== Done ==="
