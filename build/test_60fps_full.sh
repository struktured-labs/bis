#!/bin/bash
# A/B test: baseline vs 60fps-everywhere patch (v1.2 ROM)
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="tmp/rom_v22_build/bis_v22_merged.3ds"
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"

test_run() {
    local name="$1"
    local ips_file="$2"

    mkdir -p "$IPS_DIR"
    if [ -n "$ips_file" ]; then
        cp "$ips_file" "$IPS_DIR/code.ips"
    else
        rm -f "$IPS_DIR/code.ips"
    fi

    pkill -9 -f azahar 2>/dev/null
    sleep 2
    rm -f "$CSV"

    env DISPLAY=:99 \
        XAUTHORITY=/tmp/xvfb-run.mQUFVs/Xauthority \
        LIBGL_ALWAYS_SOFTWARE=1 \
        GALLIUM_DRIVER=llvmpipe \
        QT_QPA_PLATFORM=xcb \
        SDL_AUDIODRIVER=dummy \
        "$EMULATOR" "$ROM" &
    local pid=$!

    for t in $(seq 5 5 60); do
        sleep 5
        if ! kill -0 $pid 2>/dev/null; then
            echo "$name: CRASH at ${t}s"
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "$name: ${avg} FPS (${lines} samples)"
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "$name: HANG (no FPS data after 60s)"
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

echo "=== 60fps-everywhere Patch A/B Test (v1.2 ROM) ==="
test_run "baseline" ""
sleep 3
test_run "60fps_original" "patches/60fps_update_v1.2.ips"
sleep 3
test_run "60fps_full" "patches/60fps_v12_full.ips"

rm -f "$IPS_DIR/code.ips"
echo "=== Done ==="
