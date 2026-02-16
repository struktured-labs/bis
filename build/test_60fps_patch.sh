#!/bin/bash
# Final A/B test: baseline vs 60fps IPS patch
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="bis.3DS"
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"

test_combo() {
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
        LIBGL_ALWAYS_SOFTWARE=1 \
        GALLIUM_DRIVER=llvmpipe \
        QT_QPA_PLATFORM=xcb \
        SDL_AUDIODRIVER=dummy \
        "$EMULATOR" "$ROM" &
    local pid=$!

    for t in $(seq 5 5 60); do
        sleep 5
        if ! kill -0 $pid 2>/dev/null; then
            echo "  $name: CRASH at ${t}s"
            echo "$name CRASH" >> tmp/60fps_final_results.txt
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "  $name: ${avg} FPS"
            echo "$name ${avg}" >> tmp/60fps_final_results.txt
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "  $name: HANG"
    echo "$name HANG" >> tmp/60fps_final_results.txt
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

rm -f tmp/60fps_final_results.txt
echo "=== FINAL 60fps Patch Verification ==="

test_combo "baseline" ""
test_combo "60fps_reader_patch" "tmp/code_60fps_reader.ips"
test_combo "baseline_verify" ""
test_combo "60fps_reader_patch_verify" "tmp/code_60fps_reader.ips"

rm -f "$IPS_DIR/code.ips"

echo ""
echo "=== FINAL RESULTS ==="
cat tmp/60fps_final_results.txt
