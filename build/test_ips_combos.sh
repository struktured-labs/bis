#!/bin/bash
# Test all IPS patch combinations headlessly
cd /home/struktured/projects/bis

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
ROM="bis.3DS"
IPS_DIR="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"
CSV="tmp/citra_fps.csv"

test_combo() {
    local name="$1"
    local ips_file="$2"

    # Install IPS (or remove for baseline)
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

    # Wait up to 60s for FPS data
    for t in $(seq 5 5 60); do
        sleep 5
        if ! kill -0 $pid 2>/dev/null; then
            echo "  $name: CRASH at ${t}s"
            echo "$name CRASH" >> tmp/ips_results.txt
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "  $name: ${avg} FPS"
            echo "$name ${avg}" >> tmp/ips_results.txt
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "  $name: HANG (no FPS after 60s)"
    echo "$name HANG" >> tmp/ips_results.txt
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

rm -f tmp/ips_results.txt
echo "=== IPS Patch Combination Test ==="

test_combo "baseline" ""
test_combo "A(beq_nop)" "tmp/code_patchA.ips"
test_combo "B(loop=1)" "tmp/ips_combo_B_only.ips"
test_combo "C(state=1)" "tmp/ips_combo_C_only.ips"
test_combo "A+B" "tmp/ips_combo_AB.ips"
test_combo "A+C" "tmp/ips_combo_AC.ips"
test_combo "B+C" "tmp/ips_combo_BC.ips"
test_combo "A+B+C" "tmp/ips_combo_ABC.ips"

# Cleanup
rm -f "$IPS_DIR/code.ips"

echo ""
echo "=== RESULTS ==="
cat tmp/ips_results.txt
