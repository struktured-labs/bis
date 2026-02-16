#!/bin/bash
# Test new IPS patch targets (VBlank wait + frame skip)
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
            echo "$name CRASH" >> tmp/new_patch_results.txt
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "  $name: ${avg} FPS"
            echo "$name ${avg}" >> tmp/new_patch_results.txt
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "  $name: HANG (no FPS after 60s)"
    echo "$name HANG" >> tmp/new_patch_results.txt
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

rm -f tmp/new_patch_results.txt
echo "=== New Patch Test (VBlank + Frame Skip targets) ==="

# Baseline first
test_combo "baseline" ""

# Individual patches
test_combo "D(no_frameskip)" "tmp/code_patchD.ips"
test_combo "E(vblank_ret)" "tmp/code_patchE.ips"
test_combo "F(nop_vblank_svc)" "tmp/code_patchF.ips"
test_combo "G(skip_wait)" "tmp/code_patchG.ips"
test_combo "I(no_77_set)" "tmp/code_patchI.ips"

# Combinations
test_combo "D+I" "tmp/code_combo_DI.ips"
test_combo "D+G" "tmp/code_combo_DG.ips"
test_combo "F+I" "tmp/code_combo_FI.ips"
test_combo "G+I" "tmp/code_combo_GI.ips"
test_combo "D+F+G+I" "tmp/code_combo_DFGI.ips"

# Cleanup
rm -f "$IPS_DIR/code.ips"

echo ""
echo "=== RESULTS ==="
cat tmp/new_patch_results.txt
