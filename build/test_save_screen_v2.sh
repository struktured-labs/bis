#!/bin/bash
# Save screen verification via screenshot comparison
# Takes screenshots at t=20s (save screen) and t=40s (should advance if working)
# If screenshots are different → game advanced past save screen
set -e
cd /home/struktured/projects/bis

EMU="build/emulator/Lime3DS/build/bin/Release/azahar"
XDG="$PWD/config/headless"
MODS="$HOME/.local/share/azahar-emu/load/mods/00040000001D1400/exefs"

# Input: A-mash (0-15s), touch save slot (15-25s), A-mash (25-45s)
python3 -c "
lines = []
for i in range(0, 3510, 4):
    lines.append(f'{i} 2 0x001')
    lines.append(f'{i+2} 2 0x000')
# Touch save slot 1 area - try multiple y positions
for i in range(3510, 5850, 8):
    y = 0.25 + (i % 100) * 0.003  # vary y slightly 0.25-0.55
    lines.append(f'{i} 4 0x1000 0.5 {y:.3f}')
    lines.append(f'{i+4} 4 0x0000')
for i in range(5850, 10530, 4):
    lines.append(f'{i} 2 0x001')
    lines.append(f'{i+2} 2 0x000')
with open('input_script.txt', 'w') as f:
    f.write('\n'.join(lines) + '\n')
print(f'{len(lines)} events')
"

run_save_test() {
    local name="$1" ips_file="$2"
    echo ""
    echo "=== TEST: $name ==="

    if [ -n "$ips_file" ] && [ -f "$ips_file" ]; then
        mkdir -p "$MODS"; cp "$ips_file" "$MODS/code.ips"
    else
        rm -f "$MODS/code.ips"
    fi
    rm -f tmp/citra_fps.csv tmp/ss_early_${name}.png tmp/ss_late_${name}.png

    XDG_CONFIG_HOME="$XDG" DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe \
        QT_QPA_PLATFORM=xcb SDL_AUDIODRIVER=dummy "$EMU" bis.3DS > /dev/null 2>&1 &
    local pid=$!
    sleep 5
    if ! kill -0 $pid 2>/dev/null; then echo "  CRASH at startup"; return 1; fi

    # Screenshot at t=20s (should be save screen)
    sleep 15
    DISPLAY=:99 import -window root "tmp/ss_early_${name}.png" 2>/dev/null || true

    # Screenshot at t=40s (should be past save screen if it works)
    sleep 20
    DISPLAY=:99 import -window root "tmp/ss_late_${name}.png" 2>/dev/null || true

    kill $pid 2>/dev/null; sleep 2

    # Compare screenshots
    if [ -f "tmp/ss_early_${name}.png" ] && [ -f "tmp/ss_late_${name}.png" ]; then
        # Use ImageMagick compare - get pixel difference percentage
        local diff=$(compare -metric RMSE "tmp/ss_early_${name}.png" "tmp/ss_late_${name}.png" /dev/null 2>&1 | grep -oP '[\d.]+' | head -1)
        echo "  Screenshot diff: $diff"
        local diff_int=$(echo "$diff" | awk '{printf "%d", $1 * 1000}')
        if [ "$diff_int" -gt 100 ]; then
            echo "  RESULT: PASS (screens differ → game advanced)"
        else
            echo "  RESULT: FAIL (screens same → stuck on save screen)"
        fi
    else
        echo "  RESULT: UNKNOWN (screenshots missing)"
    fi

    # Also report FPS
    if [ -f tmp/citra_fps.csv ]; then
        local fps=$(awk -F',' 'NR>1 && $2+0>0.5 && $2+0<200 {sum+=$2; n++} END {if(n>0) printf "%.1f(%d)", sum/n, n}' tmp/citra_fps.csv)
        echo "  FPS: $fps"
    fi
}

echo "=== SAVE SCREEN AUTOMATED VERIFICATION ==="

# Baseline: known-good 2-site 60fps patch
run_save_test "2site" "tmp/test_2site_60fps.ips"

# Test: simple cave (BL → MOV R1,#0 → return) — isolates BL mechanism
run_save_test "cave_simple" "tmp/test_cave_simple.ips"

# Test: full cave with fallback
run_save_test "cave_full" "tmp/test_cave_only.ips"

rm -f "$MODS/code.ips" input_script.txt
echo ""
echo "=== DONE ==="
