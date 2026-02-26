#!/bin/bash
# Process BIS update CIA -> extract code.bin -> find FPS patterns -> generate IPS patch -> test
set -e
cd /home/struktured/projects/bis

UPDATE_CIA="${1:-}"
if [ -z "$UPDATE_CIA" ]; then
    echo "Usage: $0 <update.cia>"
    echo "  Download from: https://hshop.erista.me/t/2851"
    echo "  Title ID: 0004000E001D1400 (v1.2 update)"
    exit 1
fi

if [ ! -f "$UPDATE_CIA" ]; then
    echo "ERROR: File not found: $UPDATE_CIA"
    exit 1
fi

EMULATOR="build/emulator/Lime3DS/build/bin/Release/azahar"
WORK="tmp/update_v12"
mkdir -p "$WORK"

echo "=== BIS Update Processing Pipeline ==="
echo "Input: $UPDATE_CIA ($(wc -c < "$UPDATE_CIA") bytes)"
echo ""

# Step 1: Install update CIA in emulator
echo "[1/6] Installing update CIA in emulator..."
env DISPLAY=:99 \
    LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    QT_QPA_PLATFORM=xcb \
    SDL_AUDIODRIVER=dummy \
    "$EMULATOR" -i "$UPDATE_CIA" 2>&1 | tail -5 || true
echo "  Done"

# Step 2: Extract CIA contents for analysis
echo ""
echo "[2/6] Extracting CIA for static analysis..."
./tools/ctrtool -t cia \
    --contents="$WORK/contents" \
    --tmd="$WORK/tmd.bin" \
    --tik="$WORK/tik.bin" \
    --certs="$WORK/certs.bin" \
    -p "$UPDATE_CIA" 2>&1 | grep -v "^$" || true

# Find the content file
CONTENT=$(ls "$WORK"/contents.* 2>/dev/null | head -1)
if [ -z "$CONTENT" ]; then
    echo "  Plain extraction..."
    ./tools/ctrtool -t cia -n 0 --ncch="$WORK/partition0.ncch" -p "$UPDATE_CIA" 2>&1 || true
    CONTENT="$WORK/partition0.ncch"
fi

if [ ! -f "$CONTENT" ]; then
    echo "ERROR: Could not extract CIA contents"
    exit 1
fi
echo "  Content: $CONTENT ($(wc -c < "$CONTENT") bytes)"

# Step 3: Extract ExeFS with decompressed code
echo ""
echo "[3/6] Extracting decompressed code.bin..."
mkdir -p "$WORK/exefs_dir"

# Try ctrtool first (handles decompression)
./tools/ctrtool -t ncch \
    --exefs="$WORK/exefs.bin" \
    --exefsdir="$WORK/exefs_dir" \
    --decompresscode \
    -p "$CONTENT" 2>&1 | grep -v "^$" || true

# Check what we got
CODE_BIN=""
if [ -f "$WORK/exefs_dir/.code" ]; then
    CODE_BIN="$WORK/exefs_dir/.code"
elif [ -f "$WORK/exefs_dir/code.bin" ]; then
    # Might need BLZ decompression
    echo "  Decompressing with BLZ..."
    cp "$WORK/exefs_dir/code.bin" "$WORK/code_compressed.bin"
    ./tools/3dstool -uvf "$WORK/code_compressed.bin" \
        --compress-type blz \
        --compress-out "$WORK/code_decompressed.bin" 2>&1
    CODE_BIN="$WORK/code_decompressed.bin"
fi

if [ -z "$CODE_BIN" ] || [ ! -f "$CODE_BIN" ]; then
    # Fallback: use 3dstool
    echo "  Fallback: using 3dstool..."
    ./tools/3dstool -xvtf cxi "$CONTENT" \
        --header "$WORK/cxi_header.bin" \
        --exh "$WORK/exheader.bin" \
        --exefs "$WORK/exefs.bin" \
        --plain "$WORK/plain.bin" 2>&1 || true
    if [ -f "$WORK/exefs.bin" ]; then
        ./tools/3dstool -xvtf exefs "$WORK/exefs.bin" \
            --exefs-dir "$WORK/exefs_dir" \
            --header "$WORK/exefs_header.bin" 2>&1
        if [ -f "$WORK/exefs_dir/code.bin" ]; then
            cp "$WORK/exefs_dir/code.bin" "$WORK/code_compressed.bin"
            ./tools/3dstool -uvf "$WORK/code_compressed.bin" \
                --compress-type blz \
                --compress-out "$WORK/code_decompressed.bin" 2>&1
            CODE_BIN="$WORK/code_decompressed.bin"
        fi
    fi
fi

if [ -z "$CODE_BIN" ] || [ ! -f "$CODE_BIN" ]; then
    echo "ERROR: Could not extract decompressed code.bin"
    ls -la "$WORK/exefs_dir/" 2>/dev/null
    exit 1
fi

echo "  Decompressed code: $CODE_BIN ($(wc -c < "$CODE_BIN") bytes)"

# Step 4: Compare with v1.0 code
echo ""
echo "[4/6] Comparing with v1.0..."
V10_CODE="tmp/decompressed/code_decompressed.bin"
if [ ! -f "$V10_CODE" ]; then
    echo "  Decompressing v1.0 code.bin..."
    mkdir -p tmp/decompressed
    cp build/v3_extract/exefs_dir/code.bin tmp/decompressed/code_original.bin
    ./tools/3dstool -uvf tmp/decompressed/code_original.bin \
        --compress-type blz \
        --compress-out "$V10_CODE"
fi
echo "  v1.0: $(wc -c < "$V10_CODE") bytes"
echo "  v1.2: $(wc -c < "$CODE_BIN") bytes"
DIFF_COUNT=$(cmp -l "$V10_CODE" "$CODE_BIN" 2>/dev/null | wc -l || echo "files differ in size")
echo "  Byte differences: $DIFF_COUNT"

# Step 5: Scan for FPS patterns and generate IPS
echo ""
echo "[5/6] Scanning for FPS patterns..."
uv run python3 build/find_fps_patterns_update.py "$CODE_BIN" "$V10_CODE"

echo ""
echo "[5b/6] Generating IPS patch (smart match)..."
uv run python3 build/generate_update_ips.py "$CODE_BIN"

echo ""
echo "[5c/6] Generating aggressive IPS (all candidates)..."
uv run python3 build/generate_update_ips.py "$CODE_BIN" --aggressive

# Step 6: Headless test
echo ""
echo "[6/6] Running headless A/B test..."
ROM="bis.3DS"
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

    pkill -9 -f azahar 2>/dev/null; sleep 2
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
            echo "$name CRASH" >> "$WORK/test_results.txt"
            return
        fi
        local lines=$(wc -l < "$CSV" 2>/dev/null || echo 0)
        if [ "$lines" -gt 6 ]; then
            local avg=$(awk -F',' 'NR>6 && $2>0 {sum+=$2; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' "$CSV")
            echo "  $name: ${avg} FPS"
            echo "$name ${avg}" >> "$WORK/test_results.txt"
            kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
            return
        fi
    done

    echo "  $name: HANG"
    echo "$name HANG" >> "$WORK/test_results.txt"
    kill $pid 2>/dev/null; pkill -9 -f azahar 2>/dev/null
}

rm -f "$WORK/test_results.txt"

# Test with update installed + no patch (baseline)
test_run "v12_baseline" ""

# Test with update + v1.2 smart patch
test_run "v12_smart_patch" "patches/60fps_v12.ips"

# Test with update + aggressive patch
test_run "v12_aggressive" "patches/60fps_v12_aggressive.ips"

# Clean up
rm -f "$IPS_DIR/code.ips"

echo ""
echo "=== RESULTS ==="
cat "$WORK/test_results.txt"
echo ""
echo "=== PIPELINE COMPLETE ==="
