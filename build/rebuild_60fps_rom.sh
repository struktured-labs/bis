#!/bin/bash
# Rebuild ROM with VBlank loop count patch for 60fps
# Uses clean v3_extract as base, patches decompressed code.bin, recompresses
set -e
cd /home/struktured/projects/bis
export PATH="$PWD/tools:$PATH"

echo "=== 60fps ROM Build (VBlank Loop Patch) ==="

WORK="tmp/rom_build_60fps"
mkdir -p "$WORK"

# Step 1: Patch code.bin
echo "[1/4] Patching decompressed code.bin..."
if [ ! -f tmp/decompressed/code_decompressed.bin ]; then
    echo "  Decompressing original code.bin..."
    mkdir -p tmp/decompressed
    cp build/v3_extract/exefs_dir/code.bin tmp/decompressed/code_original.bin
    3dstool -uvf tmp/decompressed/code_original.bin \
        --compress-type blz \
        --compress-out tmp/decompressed/code_decompressed.bin
fi
uv run python3 build/patch_code_bin_60fps.py

# Step 2: Recompress
echo "[2/4] Recompressing patched code.bin..."
cp tmp/decompressed/code_decompressed_60fps.bin "$WORK/code_to_compress.bin"
3dstool -zvf "$WORK/code_to_compress.bin" --compress-type blz --compress-out "$WORK/code_patched.bin"
echo "  Original: $(wc -c < build/v3_extract/exefs_dir/code.bin) bytes"
echo "  Patched:  $(wc -c < "$WORK/code_patched.bin") bytes"

# Step 3: Rebuild ExeFS
echo "[3/4] Rebuilding ExeFS..."
mkdir -p "$WORK/exefs_dir"
cp build/v3_extract/exefs_dir/* "$WORK/exefs_dir/"
cp "$WORK/code_patched.bin" "$WORK/exefs_dir/code.bin"

3dstool -cvtf exefs "$WORK/exefs_patched.bin" \
    --exefs-dir "$WORK/exefs_dir" \
    --header build/v3_extract/exefs_header.bin

# Step 4: Rebuild CXI and 3DS
echo "[4/4] Rebuilding ROM..."
# Use the extracted headers/partitions from build/extracted/ (has all parts)
3dstool -cvtf cxi "$WORK/partition0.cxi" \
    --header build/extracted/cxi_header.bin \
    --exh build/extracted/exheader.bin \
    --exefs "$WORK/exefs_patched.bin" \
    --romfs build/extracted/romfs.bin \
    --logo build/extracted/logo.bin \
    --plain build/extracted/plain.bin

3dstool -cvtf 3ds "build/Mario_Luigi_BIS_60fps_vblank.3ds" \
    --header build/extracted/ncsd_header.bin \
    -0 "$WORK/partition0.cxi" \
    -1 build/extracted/partition1.cfa \
    -6 build/extracted/partition6.cfa \
    -7 build/extracted/partition7.cfa

echo ""
echo "=== BUILD COMPLETE ==="
ls -lh build/Mario_Luigi_BIS_60fps_vblank.3ds
echo ""
echo "Patch: vaddr 0x0011B3EC - force VBlank loop count = 1"
echo "  lsr r0, r0, #24 (0xE1A00C20) -> mov r0, #1 (0xE3A00001)"
