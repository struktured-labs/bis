#!/bin/bash

# Rebuild ROM with ALL patches:
# 1. CRO patches (already in romfs_patched.bin)
# 2. code.bin patches (newly created)

set -e

cd /home/struktured/projects/bis

# Use local tools
export PATH="$PWD/tools:$PATH"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ROM Rebuild v2 - CRO + Frame Limiter Patches                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
if [ ! -f build/extracted/exefs_dir/code_patched.bin ]; then
    echo "ERROR: code_patched.bin not found"
    echo "Run: uv run build/patch_frame_limiter.py first"
    exit 1
fi

if [ ! -f build/extracted/romfs_patched.bin ]; then
    echo "ERROR: romfs_patched.bin not found (CRO patches missing)"
    echo "CRO patches should have been applied earlier"
    exit 1
fi

# Create output directory
mkdir -p build/v2_rom
WORK_DIR="build/v2_rom"

echo "Step 1: Rebuild exefs with patched code.bin"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Copy patched code.bin to exefs directory
cp build/extracted/exefs_dir/code_patched.bin build/extracted/exefs_dir/code.bin
echo "  ✓ Installed patched code.bin"

# Rebuild exefs.bin using 3dstool
cd build/extracted

# Extract header from original exefs if not already done
if [ ! -f exefs_header.bin ]; then
    echo "  Extracting exefs header from original..."
    3dstool -xvtf exefs exefs.bin --header exefs_header.bin
fi

# Rebuild exefs with patched code
3dstool -cvtf exefs exefs_v2.bin \
    --exefs-dir exefs_dir \
    --header exefs_header.bin

if [ $? -eq 0 ]; then
    echo "  ✓ Created exefs_v2.bin with patched code"
else
    echo "  ✗ Failed to create exefs_v2.bin"
    exit 1
fi

cd ../..
echo ""

echo "Step 2: Rebuild partition0.cxi with patched exefs + romfs"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Extract exheader from original CXI if not already done
if [ ! -f build/extracted/exheader.bin ]; then
    echo "  Extracting exheader from original partition0.cxi..."
    3dstool -xvtf cxi build/extracted/partition0.cxi --exh build/extracted/exheader.bin
fi

# Check for exheader
if [ -f build/extracted/exheader.bin ]; then
    EXHEADER_ARG="--exh build/extracted/exheader.bin"
    echo "  ✓ Using exheader.bin"
else
    echo "  ⚠ exheader.bin not found, building without it"
    EXHEADER_ARG=""
fi

# Rebuild CXI
3dstool -cvtf cxi ${WORK_DIR}/partition0_v2.cxi \
    --header build/extracted/cxi_header.bin \
    $EXHEADER_ARG \
    --exefs build/extracted/exefs_v2.bin \
    --romfs build/extracted/romfs_patched.bin \
    --logo build/extracted/logo.bin \
    --plain build/extracted/plain.bin

if [ $? -eq 0 ]; then
    echo "  ✓ Created partition0_v2.cxi"
else
    echo "  ✗ Failed to create partition0_v2.cxi"
    exit 1
fi

echo ""

echo "Step 3: Rebuild final .3ds ROM"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Copy partition0_v2.cxi to use as partition0
cp ${WORK_DIR}/partition0_v2.cxi ${WORK_DIR}/partition0.cxi

# Build final ROM with all partitions
3dstool -cvtf 3ds build/Mario_Luigi_BIS_60fps_v2.3ds \
    --header build/extracted/ncsd_header.bin \
    -0 ${WORK_DIR}/partition0.cxi \
    -1 build/extracted/partition1.cfa \
    -6 build/extracted/partition6.cfa \
    -7 build/extracted/partition7.cfa

if [ $? -eq 0 ]; then
    echo "  ✓ Created Mario_Luigi_BIS_60fps_v2.3ds"
else
    echo "  ✗ Failed to create final ROM"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ROM BUILD COMPLETE                                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ls -lh build/Mario_Luigi_BIS_60fps_v2.3ds

echo ""
echo "Patches applied:"
echo "  ✓ CRO patches (12 modules @ offset 0x76)"
echo "  ✓ Frame limiter patches (9x float 30.0 → 60.0 in code.bin)"
echo ""
echo "Next step: Test with automated verification"
echo "  ./build/automated_fps_test.sh"
echo ""
