#!/bin/bash

# Rebuild ROM v3 - Better approach using existing encrypted partition
# Just update exefs inside the already-built partition0_patched.cxi

set -e

cd /home/struktured/projects/bis

# Use local tools
export PATH="$PWD/tools:$PATH"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ROM Rebuild v3 - Update exefs in encrypted partition        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
if [ ! -f build/extracted/exefs_dir/code_patched.bin ]; then
    echo "ERROR: code_patched.bin not found"
    exit 1
fi

if [ ! -f build/extracted/partition0_patched.cxi ]; then
    echo "ERROR: partition0_patched.cxi not found (CRO patches)"
    exit 1
fi

WORK_DIR="build/v3_rom"
mkdir -p "$WORK_DIR"

echo "Step 1: Extract exefs from existing patched CXI"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Extract exefs from the CRO-patched partition
3dstool -xvtf cxi build/extracted/partition0_patched.cxi \
    --exefs ${WORK_DIR}/exefs_from_patched.bin \
    --header ${WORK_DIR}/header_temp.bin

echo "  ✓ Extracted exefs from CRO-patched partition"
echo ""

echo "Step 2: Extract exefs contents and replace code.bin"
echo "─────────────────────────────────────────────────────────────"
echo ""

mkdir -p ${WORK_DIR}/exefs_dir
3dstool -xvtf exefs ${WORK_DIR}/exefs_from_patched.bin \
    --exefs-dir ${WORK_DIR}/exefs_dir \
    --header ${WORK_DIR}/exefs_header.bin

# Replace code.bin with our patched version
cp build/extracted/exefs_dir/code_patched.bin ${WORK_DIR}/exefs_dir/code.bin

echo "  ✓ Replaced code.bin with frame-limiter-patched version"
echo ""

echo "Step 3: Rebuild exefs with both patches"
echo "─────────────────────────────────────────────────────────────"
echo ""

3dstool -cvtf exefs ${WORK_DIR}/exefs_final.bin \
    --exefs-dir ${WORK_DIR}/exefs_dir \
    --header ${WORK_DIR}/exefs_header.bin

echo "  ✓ Created exefs with CRO + frame limiter patches"
echo ""

echo "Step 4: Use ctrtool to rebuild CXI (preserves encryption)"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Extract all parts from partition0_patched.cxi
3dstool -xvtf cxi build/extracted/partition0_patched.cxi \
    --header ${WORK_DIR}/cxi_header.bin \
    --exh ${WORK_DIR}/exheader.bin \
    --logo ${WORK_DIR}/logo.bin \
    --plain ${WORK_DIR}/plain.bin \
    --romfs ${WORK_DIR}/romfs.bin

# Now rebuild with ctrtool (if available) or use the original method
# Actually, let's try a different approach: just use the FINAL.3ds method

echo "  Extracting components completed"
echo ""

echo "Step 5: Build using same method as FINAL ROM"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Copy FINAL ROM and extract it
cp build/Mario_Luigi_BIS_60fps_FINAL.3ds ${WORK_DIR}/base.3ds

# Extract just to get the proper structure
3dstool -xvtf 3ds ${WORK_DIR}/base.3ds \
    --header ${WORK_DIR}/ncsd_header_final.bin \
    -0 ${WORK_DIR}/p0_final.cxi \
    -1 ${WORK_DIR}/p1_final.cfa \
    -6 ${WORK_DIR}/p6_final.cfa \
    -7 ${WORK_DIR}/p7_final.cfa

# Now update just the exefs in p0_final.cxi
mkdir -p ${WORK_DIR}/p0_extract
3dstool -xvtf cxi ${WORK_DIR}/p0_final.cxi \
    --header ${WORK_DIR}/p0_extract/header.bin \
    --exh ${WORK_DIR}/p0_extract/exheader.bin \
    --exefs ${WORK_DIR}/p0_extract/exefs.bin \
    --logo ${WORK_DIR}/p0_extract/logo.bin \
    --plain ${WORK_DIR}/p0_extract/plain.bin \
    --romfs ${WORK_DIR}/p0_extract/romfs.bin

# Replace exefs with our new one
cp ${WORK_DIR}/exefs_final.bin ${WORK_DIR}/p0_extract/exefs.bin

# Rebuild partition 0
3dstool -cvtf cxi ${WORK_DIR}/p0_v3.cxi \
    --header ${WORK_DIR}/p0_extract/header.bin \
    --exh ${WORK_DIR}/p0_extract/exheader.bin \
    --exefs ${WORK_DIR}/p0_extract/exefs.bin \
    --logo ${WORK_DIR}/p0_extract/logo.bin \
    --plain ${WORK_DIR}/p0_extract/plain.bin \
    --romfs ${WORK_DIR}/p0_extract/romfs.bin

echo "  ✓ Rebuilt partition 0 with all patches"
echo ""

echo "Step 6: Build final v3 ROM"
echo "─────────────────────────────────────────────────────────────"
echo ""

3dstool -cvtf 3ds build/Mario_Luigi_BIS_60fps_v3.3ds \
    --header ${WORK_DIR}/ncsd_header_final.bin \
    -0 ${WORK_DIR}/p0_v3.cxi \
    -1 ${WORK_DIR}/p1_final.cfa \
    -6 ${WORK_DIR}/p6_final.cfa \
    -7 ${WORK_DIR}/p7_final.cfa

if [ $? -eq 0 ]; then
    echo "  ✓ Created Mario_Luigi_BIS_60fps_v3.3ds"
else
    echo "  ✗ Failed to create final ROM"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ROM BUILD COMPLETE - v3                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ls -lh build/Mario_Luigi_BIS_60fps_v3.3ds

echo ""
echo "Patches applied:"
echo "  ✓ CRO patches (12 modules @ offset 0x76) - from FINAL"
echo "  ✓ Frame limiter patches (9x float 30.0 → 60.0 in code.bin) - NEW"
echo ""
echo "Next step: Test the v3 ROM"
echo "  citra.AppImage build/Mario_Luigi_BIS_60fps_v3.3ds"
echo ""
