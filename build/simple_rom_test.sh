#!/bin/bash

cd /home/struktured/projects/bis

echo "=== Simple ROM Test ==="
echo ""
echo "This will launch both ROMs for 10 seconds each"
echo "Watch to see if either crashes or shows 'corrupted' message"
echo ""

echo "TEST 1: Original ROM"
echo "---"
timeout 10 /home/struktured/.local/bin/lime3ds.AppImage \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds" \
    2>&1 | grep -E "Error|corrupted|crash|failed" || echo "No errors detected"

pkill -9 lime3ds 2>/dev/null
sleep 2

echo ""
echo "TEST 2: Patched ROM"
echo "---"
timeout 10 /home/struktured/.local/bin/lime3ds.AppImage \
    build/Mario_Luigi_BIS_60fps_FINAL.3ds \
    2>&1 | grep -E "Error|corrupted|crash|failed" || echo "No errors detected"

pkill -9 lime3ds 2>/dev/null

echo ""
echo "Done! Did you see any differences?"
