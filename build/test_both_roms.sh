#!/bin/bash

# Compare original vs patched ROM with Citra (confirmed working)

cd /home/struktured/projects/bis

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Side-by-Side Comparison: Original vs Patched                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "This will launch BOTH ROMs so you can compare."
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  ORIGINAL ROM (baseline - should be ~30 FPS)"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Play for a bit, notice how smooth/choppy it feels."
echo "This is the baseline to compare against."
echo ""
echo "Press Enter to launch..."
read

/home/struktured/.local/bin/citra.AppImage \
    "Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  PATCHED ROM (should be ~60 FPS if patches work)"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Now compare - does this feel SMOOTHER?"
echo ""
echo "Press Enter to launch..."
read

/home/struktured/.local/bin/citra.AppImage \
    build/Mario_Luigi_BIS_60fps_FINAL.3ds

echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
read -p "Was the patched ROM noticeably SMOOTHER? (y/n/same): " SMOOTHER
read -p "Did patched show any errors/corruption? (y/n): " ERRORS

echo ""
if [ "$SMOOTHER" = "y" ] && [ "$ERRORS" = "n" ]; then
    echo "✅ SUCCESS! Patches appear to be working - 60 FPS achieved!"
elif [ "$SMOOTHER" = "same" ] && [ "$ERRORS" = "n" ]; then
    echo "⚠️  Patches load but no visible FPS improvement"
    echo "    Still running at ~30 FPS, patches not taking effect"
elif [ "$ERRORS" = "y" ]; then
    echo "❌ Patches broke the ROM (corruption/errors)"
else
    echo "❓ Unclear results"
fi
