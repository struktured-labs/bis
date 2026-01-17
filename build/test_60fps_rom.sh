#!/bin/bash

# Test the 60fps patched ROM with Citra AppImage (confirmed working)

cd /home/struktured/projects/bis

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  60 FPS ROM Test (Using Citra - confirmed working)             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "This will test the patched ROM with Citra (you confirmed works)."
echo "Watch for:"
echo "  - Does it load without 'corrupted' error?"
echo "  - Does the game feel SMOOTHER than normal?"
echo ""
echo "30 FPS = choppy, stuttery"
echo "60 FPS = smooth, fluid"
echo ""
echo "The difference should be VERY obvious if it works."
echo ""
echo "Press Enter to start..."
read

/home/struktured/.local/bin/citra.AppImage build/Mario_Luigi_BIS_60fps_FINAL.3ds

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "What happened?"
echo ""
read -p "Did it load? (y/n): " LOADED
read -p "Any 'corrupted' errors? (y/n): " CORRUPTED
read -p "Did it crash? (y/n): " CRASHED

if [ "$LOADED" = "y" ] && [ "$CORRUPTED" = "n" ] && [ "$CRASHED" = "n" ]; then
    echo ""
    read -p "How did it FEEL compared to normal? (smoother/same/worse): " FEEL

    if [ "$FEEL" = "smoother" ]; then
        echo ""
        echo "✅ SUCCESS! The 60fps patches appear to be working!"
        echo ""
        echo "The game loaded clean and feels smoother = 60 FPS achieved!"
    elif [ "$FEEL" = "same" ]; then
        echo ""
        echo "⚠️  Patches load but no FPS change detected"
        echo ""
        echo "The ROM isn't corrupted, but FPS still feels like 30."
        echo "This means the patches aren't taking effect."
        echo "May need to investigate frame limiter in main code.bin"
    else
        echo ""
        echo "❓ Unclear - may need more testing"
    fi
else
    echo ""
    echo "❌ Patches broke the ROM"
    echo ""
    if [ "$CORRUPTED" = "y" ]; then
        echo "ROM shows as corrupted - patches damaged file structure"
    elif [ "$CRASHED" = "y" ]; then
        echo "Game crashed - patches broke game code"
    else
        echo "Game didn't load properly"
    fi
fi
