#!/bin/bash

# Test 3 emulators with the BIS ROM to see which ones work

cd /home/struktured/projects/bis

ROM="Mario & Luigi - Bowser's Inside Story + Bowser Jr.'s Journey (USA).3ds"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Emulator Comparison Test                                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Testing which emulator can load BIS without hanging..."
echo "ROM: $ROM"
echo ""
echo "Press Ctrl+C if any emulator hangs for >30 seconds"
echo ""

# Test 1: Original Lime3DS AppImage
echo "════════════════════════════════════════════════════════════════"
echo "  TEST 1: Lime3DS AppImage (original, unmodified)"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ -f /home/struktured/.local/bin/lime3ds.AppImage ]; then
    echo "Starting Lime3DS..."
    echo "Watch for: Does it load past the title screen?"
    echo ""

    timeout 30 env DISPLAY=:0 \
        MESA_GL_VERSION_OVERRIDE=4.6 \
        __GLX_VENDOR_LIBRARY_NAME=nvidia \
        /home/struktured/.local/bin/lime3ds.AppImage "$ROM" 2>&1 | head -10 &

    EMU_PID=$!
    sleep 30

    if kill -0 $EMU_PID 2>/dev/null; then
        echo "Still running after 30s - check window manually"
        read -p "Did it load successfully? (y/n): " LIME_RESULT
        pkill -9 lime3ds || true
    else
        echo "Exited/crashed within 30s"
        LIME_RESULT="n"
    fi
else
    echo "❌ Lime3DS not found at /home/struktured/.local/bin/lime3ds.AppImage"
    LIME_RESULT="n"
fi

echo ""
sleep 2

# Test 2: Citra AppImage
echo "════════════════════════════════════════════════════════════════"
echo "  TEST 2: Citra AppImage"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ -f /home/struktured/.local/bin/citra.AppImage ]; then
    echo "Starting Citra..."
    echo "Watch for: Does it load past the title screen?"
    echo ""

    timeout 30 env DISPLAY=:0 \
        MESA_GL_VERSION_OVERRIDE=4.6 \
        __GLX_VENDOR_LIBRARY_NAME=nvidia \
        /home/struktured/.local/bin/citra.AppImage "$ROM" 2>&1 | head -10 &

    EMU_PID=$!
    sleep 30

    if kill -0 $EMU_PID 2>/dev/null; then
        echo "Still running after 30s - check window manually"
        read -p "Did it load successfully? (y/n): " CITRA_RESULT
        pkill -9 citra || true
    else
        echo "Exited/crashed within 30s"
        CITRA_RESULT="n"
    fi
else
    echo "❌ Citra not found at /home/struktured/.local/bin/citra.AppImage"
    CITRA_RESULT="n"
fi

echo ""
sleep 2

# Test 3: Custom Build
echo "════════════════════════════════════════════════════════════════"
echo "  TEST 3: Custom Build (with FPS logging)"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ -f build/emulator/Lime3DS/build/bin/Release/azahar ]; then
    echo "Starting Custom Azahar..."
    echo "Watch for: Does it load past the title screen?"
    echo ""

    timeout 30 env DISPLAY=:0 \
        MESA_GL_VERSION_OVERRIDE=4.6 \
        __GLX_VENDOR_LIBRARY_NAME=nvidia \
        build/emulator/Lime3DS/build/bin/Release/azahar "$ROM" 2>&1 | head -10 &

    EMU_PID=$!
    sleep 30

    if kill -0 $EMU_PID 2>/dev/null; then
        echo "Still running after 30s - check window manually"
        read -p "Did it load successfully? (y/n): " CUSTOM_RESULT
        pkill -9 azahar || true
    else
        echo "Exited/crashed within 30s"
        CUSTOM_RESULT="n"
    fi
else
    echo "❌ Custom build not found"
    CUSTOM_RESULT="n"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Results Summary                                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Lime3DS AppImage:  $LIME_RESULT"
echo "Citra AppImage:    $CITRA_RESULT"
echo "Custom Build:      $CUSTOM_RESULT"
echo ""

if [ "$LIME_RESULT" = "y" ] || [ "$CITRA_RESULT" = "y" ]; then
    echo "✅ At least one original emulator works!"
    echo ""
    if [ "$CUSTOM_RESULT" = "n" ]; then
        echo "⚠️  Custom build is broken - use working emulator instead"
    fi
else
    echo "❌ No emulators work with this ROM"
    echo ""
    echo "Possible causes:"
    echo "  - ROM incompatibility"
    echo "  - ROM file corrupted"
    echo "  - Missing system files/keys"
fi
