#!/bin/bash
# Test all patches and generate report

cd /home/struktured/projects/bis

echo "Testing all patches..."
echo "======================"

for patch in patches/60fps_v*.ips; do
    echo ""
    echo "Testing: $patch"
    ./test_fps.sh "$patch" 12
done

echo ""
echo "======================"
echo "Screenshots saved in tmp/"
ls -la tmp/*.png 2>/dev/null | tail -20
