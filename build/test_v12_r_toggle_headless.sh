#!/bin/bash
# usage: run_test.sh <ips> <label>   -- isolated headless R-toggle test
set -u
B=/home/struktured/projects/bis; T=$B/tmp/issue1; IPS=$1; L=$2
H=$T/home; mkdir -p $H/.config $H/.local/share/azahar-emu $T/out/$L
if [ ! -d $H/.config/azahar-emu ]; then
  cp -r ~/.config/azahar-emu $H/.config/
  for d in nand sdmc sysdata; do cp -r ~/.local/share/azahar-emu/$d $H/.local/share/azahar-emu/; done
fi
C=$H/.config/azahar-emu/qt-config.ini
sed -i -e 's/^graphics_api=.*/graphics_api=1/' -e 's/^graphics_api\\default=.*/graphics_api\\default=false/' -e 's/^volume=.*/volume=0/' -e 's/^volume\\default=.*/volume\\default=false/' $C
M=$H/.local/share/azahar-emu/load/mods/00040000001D1400/exefs; rm -rf $H/.local/share/azahar-emu/load; mkdir -p $M
[ "$IPS" != none ] && cp $IPS $M/code.ips
cd $T/out/$L; rm -rf tmp; mkdir tmp; cp $T/input_script.txt .
rm -f $B/tmp/citra_fps.csv
DISP=:117
Xvfb $DISP -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 & XP=$!; sleep 2
env -u WAYLAND_DISPLAY HOME=$H DISPLAY=$DISP LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe QT_QPA_PLATFORM=xcb SDL_AUDIODRIVER=dummy \
  $B/build/emulator/Lime3DS/build/bin/Release/bis_emu $B/bis.3DS >emu.log 2>&1 & EP=$!
for t in ${SHOTS:-20 40 55 70 85 100 115}; do
  while [ $SECONDS -lt $t ]; do sleep 1; done
  DISPLAY=$DISP xwd -root -silent | convert xwd:- shot_${t}s.png
done
while [ $SECONDS -lt ${DUR:-125} ]; do sleep 1; done
kill $EP; sleep 2; kill -9 $EP 2>/dev/null; kill $XP
cp $B/tmp/citra_fps.csv fps.csv
echo done $L
