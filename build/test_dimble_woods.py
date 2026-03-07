"""Generate input script for Dimble Woods one-way path bug test.

Strategy:
- Frame 0: Load save state from slot 2 (Dimble Woods)
- Wait for state to load
- Walk LEFT for a while (should work)
- Walk RIGHT for a while (may be blocked at 60fps)
- Repeat pattern to capture before/after position changes

The one-way path bug: at 60fps, player can only go one direction in a
specific area near the carrot minigame in Dimble Woods (ekubon_15).
"""
HZ = 234  # HID polls per second

lines = ["# Dimble Woods one-way path test"]

# Load save state from slot 2 at frame 1
# Button 0x4000 = load state, cx = slot number
lines.append("1 1 4000 2.0 0.0")

# Wait 10 seconds for state to load
wait_end = 10 * HZ

# Phase 1: Walk LEFT for 10 seconds
left_start = wait_end
left_end = left_start + 10 * HZ
lines.append("%d %d 000 -1.0 0.0" % (left_start, left_end - left_start))

# Phase 2: Walk RIGHT for 10 seconds
right_start = left_end + 1 * HZ  # 1 sec pause
right_end = right_start + 10 * HZ
lines.append("%d %d 000 1.0 0.0" % (right_start, right_end - right_start))

# Phase 3: Walk UP for 10 seconds
up_start = right_end + 1 * HZ
up_end = up_start + 10 * HZ
lines.append("%d %d 000 0.0 1.0" % (up_start, up_end - up_start))

# Phase 4: Walk DOWN for 10 seconds
down_start = up_end + 1 * HZ
down_end = down_start + 10 * HZ
lines.append("%d %d 000 0.0 -1.0" % (down_start, down_end - down_start))

# Phase 5: Repeat LEFT-RIGHT cycle 3 more times
t = down_end + 1 * HZ
for cycle in range(3):
    # LEFT 8 sec
    lines.append("%d %d 000 -1.0 0.0" % (t, 8 * HZ))
    t += 9 * HZ
    # RIGHT 8 sec
    lines.append("%d %d 000 1.0 0.0" % (t, 8 * HZ))
    t += 9 * HZ

# Total ~3 minutes
total_frames = t
total_secs = total_frames / HZ

with open("input_script.txt", "w") as f:
    f.write("\n".join(lines) + "\n")

print("Generated %d lines, ~%.0f seconds" % (len(lines), total_secs))
print("Strategy: load state -> L/R/U/D exploration -> 3x L/R cycles")
