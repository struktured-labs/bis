"""Patch HugeBattle.cro to force 60fps in giant battles.

The CRO has its own STRB/LDRB instructions that read/write the FPS byte (+0x3D).
Our code.bin IPS patch can't reach these. We create a modified CRO for romfs overlay.

Strategy: NOP the only confirmed non-zero writer to +0x3D.
File offset 0x0efc60: mov r1,#1; strb r1,[r0,#0x3d] -> NOP the strb

We DON'T patch readers because some +0x3D accesses are on different structs
(state machines with values 0-13). Instead, we rely on the v3 code.bin patch
to keep the FPS byte at 0 in memory, so CRO readers naturally see 0.

But the CRO's own writer at 0x0efc60 SETS it to 1, which is the problem.
"""
import struct
import shutil

src = "tmp/romfs_extract/RO/HugeBattle.cro"
dst = "tmp/HugeBattle_patched.cro"

shutil.copy2(src, dst)

with open(dst, "r+b") as f:
    data = bytearray(f.read())

    NOP = bytes.fromhex("0000A0E1")  # MOV R0,R0 (NOP)

    patches = []

    # 1. NOP the strb r1,[r0,#0x3d] at file offset 0x0efc60
    #    This is the only confirmed write of 1 (30fps) to the FPS byte
    off = 0x0efc60
    orig = data[off:off+4]
    expected = bytes.fromhex("3D10C0E5")  # strb r1,[r0,#0x3d]
    assert orig == expected, "Unexpected bytes at 0x%x: %s (expected %s)" % (off, orig.hex(), expected.hex())
    data[off:off+4] = NOP
    patches.append(("NOP strb r1,[r0,#0x3d] (writes 1=30fps)", off))

    # 2. Also NOP the strb at 0x0a90a8 (strb r4,[r0,#0x3d])
    #    This is another runtime write whose value we're not sure about
    off2 = 0x0a90a8
    orig2 = data[off2:off2+4]
    expected2 = bytes.fromhex("3D40C0E5")  # strb r4,[r0,#0x3d]
    assert orig2 == expected2, "Unexpected bytes at 0x%x: %s" % (off2, orig2.hex())
    data[off2:off2+4] = NOP
    patches.append(("NOP strb r4,[r0,#0x3d] (unknown value writer)", off2))

    f.seek(0)
    f.write(data)

print("Patched HugeBattle.cro:")
for desc, off in patches:
    print("  0x%06x: %s" % (off, desc))
print("Output: %s" % dst)

# Verify
with open(dst, "rb") as f:
    data = f.read()
    for desc, off in patches:
        assert data[off:off+4] == NOP, "Patch failed at 0x%x" % off
print("Verification: OK")
