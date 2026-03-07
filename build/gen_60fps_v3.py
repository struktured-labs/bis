"""Generate comprehensive 60fps IPS patch v3 for v1.2 update.

Strategy: Patch ALL writers and ALL critical readers of the FPS byte (+0x3D).

Writers (force write 0 or NOP):
  1. 0x17c260: strb r0,[r4,#0x3d]  -> strb r2,[r4,#0x3d]  (r2=0 from 0x17c25c)
  2. 0x000828dc: strbne r0,[r4,#0x3d] -> NOP (conditional writer from global state)
  3. 0x0014b44c: strb r0,[r4,#0x3d] (r0=0xFF init) -> strb r5,[r4,#0x3d] (r5=0)

Readers (force return 0):
  4. 0x03e8e8: ldrb r1,[r4,#0x3d] -> mov r1,#0  (main frame loop - existing patch)
  5. 0x180a5c: ldrb r0,[r4,#0x3d] -> mov r0,#0  (init time - existing patch)
  6. 0x263250: ldrb r0,[r4,#0x3d] -> mov r0,#0  (FPS wrapper return value)
  7. 0x012b54: ldrb r2,[r4,#0x3d] -> mov r2,#0  (render flag setter 1)
  8. 0x012cb0: ldrb r2,[r4,#0x3d] -> mov r2,#0  (render flag setter 2)
  9. 0x017fa08: ldrb r1,[r4,#0x3d]-> mov r1,#0  (frame timing render flags) - but uses iVar7 not r4!
  10. 0x26c114: ldrb r1,[r4,#0x3d] -> mov r1,#0  (render flag setter 3)

Note: 0x0010f2c4 reads +0x3d from param_3, not the FPS struct - different struct type
      0x00061c18, 0x000c1550 copy +0x3d to locals - from param_4, also different struct
      0x00261f50 uses +0x3d as bit index - different struct entirely
      0x00051950 reads uint3 at +0x3d - different struct

We focus on the ones that clearly operate on the FPS struct (base in r4 with
surrounding accesses to +0x3c, +0x3e, +0x3f etc matching the FPS struct layout).
"""
import struct

def ips_record(offset, data):
    """Create an IPS record: 3-byte BE offset + 2-byte BE size + data."""
    return struct.pack('>I', offset)[1:4] + struct.pack('>H', len(data)) + data


# ARM instructions
MOV_R0_0 = bytes.fromhex("0000A0E3")  # E3A00000 MOV R0,#0
MOV_R1_0 = bytes.fromhex("0010A0E3")  # E3A01000 MOV R1,#0
MOV_R2_0 = bytes.fromhex("0020A0E3")  # E3A02000 MOV R2,#0
NOP = bytes.fromhex("0000A0E1")       # E1A00000 MOV R0,R0 (NOP)

records = []

# === WRITERS: prevent non-zero writes ===

# 1. 0x17c260: strb r0,[r4,#0x3d] in FPS setter
#    r2 is set to 0 at 0x17c25c (mov r2,#0), so change strb r0 to strb r2
#    strb r2,[r4,#0x3d] = E5C4203D
records.append(("FPS setter writer", 0x17c260, bytes.fromhex("3D20C4E5")))

# 2. 0x000828dc: strbne r0,[r4,#0x3d] - conditional writer from global state
#    NOP it out
records.append(("Conditional FPS writer", 0x000828dc, NOP))

# 3. 0x0014b44c: strb r0,[r4,#0x3d] where r0=0xFF (initialization)
#    Change to strb r5,[r4,#0x3d] where r5=0
#    strb r5,[r4,#0x3d] = E5C4503D
records.append(("Init FPS writer (0xFF)", 0x0014b44c, bytes.fromhex("3D50C4E5")))

# === READERS: force return 0 ===

# 4. 0x03e8e8: main frame loop (existing v1 patch)
records.append(("Main frame loop reader", 0x03e8e8, MOV_R1_0))

# 5. 0x180a5c: init-time reader (existing v1 patch)
records.append(("Init-time reader", 0x180a5c, MOV_R0_0))

# 6. 0x263250: FPS wrapper return - ldrb r0,[r4,#0x3d] -> mov r0,#0
records.append(("FPS wrapper reader", 0x263250, MOV_R0_0))

# 7. 0x012b54: render flag setter 1 - ldrb r2,[r4,#0x3d] -> mov r2,#0
records.append(("Render flag reader 1", 0x012b54, MOV_R2_0))

# 8. 0x012cb0: render flag setter 2 - ldrb r2,[r4,#0x3d] -> mov r2,#0
records.append(("Render flag reader 2", 0x012cb0, MOV_R2_0))

# 9. 0x26c114: render flag setter 3 - ldrb r1,[r4,#0x3d] -> mov r1,#0
records.append(("Render flag reader 3", 0x26c114, MOV_R1_0))

# Build IPS
ips = b"PATCH"
for name, offset, data in sorted(records, key=lambda x: x[1]):
    print("  0x%06x: %s (%d bytes)" % (offset, name, len(data)))
    ips += ips_record(offset, data)
ips += b"EOF"

out_path = "patches/60fps_v3_update_v1.2.ips"
with open(out_path, "wb") as f:
    f.write(ips)

print("\nGenerated %s (%d bytes, %d patch sites)" % (out_path, len(ips), len(records)))

# Verify
print("\nVerification:")
with open(out_path, "rb") as f:
    data = f.read()
assert data[:5] == b"PATCH"
assert data[-3:] == b"EOF"
print("  Header: OK")
print("  Footer: OK")
print("  Total size: %d bytes" % len(data))
