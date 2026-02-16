#!/usr/bin/env python3
"""Test individual patches to confirm they still work (not hang)."""
import struct
import subprocess
import os
import time

os.chdir("/home/struktured/projects/bis")
os.environ["PATH"] = os.path.join(os.getcwd(), "tools") + ":" + os.environ["PATH"]

BASE_ADDR = 0x00100000
INPUT = "tmp/decompressed/code_decompressed.bin"
EMULATOR = "build/emulator/Lime3DS/build/bin/Release/azahar"

PATCHES = {
    "A": (0x0012E1EC, 0x0A000005, 0xE1A00000, "NOP beq"),
    "B": (0x0011B3EC, 0xE1A00C20, 0xE3A00001, "loop=1"),
    "C": (0x001228D4, 0xE3A00002, 0xE3A00001, "state=1"),
}

def build_rom(patch_name):
    vaddr, old_val, new_val, desc = PATCHES[patch_name]
    with open(INPUT, "rb") as f:
        data = bytearray(f.read())
    off = vaddr - BASE_ADDR
    data[off:off+4] = struct.pack('<I', new_val)

    code_path = f"tmp/single_{patch_name}_code.bin"
    work = f"tmp/single_{patch_name}"
    os.makedirs(work, exist_ok=True)
    with open(code_path, "wb") as f:
        f.write(data)

    subprocess.run(["3dstool", "-zvf", code_path, "--compress-type", "blz",
                     "--compress-out", f"{work}/code.bin"], check=True, capture_output=True)

    exefs_dir = f"{work}/exefs_dir"
    os.makedirs(exefs_dir, exist_ok=True)
    subprocess.run(f"cp build/v3_extract/exefs_dir/* {exefs_dir}/", shell=True, check=True, capture_output=True)
    subprocess.run(f"cp {work}/code.bin {exefs_dir}/code.bin", shell=True, check=True, capture_output=True)

    subprocess.run(["3dstool", "-cvtf", "exefs", f"{work}/exefs.bin",
                     "--exefs-dir", exefs_dir, "--header", "build/v3_extract/exefs_header.bin"],
                    check=True, capture_output=True)

    subprocess.run(["3dstool", "-cvtf", "cxi", f"{work}/partition0.cxi",
                     "--header", "build/extracted/cxi_header.bin",
                     "--exh", "build/extracted/exheader.bin",
                     "--exefs", f"{work}/exefs.bin",
                     "--romfs", "build/extracted/romfs.bin",
                     "--logo", "build/extracted/logo.bin",
                     "--plain", "build/extracted/plain.bin"],
                    check=True, capture_output=True)

    rom = f"build/single_{patch_name}.3ds"
    subprocess.run(["3dstool", "-cvtf", "3ds", rom,
                     "--header", "build/extracted/ncsd_header.bin",
                     "-0", f"{work}/partition0.cxi",
                     "-1", "build/extracted/partition1.cfa",
                     "-6", "build/extracted/partition6.cfa",
                     "-7", "build/extracted/partition7.cfa"],
                    check=True, capture_output=True)
    return rom

def test_rom(rom_path, name, timeout=90):
    csv = "tmp/citra_fps.csv"
    if os.path.exists(csv):
        os.remove(csv)

    env = os.environ.copy()
    env["DISPLAY"] = ":0"
    proc = subprocess.Popen([EMULATOR, rom_path], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(5)
        if proc.poll() is not None:
            return f"CRASH (exit {proc.returncode})"
        try:
            with open(csv) as f:
                lines = f.readlines()
            if len(lines) > 6:
                fps = [float(l.split(',')[1]) for l in lines[5:] if float(l.split(',')[1]) > 0]
                if len(fps) >= 3:
                    avg = sum(fps) / len(fps)
                    proc.terminate()
                    try: proc.wait(5)
                    except: proc.kill()
                    return f"{avg:.1f} FPS"
        except:
            pass
        print(f"  {int(time.time()-start)}s...")

    proc.kill()
    return "HANG"

subprocess.run(["pkill", "-9", "-f", "azahar"], capture_output=True)
time.sleep(2)

results = {}
for name in ["A", "B", "C"]:
    desc = PATCHES[name][3]
    print(f"\n--- Testing {name} ({desc}) ---")
    print("  Building...")
    rom = build_rom(name)
    print(f"  Testing {rom}...")
    result = test_rom(rom, name)
    results[name] = result
    print(f"  Result: {result}")
    subprocess.run(["pkill", "-9", "-f", "azahar"], capture_output=True)
    time.sleep(2)

print("\n=== RESULTS ===")
for name, result in results.items():
    desc = PATCHES[name][3]
    print(f"  {name} ({desc}): {result}")
