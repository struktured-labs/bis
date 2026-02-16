#!/usr/bin/env python3
"""Test all patch combinations to find which cause hangs vs 60fps."""
import struct
import subprocess
import os
import sys
import time
import signal

BASE_ADDR = 0x00100000
INPUT = "tmp/decompressed/code_decompressed.bin"
EMULATOR = "build/emulator/Lime3DS/build/bin/Release/azahar"
ORIGINAL_ROM = "bis.3DS"

ALL_PATCHES = {
    "A_nop_beq": {
        "vaddr": 0x0012E1EC,
        "old": 0x0A000005,
        "new": 0xE1A00000,
        "desc": "NOP beq -> 60fps skip-wait path",
    },
    "B_loop_count_1": {
        "vaddr": 0x0011B3EC,
        "old": 0xE1A00C20,
        "new": 0xE3A00001,
        "desc": "Force VBlank loop count to 1",
    },
    "C_state_flag_1": {
        "vaddr": 0x001228D4,
        "old": 0xE3A00002,
        "new": 0xE3A00001,
        "desc": "State flag 1 instead of 2",
    },
}

# Test these combinations (skip single patches - already tested individually)
COMBOS = [
    ["A_nop_beq", "B_loop_count_1"],           # A+B
    ["A_nop_beq", "C_state_flag_1"],           # A+C
    ["B_loop_count_1", "C_state_flag_1"],       # B+C
    ["A_nop_beq", "B_loop_count_1", "C_state_flag_1"],  # A+B+C (known to hang)
]

def build_rom(patches_to_apply, combo_name):
    """Build a ROM with specified patches."""
    with open(INPUT, "rb") as f:
        data = bytearray(f.read())

    for name in patches_to_apply:
        p = ALL_PATCHES[name]
        off = p["vaddr"] - BASE_ADDR
        expected = struct.pack('<I', p["old"])
        actual = bytes(data[off:off+4])
        if actual != expected:
            print(f"  MISMATCH at {name}: expected {expected.hex()}, got {actual.hex()}")
            return None
        data[off:off+4] = struct.pack('<I', p["new"])

    # Save patched code
    patched_code = f"tmp/combo_{combo_name}_code.bin"
    with open(patched_code, "wb") as f:
        f.write(data)

    # Compress
    work = f"tmp/combo_{combo_name}"
    os.makedirs(work, exist_ok=True)
    subprocess.run([
        "3dstool", "-zvf", patched_code,
        "--compress-type", "blz",
        "--compress-out", f"{work}/code.bin"
    ], check=True, capture_output=True)

    # Build ExeFS
    exefs_dir = f"{work}/exefs_dir"
    os.makedirs(exefs_dir, exist_ok=True)
    subprocess.run(f"cp build/v3_extract/exefs_dir/* {exefs_dir}/", shell=True, check=True, capture_output=True)
    subprocess.run(f"cp {work}/code.bin {exefs_dir}/code.bin", shell=True, check=True, capture_output=True)

    subprocess.run([
        "3dstool", "-cvtf", "exefs", f"{work}/exefs.bin",
        "--exefs-dir", exefs_dir,
        "--header", "build/v3_extract/exefs_header.bin"
    ], check=True, capture_output=True)

    # Build CXI
    subprocess.run([
        "3dstool", "-cvtf", "cxi", f"{work}/partition0.cxi",
        "--header", "build/extracted/cxi_header.bin",
        "--exh", "build/extracted/exheader.bin",
        "--exefs", f"{work}/exefs.bin",
        "--romfs", "build/extracted/romfs.bin",
        "--logo", "build/extracted/logo.bin",
        "--plain", "build/extracted/plain.bin"
    ], check=True, capture_output=True)

    # Build 3DS
    rom_path = f"build/combo_{combo_name}.3ds"
    subprocess.run([
        "3dstool", "-cvtf", "3ds", rom_path,
        "--header", "build/extracted/ncsd_header.bin",
        "-0", f"{work}/partition0.cxi",
        "-1", "build/extracted/partition1.cfa",
        "-6", "build/extracted/partition6.cfa",
        "-7", "build/extracted/partition7.cfa"
    ], check=True, capture_output=True)

    return rom_path

def test_rom(rom_path, combo_name, timeout=80):
    """Run ROM and measure FPS. Returns avg FPS or None if hung."""
    csv_path = "tmp/citra_fps.csv"

    # Clean
    if os.path.exists(csv_path):
        os.remove(csv_path)

    env = os.environ.copy()
    env["DISPLAY"] = ":0"

    proc = subprocess.Popen(
        [EMULATOR, rom_path],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    start = time.time()
    last_lines = 0
    fps_data = []

    while time.time() - start < timeout:
        time.sleep(5)

        if proc.poll() is not None:
            print(f"  Process died (exit {proc.returncode})")
            return None

        try:
            with open(csv_path, 'r') as f:
                lines = f.readlines()
            num_lines = len(lines)
        except FileNotFoundError:
            num_lines = 0
            lines = []

        elapsed = int(time.time() - start)

        if num_lines > 5:
            # Parse FPS values
            fps_values = []
            for line in lines[5:]:  # Skip header + first 4 samples
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    try:
                        fps = float(parts[1])
                        if fps > 0:
                            fps_values.append(fps)
                    except ValueError:
                        pass

            if len(fps_values) >= 3:
                avg = sum(fps_values) / len(fps_values)
                print(f"  {elapsed}s: {num_lines} lines, avg={avg:.1f} FPS")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return avg
        else:
            print(f"  {elapsed}s: {num_lines} lines (loading...)")

    # Timeout - game hung
    print(f"  TIMEOUT after {timeout}s")
    proc.kill()
    return None

def main():
    os.chdir("/home/struktured/projects/bis")
    os.environ["PATH"] = os.path.join(os.getcwd(), "tools") + ":" + os.environ["PATH"]

    # Kill any running emulator
    subprocess.run(["pkill", "-9", "-f", "azahar"], capture_output=True)
    time.sleep(2)

    print("=== Patch Combination Testing ===\n")

    results = {}

    for combo in COMBOS:
        combo_name = "+".join(c.split("_")[0] for c in combo)
        patches_desc = ", ".join(ALL_PATCHES[c]["desc"] for c in combo)

        print(f"\n--- Testing {combo_name}: {patches_desc} ---")

        # Build
        print("  Building ROM...")
        rom_path = build_rom(combo, combo_name)
        if not rom_path:
            results[combo_name] = "BUILD FAIL"
            continue

        # Test
        print(f"  Testing {rom_path}...")
        avg_fps = test_rom(rom_path, combo_name)

        if avg_fps is None:
            results[combo_name] = "HANG/CRASH"
        elif avg_fps >= 55:
            results[combo_name] = f"60fps! ({avg_fps:.1f})"
        elif avg_fps >= 25:
            results[combo_name] = f"30fps ({avg_fps:.1f})"
        else:
            results[combo_name] = f"slow ({avg_fps:.1f})"

        # Cleanup
        subprocess.run(["pkill", "-9", "-f", "azahar"], capture_output=True)
        time.sleep(2)

    print("\n\n=== RESULTS ===")
    # Include known single-patch results
    print("A only (NOP beq):       30fps (known)")
    print("B only (loop count=1):  30fps (known)")
    print("C only (state flag=1):  NOT TESTED")
    for combo_name, result in results.items():
        print(f"{combo_name}: {result}")

if __name__ == "__main__":
    main()
