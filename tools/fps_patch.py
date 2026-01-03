#!/usr/bin/env python3
"""
Generate CTRPF AR cheat codes for Mario & Luigi: Bowser's Inside Story + Bowser Jr.'s Journey
with configurable FPS limits.

Game Title IDs:
- USA: 00040000001D1400
- EUR: 00040000001D1500

Based on codes by @Shay from the 60FPS-AR-CHEATS-3DS project.
"""

import argparse
from pathlib import Path
from typing import Literal

# Game version
GAME_VERSION = "v1.2"

# FPS presets - value written to FPS control registers
# 0x00 = 60 FPS, 0x01 = 30 FPS
FPS_VALUES = {
    60: 0x00,
    30: 0x01,
}


def generate_fps_cheat(
    target_fps: int = 60,
    fallback_fps: int = 30,
    fallback_button: str = "R",
    include_toggle: bool = True,
) -> str:
    """
    Generate CTRPF AR cheat code for the specified FPS.

    The FPS control uses specific bit patterns in memory:
    - 60 FPS: compare=01000101, write=00000000 (or 01000000 for addr 0x65)
    - 30 FPS: compare=01000001, write=00000001 (or 01000001 for addr 0x65)

    Args:
        target_fps: The default FPS (60 or 30)
        fallback_fps: FPS when holding the fallback button
        fallback_button: Button to hold for fallback FPS (R, L, etc.)
        include_toggle: Whether to include the toggle version

    Returns:
        CTRPF AR cheat code string
    """
    if target_fps not in FPS_VALUES:
        raise ValueError(f"target_fps must be one of {list(FPS_VALUES.keys())}")
    if fallback_fps not in FPS_VALUES:
        raise ValueError(f"fallback_fps must be one of {list(FPS_VALUES.keys())}")

    # Exact bit patterns from original cheat codes
    # Format: (compare_value, write_value, write_value_65)
    FPS_PATTERNS = {
        60: ("01000101", "00000000", "01000000"),
        30: ("01000001", "00000001", "01000001"),
    }

    target_cmp, target_write, target_write_65 = FPS_PATTERNS[target_fps]
    fallback_cmp, fallback_write, fallback_write_65 = FPS_PATTERNS[fallback_fps]

    # Button codes for DD (conditional on button held)
    button_codes = {
        "A": "00000001",
        "B": "00000002",
        "SELECT": "00000004",
        "START": "00000008",
        "RIGHT": "00000010",
        "LEFT": "00000020",
        "UP": "00000040",
        "DOWN": "00000080",
        "R": "00000100",
        "L": "00000200",
        "X": "00000400",
        "Y": "00000800",
    }

    button_code = button_codes.get(fallback_button.upper(), "00000100")

    cheats = []

    # Toggle version with button hold
    if include_toggle:
        cheats.append(f"""[{target_fps}FPS (Hold {fallback_button} for {fallback_fps}FPS) {GAME_VERSION}]
D3000000 30000000
50000074 {target_cmp}
20000075 {target_write}
D0000000 00000000
520DA3AC {target_cmp}
220DA3AD {target_write}
D0000000 00000000
50000064 {target_cmp}
20000065 {target_write_65}
D0000000 00000000
50000044 {target_cmp}
20000045 {target_write}
D0000000 00000000
DD000000 {button_code}
50000074 {fallback_cmp}
20000075 {fallback_write}
D0000000 00000000
520DA3AC {fallback_cmp}
220DA3AD {fallback_write}
D0000000 00000000
50000064 {fallback_cmp}
20000065 {fallback_write_65}
D0000000 00000000
50000044 {fallback_cmp}
20000045 {fallback_write}
D0000000 00000000
D0000000 00000000
{{Game runs at {target_fps}FPS by default.
Hold {fallback_button} for {fallback_fps}FPS (useful for giant battles/credits).
Based on codes by @Shay}}
""")

    # Static FPS version
    cheats.append(f"""[++FPS++]

[{target_fps}FPS {GAME_VERSION}]
D3000000 30000000
50000074 {target_cmp}
20000075 {target_write}
D0000000 00000000
520DA3AC {target_cmp}
220DA3AD {target_write}
D0000000 00000000
50000064 {target_cmp}
20000065 {target_write_65}
D0000000 00000000
50000044 {target_cmp}
20000045 {target_write}
D0000000 00000000
D2000000 00000000
{{Sets FPS to {target_fps}.
Based on codes by @Shay}}

[Default {fallback_fps}FPS {GAME_VERSION}]
D3000000 30000000
50000074 {fallback_cmp}
20000075 {fallback_write}
D0000000 00000000
520DA3AC {fallback_cmp}
220DA3AD {fallback_write}
D0000000 00000000
50000064 {fallback_cmp}
20000065 {fallback_write_65}
D0000000 00000000
50000044 {fallback_cmp}
20000045 {fallback_write}
D0000000 00000000
D2000000 00000000
{{Restores default {fallback_fps}FPS.
Based on codes by @Shay}}

[--]
""")

    return "\n".join(cheats)


def main():
    parser = argparse.ArgumentParser(
        description="Generate FPS cheat codes for Mario & Luigi: BIS+BJJ"
    )
    parser.add_argument(
        "--fps",
        type=int,
        default=60,
        choices=[30, 60],
        help="Target FPS (default: 60)"
    )
    parser.add_argument(
        "--fallback-fps",
        type=int,
        default=30,
        choices=[30, 60],
        help="Fallback FPS when holding button (default: 30)"
    )
    parser.add_argument(
        "--button",
        type=str,
        default="R",
        help="Button to hold for fallback FPS (default: R)"
    )
    parser.add_argument(
        "--region",
        type=str,
        default="USA",
        choices=["USA", "EUR"],
        help="Game region (default: USA)"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path (default: stdout)"
    )

    args = parser.parse_args()

    cheat_code = generate_fps_cheat(
        target_fps=args.fps,
        fallback_fps=args.fallback_fps,
        fallback_button=args.button,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(cheat_code)
        print(f"Cheat code written to: {args.output}")
    else:
        print(cheat_code)


if __name__ == "__main__":
    main()
