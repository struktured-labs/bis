#!/usr/bin/env python3
"""
Analyze memory trace logs from instrumented Lime3DS emulator

Usage:
    uv run analyze_memory_trace.py memory_trace.log
"""

import re
import sys
from collections import defaultdict, Counter
from pathlib import Path


class MemoryTrace:
    """Parse and analyze memory trace logs"""

    def __init__(self, log_file):
        self.log_file = log_file
        self.writes = []
        self.pc_to_writes = defaultdict(list)
        self.addr_to_writes = defaultdict(list)

    def parse(self):
        """Parse memory trace log file"""
        # Pattern: [MEM_TRACE] Write8: PC=001a2b3c Addr=30000075 Val=01
        pattern = re.compile(
            r'\[MEM_TRACE\] Write(?P<size>\d+): '
            r'PC=(?P<pc>[0-9a-f]+) '
            r'Addr=(?P<addr>[0-9a-f]+) '
            r'Val=(?P<val>[0-9a-f]+)',
            re.IGNORECASE
        )

        with open(self.log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = pattern.search(line)
                if match:
                    write = {
                        'line': line_num,
                        'size': int(match.group('size')),
                        'pc': int(match.group('pc'), 16),
                        'addr': int(match.group('addr'), 16),
                        'val': int(match.group('val'), 16),
                    }
                    self.writes.append(write)
                    self.pc_to_writes[write['pc']].append(write)
                    self.addr_to_writes[write['addr']].append(write)

        print(f"Parsed {len(self.writes)} memory writes from {self.log_file}")

    def analyze_fps_flag(self, fps_addr=0x30000075):
        """Analyze writes to FPS flag specifically"""
        print(f"\n{'='*60}")
        print(f"FPS Flag Analysis (Address: 0x{fps_addr:08x})")
        print(f"{'='*60}\n")

        fps_writes = self.addr_to_writes.get(fps_addr, [])
        if not fps_writes:
            print("No writes to FPS flag found!")
            return

        print(f"Total writes to FPS flag: {len(fps_writes)}")

        # Value distribution
        values = Counter(w['val'] for w in fps_writes)
        print(f"\nValue distribution:")
        for val, count in values.most_common():
            pct = (count / len(fps_writes)) * 100
            print(f"  0x{val:02x}: {count:5d} times ({pct:5.1f}%)")

        # PC distribution
        pcs = Counter(w['pc'] for w in fps_writes)
        print(f"\nUnique PCs writing to FPS flag: {len(pcs)}")
        print(f"\nTop PCs (by frequency):")
        for pc, count in pcs.most_common(10):
            pct = (count / len(fps_writes)) * 100
            print(f"  0x{pc:08x}: {count:5d} writes ({pct:5.1f}%)")

        # Temporal analysis
        if len(fps_writes) > 1:
            # Calculate time between writes (using line numbers as proxy)
            intervals = []
            for i in range(1, len(fps_writes)):
                interval = fps_writes[i]['line'] - fps_writes[i-1]['line']
                intervals.append(interval)

            avg_interval = sum(intervals) / len(intervals)
            print(f"\nAverage interval between writes: {avg_interval:.1f} log lines")

        # Check for patterns
        print(f"\nPattern analysis:")
        if len(set(w['pc'] for w in fps_writes)) == 1:
            print("  ✓ Single PC writes to FPS flag (consistent caller)")
        else:
            print("  ! Multiple PCs write to FPS flag")

        if len(values) == 1:
            print(f"  ✓ Always writes same value: 0x{list(values.keys())[0]:02x}")
        else:
            print(f"  ! Writes different values: {[f'0x{v:02x}' for v in values.keys()]}")

    def analyze_region(self, start_addr, end_addr):
        """Analyze writes to a memory region"""
        print(f"\n{'='*60}")
        print(f"Region Analysis: 0x{start_addr:08x} - 0x{end_addr:08x}")
        print(f"{'='*60}\n")

        region_writes = [
            w for w in self.writes
            if start_addr <= w['addr'] <= end_addr
        ]

        if not region_writes:
            print("No writes in this region!")
            return

        print(f"Total writes: {len(region_writes)}")

        # Address distribution
        addrs = Counter(w['addr'] for w in region_writes)
        print(f"\nTop addresses (by write frequency):")
        for addr, count in addrs.most_common(10):
            pct = (count / len(region_writes)) * 100
            print(f"  0x{addr:08x}: {count:5d} writes ({pct:5.1f}%)")

    def find_hot_pcs(self, top_n=20):
        """Find PCs that write most frequently"""
        print(f"\n{'='*60}")
        print(f"Hot PC Analysis (Top {top_n} writers)")
        print(f"{'='*60}\n")

        pc_counts = Counter(w['pc'] for w in self.writes)
        total_writes = len(self.writes)

        print(f"{'PC':<12} {'Writes':<8} {'%':<8} {'Unique Addrs':<12}")
        print("-" * 50)

        for pc, count in pc_counts.most_common(top_n):
            pct = (count / total_writes) * 100
            unique_addrs = len(set(w['addr'] for w in self.pc_to_writes[pc]))
            print(f"0x{pc:08x}   {count:<8} {pct:5.1f}%   {unique_addrs:<12}")

    def export_for_ghidra(self, output_file="pcs_to_analyze.txt"):
        """Export list of PCs for analysis in Ghidra"""
        # Get unique PCs that write to FPS flag
        fps_pcs = set()
        for write in self.addr_to_writes.get(0x30000075, []):
            fps_pcs.add(write['pc'])

        # Also get hot PCs in general
        pc_counts = Counter(w['pc'] for w in self.writes)
        hot_pcs = set(pc for pc, _ in pc_counts.most_common(50))

        all_pcs = fps_pcs | hot_pcs

        with open(output_file, 'w') as f:
            f.write("# PCs to analyze in Ghidra\n")
            f.write("# (derived from memory trace analysis)\n\n")
            f.write("# PCs writing to FPS flag (0x30000075):\n")
            for pc in sorted(fps_pcs):
                f.write(f"0x{pc:08x}\n")
            f.write("\n# Other hot PCs:\n")
            for pc in sorted(hot_pcs - fps_pcs):
                f.write(f"0x{pc:08x}\n")

        print(f"\n{'='*60}")
        print(f"Exported {len(all_pcs)} PCs to: {output_file}")
        print(f"{'='*60}")
        print(f"\nYou can now analyze these addresses in Ghidra:")
        print(f"  1. Open Ghidra with your game binary")
        print(f"  2. Go to Navigation > Go To... (press G)")
        print(f"  3. Enter each PC address to analyze the code")
        print(f"  4. Look for function calls, loops, and branching logic")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <memory_trace.log>")
        print(f"\nAnalyzes memory trace logs from instrumented Lime3DS")
        sys.exit(1)

    log_file = sys.argv[1]
    if not Path(log_file).exists():
        print(f"Error: {log_file} not found!")
        sys.exit(1)

    # Parse trace
    trace = MemoryTrace(log_file)
    trace.parse()

    # Run analyses
    trace.analyze_fps_flag(0x30000075)
    trace.analyze_region(0x30000070, 0x30000080)  # Region around FPS flag
    trace.find_hot_pcs(20)

    # Export for Ghidra
    trace.export_for_ghidra("tmp/pcs_to_analyze.txt")

    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)


if __name__ == '__main__':
    main()
