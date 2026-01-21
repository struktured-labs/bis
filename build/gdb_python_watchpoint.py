#!/usr/bin/env python3
"""
GDB Python Script - Automated Watchpoint with Timing
Uses GDB's Python API to properly handle delays and watchpoints
"""

import gdb
import time
import sys

class FPSWatchpoint:
    def __init__(self):
        self.log_file = open("/home/struktured/projects/bis/tmp/gdb_fps_watchpoint.log", "w")
        self.hit_count = 0
        self.max_hits = 3

    def log(self, msg):
        """Write to both stdout and log file"""
        print(msg)
        self.log_file.write(msg + "\n")
        self.log_file.flush()

    def run(self):
        """Main execution flow"""
        self.log("=" * 70)
        self.log("  GDB Python Watchpoint - FPS Control Discovery")
        self.log("=" * 70)
        self.log("")

        # Configure GDB
        gdb.execute("set pagination off")
        gdb.execute("set logging overwrite on")
        gdb.execute("set confirm off")
        gdb.execute("handle SIGSEGV nostop noprint pass")
        gdb.execute("handle SIGILL nostop noprint pass")

        # Set up event handler BEFORE starting
        gdb.events.stop.connect(self.handle_stop)

        self.log("Starting emulator with delayed breakpoint...")

        # Create a temporary breakpoint that will trigger after startup
        # We'll use a Python breakpoint that triggers after the inferior starts
        class StartupBreakpoint(gdb.Breakpoint):
            def __init__(self, outer):
                # Break at main (or any early point)
                super().__init__("*0x100000", internal=True, temporary=False)
                self.outer = outer
                self.triggered = False

            def stop(self):
                if not self.triggered:
                    self.triggered = True
                    self.outer.log("Initial breakpoint hit, waiting 15 seconds...")
                    time.sleep(15)
                    self.outer.setup_watchpoints()
                    return False  # Don't actually stop, continue execution
                return False

        try:
            bp = StartupBreakpoint(self)
        except:
            # If breakpoint creation fails, just try direct approach
            pass

        self.log("Starting execution...")

        try:
            # Start the program - this will run until a stop event
            gdb.execute("run")
        except gdb.error as e:
            self.log(f"Run ended: {e}")

        self.log("")
        self.log("=" * 70)
        self.log(f"Analysis complete. Captured {self.hit_count} watchpoint hits.")
        self.log("=" * 70)

        self.log_file.close()

    def setup_watchpoints(self):
        """Set up watchpoints after game has loaded"""
        self.log("Setting watchpoints on 0x30000075...")
        try:
            gdb.execute("watch *(unsigned char*)0x30000075")
            gdb.execute("rwatch *(unsigned char*)0x30000075")
            self.log("Watchpoints set successfully")
        except gdb.error as e:
            self.log(f"Warning: Could not set watchpoint: {e}")
            self.log("Trying alternative addresses...")
            # Try nearby addresses
            for offset in [0x74, 0x75, 0x76]:
                try:
                    addr = 0x30000000 + offset
                    gdb.execute(f"watch *(unsigned char*)0x{addr:08X}")
                    self.log(f"Set watchpoint on 0x{addr:08X}")
                except:
                    pass

        self.log("Watchpoints configured, continuing execution...")
        self.log("")

    def handle_stop(self, event):
        """Called whenever execution stops (breakpoint, watchpoint, etc)"""
        if isinstance(event, gdb.SignalEvent):
            return  # Ignore signals

        if isinstance(event, gdb.BreakpointEvent):
            self.hit_count += 1

            self.log("")
            self.log("=" * 70)
            self.log(f"  WATCHPOINT HIT #{self.hit_count}")
            self.log("=" * 70)
            self.log("")

            # Get current frame
            try:
                frame = gdb.selected_frame()
                pc = frame.pc()

                self.log(f"Program Counter: 0x{pc:08X}")
                self.log("")

                # Show registers
                self.log("--- Registers ---")
                self.log(gdb.execute("info registers", to_string=True))

                # Show backtrace
                self.log("--- Backtrace ---")
                self.log(gdb.execute("backtrace 20", to_string=True))

                # Disassemble around PC
                self.log("--- Disassembly ---")
                try:
                    disasm = gdb.execute(f"disassemble {pc-32},{pc+64}", to_string=True)
                    self.log(disasm)
                except:
                    self.log("Could not disassemble")

                # Show memory at target address
                self.log("--- Memory at 0x30000075 ---")
                try:
                    mem = gdb.execute("x/32xb 0x30000075", to_string=True)
                    self.log(mem)
                except:
                    self.log("Could not read memory")

            except Exception as e:
                self.log(f"Error during analysis: {e}")

            # Continue or quit after max hits
            if self.hit_count >= self.max_hits:
                self.log("")
                self.log(f"Captured {self.max_hits} hits, stopping...")
                gdb.execute("quit")
            else:
                self.log("")
                self.log("Continuing to catch next hit...")
                self.log("")

# Entry point when loaded by GDB
if __name__ == "__main__":
    watchpoint = FPSWatchpoint()
    watchpoint.run()
