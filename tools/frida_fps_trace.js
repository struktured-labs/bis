/**
 * Frida script for tracing FPS-related memory operations in Citra/Lime3DS
 *
 * Usage:
 *   frida -l frida_fps_trace.js -f ./citra-qt -- /path/to/rom.3ds
 *
 * Or attach to running process:
 *   frida -l frida_fps_trace.js citra-qt
 */

// Target addresses and ranges
const FPS_FLAG_ADDR = 0x30000075;
const LINEAR_HEAP_START = 0x30000000;
const LINEAR_HEAP_END = 0x38000000;

// Track unique PCs that write to FPS flag
const fpsWriters = new Set();
const writeHistory = [];

console.log("[*] Frida FPS Trace Script Loaded");
console.log("[*] Targeting FPS flag at: 0x" + FPS_FLAG_ADDR.toString(16));

/**
 * Find and hook memory write functions
 */
function hookMemoryWrites() {
    // Look for Memory::Write8/16/32 functions in the binary
    const write8Patterns = [
        "Memory::Write8",
        "_ZN6Memory6Write8Ejh",  // Mangled name
        "Write8",
    ];

    const write16Patterns = [
        "Memory::Write16",
        "_ZN6Memory7Write16Ejt",
        "Write16",
    ];

    const write32Patterns = [
        "Memory::Write32",
        "_ZN6Memory7Write32Ejj",
        "Write32",
    ];

    // Try to find and hook Write8
    let foundWrite8 = false;
    for (const pattern of write8Patterns) {
        const addr = Module.findExportByName(null, pattern);
        if (addr) {
            console.log("[+] Found Write8 at: " + addr);
            hookWrite8(addr);
            foundWrite8 = true;
            break;
        }
    }

    if (!foundWrite8) {
        console.log("[-] Could not find Write8 function, trying symbol scan...");
        scanForWriteFunctions();
    }
}

/**
 * Hook Memory::Write8 function
 */
function hookWrite8(address) {
    Interceptor.attach(address, {
        onEnter: function(args) {
            const vaddr = args[0].toInt32();
            const value = args[1].toInt32() & 0xFF;

            // Only trace LINEAR_HEAP region
            if (vaddr >= LINEAR_HEAP_START && vaddr < LINEAR_HEAP_END) {
                const pc = this.context.pc;
                const lr = this.context.lr || this.context.x30;  // ARM/ARM64 link register

                // Special attention to FPS flag
                if (vaddr === FPS_FLAG_ADDR) {
                    console.log("\n[FPS_WRITE]");
                    console.log("  Address: 0x" + vaddr.toString(16));
                    console.log("  Value: 0x" + value.toString(16) + " (" + value + ")");
                    console.log("  PC: " + pc);
                    console.log("  LR: " + lr);
                    console.log("  Backtrace:");

                    try {
                        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        bt.forEach((addr, i) => {
                            const sym = DebugSymbol.fromAddress(addr);
                            console.log("    " + i + ": " + addr + " " + sym);
                        });
                    } catch (e) {
                        console.log("    (backtrace unavailable: " + e + ")");
                    }

                    // Track unique PC values
                    const pcStr = pc.toString();
                    if (!fpsWriters.has(pcStr)) {
                        fpsWriters.add(pcStr);
                        console.log("  >> NEW PC writing to FPS flag!");
                    }

                    // Record to history
                    writeHistory.push({
                        timestamp: Date.now(),
                        addr: vaddr,
                        value: value,
                        pc: pcStr,
                    });

                    // Optional: Force value to 0x00 for 60fps
                    // args[1] = ptr(0x00);
                }
                // Log other LINEAR_HEAP writes at lower verbosity
                else if (vaddr >= 0x30000070 && vaddr <= 0x30000080) {
                    console.log("[MEM] Write8 PC=" + pc + " Addr=0x" + vaddr.toString(16) +
                               " Val=0x" + value.toString(16));
                }
            }
        }
    });

    console.log("[+] Hooked Write8, monitoring LINEAR_HEAP writes");
}

/**
 * Scan for write functions if symbols not found
 */
function scanForWriteFunctions() {
    console.log("[*] Scanning for memory write patterns...");

    // This is more complex - would need to scan executable sections
    // for function patterns. For now, suggest using symbols.
    console.log("[!] Please ensure emulator is built with symbols (-g)");
    console.log("[!] Or use: frida-trace -i 'Memory::*' citra-qt");
}

/**
 * Dump statistics on exit
 */
function dumpStats() {
    console.log("\n========== FPS Write Statistics ==========");
    console.log("Total FPS writes: " + writeHistory.length);
    console.log("Unique PC values: " + fpsWriters.size);
    console.log("\nUnique PCs:");
    fpsWriters.forEach(pc => console.log("  " + pc));

    if (writeHistory.length > 0) {
        console.log("\nValue distribution:");
        const valueCounts = {};
        writeHistory.forEach(w => {
            valueCounts[w.value] = (valueCounts[w.value] || 0) + 1;
        });
        Object.keys(valueCounts).forEach(val => {
            console.log("  0x" + parseInt(val).toString(16) + ": " + valueCounts[val] + " times");
        });
    }

    // Save detailed history to file
    const fs = new File("/tmp/frida_fps_trace.json", "w");
    fs.write(JSON.stringify({
        writers: Array.from(fpsWriters),
        history: writeHistory,
    }, null, 2));
    fs.close();
    console.log("\nDetailed trace saved to: /tmp/frida_fps_trace.json");
}

// Attach hooks on load
setTimeout(hookMemoryWrites, 1000);

// Dump stats on process exit (Ctrl+C)
Process.setExceptionHandler(dumpStats);
