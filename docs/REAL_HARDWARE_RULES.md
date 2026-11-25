# Standing rule: no emulator-only assumptions

Every patch in this repo has to work on a real 3DS/2DS running Luma3DS, not
just in Azahar. Passing in an emulator does not show that a patch works on
hardware.

## The rule

**Never hardcode memory addresses, and never rely on behavior that only
holds in Azahar (or Citra, Lime3DS, or any other emulator). Read state the
way the game or the OS does.**

Anything that only works because of emulator-only state is an antipattern.
If it is ever done on purpose, mark it as one in the code and in this
file.

## Cautionary example: the v1.2.1 R-button read

The v1.2.1 R-toggle cave read the pad state from the hardcoded address
`0x1000201C`. In Azahar the HID shared memory always lands at
`0x10002000`, so the patch worked there. On a real 3DS the kernel picks
that address when the game maps the block (`svcMapMemoryBlock` with
addr=0), and `0x1000201C` is unmapped. The result was a data abort and an
immediate boot crash on real hardware (Remillio's crash dump on v1.0;
GameBanana report on v1.2).

The fix (v1.2.2) reads the pad the way the game does, through its own HID
object:

```
ldr  r2, =0x0042A6C0   @ game's HID object (.bss)
ldr  r2, [r2, #4]      @ PAD shared-memory pointer the game stored
cmp  r2, #0            @ not mapped yet -> default
beq  default
ldr  r2, [r2, #0x1C]   @ current PAD state
tst  r2, #0x100        @ KEY_R
```

i.e. `*(*(0x42A6C0 + 4) + 0x1C)`, with a null check. Do not use
`0x1000201C`.

## Checklist for every code cave and patch

- **Addresses:** use only addresses inside the game's own code.bin
  segments (`.text`/`.rodata`/`.data`/`.bss`, checked against the
  exheader). Never use HID/IO/shared-memory VAs (`0x1000xxxx`,
  `0x1FFxxxxx`, config memory, kernel areas). Get them from the pointer the
  game itself stored.
- **Null checks:** check any pointer the game fills in at runtime before
  dereferencing it, and fall back to stock behavior if it is null.
- **Cave placement:** a cave must be unreachable. Check B/BL targets,
  literal-pool pointers (including Thumb `+1`), vtables, CRO imports, and
  **fall-through from the preceding instruction** (a function can start one
  instruction before the `PUSH`). Prefer the zero padding at the end of the
  last `.text` page. Confirm dynamically with the gdbstub that the
  replaced code never runs in stock.
- **Timing and threads:** never remove a wait, sleep, or sync loop, or
  depend on how Azahar schedules threads. Emulator scheduling hides races.
- **Initialized state:** don't NOP an initializing store if anything still
  reads the field; write a known value instead. Emulator heap is often
  zero; hardware heap is not.
- **No runtime writes to `.text`:** Luma applies `code.ips` before the
  process starts, which is fine. Code that writes to `.text` at runtime
  faults on hardware, because `.text` is mapped RX.
- **No new SVCs, and no cache tricks:** don't add `svc` calls or
  self-modifying code. If you can't avoid it, it needs a cache flush and a
  real-hardware test.
- **ABI:** keep caves leaf-safe: save every register you clobber, keep SP
  8-byte aligned, do aligned word loads only, and don't clobber flags the
  caller still uses.
- **Verification:** headless stock Azahar is required, but it is not
  enough. Release notes must say "not yet tested on a real 3DS" until
  someone has run it on one.
