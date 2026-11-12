# wintrace

Small stack traces for Zig programs on Windows that need no debug info at run time.

Zig's `std.debug` reads the PDB at run time: without it, a trace is `???` and absolute
addresses, and the PDB reader adds over 100 KB to the binary. wintrace writes each frame as
`module+0xoffset`, which stays valid under ASLR, and lists each module's PDB identity:

```
    wintrace
    demo.exe+0x10c5 (ip)
    demo.exe+0x225f (x95)
    ... 160 frames
    demo.exe+0x22ad
    KERNEL32.DLL+0x2dda7
    ntdll.dll+0x7ee4c
    module demo.exe | demo.pdb | B8F0742BA04EE44B4C4C44205044422E1
    module KERNEL32.DLL | kernel32.pdb | E8C3A48CAC7EB60D8781D8C10020C44F1
    module ntdll.dll | ntdll.pdb | C031D45B0DA18A6E74D06ED6AB2DD9E11
```

` (ip)` marks the instruction an exception happened at; every other frame is a return address.
` (xN)` is N identical frames, such as a stack overflow's recursion. The full format is at the
top of [src/wintrace.zig](src/wintrace.zig).

It allocates nothing and needs at most 10 KB of stack, so it works in a stack overflow handler.

## Symbolizing

Later, on any machine, `wintrace-symbolize` adds function names and source lines from the
matching PDBs:

```
> wintrace-symbolize crash.log syms\demo.pdb
    wintrace
    demo.exe+0x10c5 (ip) in inner+0xc5 (C:\src\demo.zig:8)
    demo.exe+0x225f (x95) in recurse+0xe (C:\src\demo.zig:4)
    ... 160 frames
    demo.exe+0x22ad in main (C:\src\demo.zig:3)
        inlined into WinStartup+0x2c (...\lib\std\start.zig:627)
    KERNEL32.DLL+0x2dda7 (no pdb)
    ntdll.dll+0x7ee4c (no pdb)
    ...
```

The input can be a whole log, or `-` for stdin; everything that isn't a trace is copied
unchanged. A PDB from a different build is reported as such instead of giving wrong names.

Keep the PDB of each release. Build with `.strip = false` (ReleaseSmall strips by default), or
the image has no PDB identity.

## Crash reports

wintrace can report a program's panics, unhandled exceptions and errors returned from main
(Zig 0.17.0 or later). [example/main.zig](example/main.zig) is a cross-platform program set up
this way. In build.zig, add wintrace only for Windows:

```zig
if (target.result.os.tag == .windows) {
    if (b.lazyDependency("wintrace", .{})) |dep| exe.root_module.addImport("wintrace", dep.module("wintrace"));
}
```

`wintrace_options.mode` is one of:

- `.small`: never reads the PDB at run time, and writes its reports straight to the stderr
  handle. std's stderr lock isn't taken, since it goes through `std.Io.Threaded`, about 300 KB.
- `.symbolize`: when the PDB is beside the exe, crash reports print std's traces instead, with
  function names and source lines. Adds about 150 KB.

## Traces in your own code

```zig
const wintrace = @import("wintrace");

// the current stack, from the caller (or from first_address, such as a panic's)
try wintrace.writeCurrentStackTrace(w, null);

// the stack an exception was raised on, from an exception handler
try wintrace.writeStackTrace(w, info.ContextRecord);

// or capture now, write later, while the modules are still loaded
var addresses: [64]usize = undefined;
const n = wintrace.capture(context, &addresses);
try wintrace.writeAddresses(w, addresses[0..n], .{ .first_is_ip = true, .truncated = n == addresses.len });
```

A corrupt stack can still make the unwinder fault. In an exception handler, skip tracing when
you're already tracing, or a fault while tracing repeats until the stack runs out.

## Platforms

x86_64, aarch64 and x86, with Zig 0.15.2 and 0.17.0. x86 has no unwind info, so wintrace walks
the frame pointer chain there: keep frame pointers (Zig does by default) or frames go missing.

## Size

In section bytes before file alignment, what a ReleaseSmall exe gains from:

- wintrace: writing a trace, in an exe that already writes to a `std.Io.Writer`
- crash reports: all three of the `.small` mode's reports, in an exe that already calls
  `memcpy`, `memmove` and `memset`. This includes the trace above and std's `Io.Writer`.

| Zig    | arch    | wintrace | crash reports |
|--------|---------|----------|---------------|
| 0.15.2 | x86_64  | 4,072 bytes | |
| 0.15.2 | aarch64 | 3,592 bytes | |
| 0.15.2 | x86     | 3,090 bytes | |
| 0.17.0 | x86_64  | 4,096 bytes | 7,992 bytes |
| 0.17.0 | aarch64 | 3,624 bytes | 7,516 bytes |
| 0.17.0 | x86     | 3,274 bytes | 6,417 bytes |

The tests check this table exactly.

Not in the table: with Zig 0.17 on x86_64, an exe's first call to `memcpy`, `memmove` or
`memset` adds 46 KB, wintrace's or not. The routines are under 100 bytes each, but they come
with the rest of compiler-rt (its trigonometry and float conversions), which the linker doesn't
drop.

## License

[MIT-0](LICENSE)
