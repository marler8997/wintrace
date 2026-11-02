# wintrace

Small stack traces for Zig programs on Windows that need no debug info at run time.

Zig's `std.debug` traces read the PDB at run time. A program shipped without its PDB prints
`???` and absolute addresses, and the PDB reader adds hundreds of KB to the binary and needs
around a megabyte of stack to report a crash. wintrace walks the stack with the unwinder
Windows itself uses for exceptions (`RtlVirtualUnwind` over each module's `.pdata`, in
ntdll.dll), writes each frame as `module+0xoffset`, and lists the PDB identity of every module
in the trace. It allocates nothing, stops at a stack pointer outside the thread's stack, and
needs 4 to 8 KB of stack in a release build (up to 10 KB in Debug), ntdll's included, so it
works from a stack overflow handler: the tests hold it to a budget and report an overflow from a
16 KiB `SetThreadStackGuarantee`.

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

Offsets stay valid under ASLR. ` (ip)` marks the instruction an exception happened at; every
other frame is a return address. ` (xN)` stands for N identical frames, such as a stack
overflow's recursion. A deep stack keeps its innermost 96 and outermost 32 frames, so the
thread's start is still there. The PDB identity is the GUID and age the linker stamps into both
the image and its PDB, in the form symbol stores use as their directory name. The full format
is at the top of [src/wintrace.zig](src/wintrace.zig).

Later, on any machine, `wintrace-symbolize` adds function names, source lines and inlined
frames from the matching PDBs:

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

The input can be a whole log, or `-` for standard input: each trace in it is symbolized with its
own module lines, and everything else is copied unchanged. A PDB is used only for the module
whose identity it matches, so a PDB from another build is reported as `pdb is from a different
build` instead of giving wrong names. Write each trace in one piece: another thread's line in
the middle splits it, and the part before that line has no module lines, so it isn't
symbolized. The symbolizer uses dbghelp.dll, which ships with Windows, and needs only the PDBs,
not the images. It works on any trace in this format, whatever language the image was built
from.

## Usage

```zig
// build.zig
const wintrace = b.dependency("wintrace", .{}).module("wintrace");
exe.root_module.addImport("wintrace", wintrace);
```

```zig
const wintrace = @import("wintrace");

// the current stack, from the caller of writeCurrentStackTrace
// (or from first_address, such as a panic handler's return address)
try wintrace.writeCurrentStackTrace(w, null);

// the stack an exception was raised on, from a vectored or unhandled exception filter
try wintrace.writeStackTrace(w, info.ContextRecord);

// or capture addresses first and write them later, while their modules are still loaded
var addresses: [64]usize = undefined;
const n = wintrace.capture(context, &addresses);
try wintrace.writeAddresses(w, addresses[0..n], .{ .first_is_ip = true, .truncated = n == addresses.len });
```

A corrupt stack can still make ntdll's unwinder read past the stack and fault. In an exception
handler, set a threadlocal flag before writing the trace and skip it when the flag is already
set, so a fault while tracing doesn't trace again until the stack runs out.

Keep the PDB of each release you ship. A stripped image has no PDB identity, so build with
`.strip = false` (ReleaseSmall strips by default) and drop the PDB from what you ship instead.

Supports x86_64 and aarch64, and builds with Zig 0.15.2 and 0.17.0.

## Size

What wintrace adds to a ReleaseSmall exe that already writes to a `std.Io.Writer`, in section
bytes before file alignment:

| Zig    | arch    | wintrace |
|--------|---------|----------|
| 0.15.2 | x86_64  | 4,072 bytes |
| 0.15.2 | aarch64 | 3,592 bytes |
| 0.17.0 | x86_64  | 4,096 bytes |
| 0.17.0 | aarch64 | 3,624 bytes |

The builds are reproducible and the tests check these exactly, so a change to wintrace that
changes its size updates this table too.
## Also printing std's trace when the PDB is available

Where the PDB is next to the exe, such as a local Debug build, std's trace adds function names
and source lines on the spot. Write wintrace's trace first and flush it, so it's in the log even
if std's attempt fails while the process is crashing, then std's:

```zig
// in an exception filter (Zig 0.17)
try wintrace.writeStackTrace(w, info.ContextRecord);
try w.flush();
if (builtin.mode == .debug and info.ExceptionRecord.ExceptionCode != EXCEPTION_STACK_OVERFLOW) {
    const native = std.debug.cpu_context.fromWindowsContext(info.ContextRecord);
    std.debug.writeCurrentStackTrace(.{ .context = &native }, terminal) catch {};
}
```

In a panic handler it's `wintrace.writeCurrentStackTrace(w, first_address)`, then std's
`writeCurrentStackTrace(.{ .first_address = first_address }, terminal)`. On Zig 0.15 the std
calls are `dumpStackTraceFromBase(context, w)` and `dumpCurrentStackTrace(first_address)`.

- Gate it at comptime, as `builtin.mode == .debug` does here (`.Debug` on Zig 0.15), so release
  builds don't pay for std's PDB reader: about 160 KB in a ReleaseSafe exe.
- A stack overflow handler runs on whatever stack `SetThreadStackGuarantee` reserved. std
  needs around a megabyte of it to read the PDB (0.7 to 1.6 MiB, depending on the Zig version
  and optimize mode), and overflowing again ends the process: std's trace never appears, and
  anything the handler would have done after it, such as showing a message box, never
  happens. Either skip std's trace for a stack overflow, as above, or set a guarantee that
  big on each thread that should report one.
  [zig-win32-crash-handling](https://github.com/marler8997/zig-win32-crash-handling) does the
  latter, with a test that fails if the guarantee is too small.

## License

[MIT-0](LICENSE)
