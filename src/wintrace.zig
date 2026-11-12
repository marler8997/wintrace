//! Stack traces for Windows that need no debug info at run time.
//!
//! Frames are walked with the unwinder Windows uses for exceptions (RtlVirtualUnwind over each
//! module's .pdata) and written as `module+0xoffset`, which stays valid under ASLR. After the
//! frames, each module in the trace is listed with the identity of its PDB, so the trace can be
//! symbolized later, on another machine, with `wintrace-symbolize` and the matching PDB:
//!
//!     wintrace
//!     demo.exe+0x10c5 (ip)
//!     demo.exe+0x225f (x95)
//!     ... 160 frames
//!     demo.exe+0x22ad
//!     KERNEL32.DLL+0x2dda7
//!     module demo.exe | demo.pdb | B8F0742BA04EE44B4C4C44205044422E1
//!     module KERNEL32.DLL | kernel32.pdb | E8C3A48CAC7EB60D8781D8C10020C44F1
//!
//! The format, line by line, each indented by four spaces:
//!   - `wintrace`: the start of a trace, so one cut short, such as by the process dying while
//!     writing it, isn't taken for part of the next.
//!   - `<module>+0x<offset>`: a frame. Every frame is a return address, which points after its
//!     call, except one marked ` (ip)`: the instruction an exception happened at. ` (xN)` means
//!     the line stands for N identical frames in a row.
//!   - `0x<address>`: a frame outside any loaded module, or in one whose path is too long to
//!     read its name.
//!   - `... N frames`: frames left out of a deep stack, between its innermost and outermost.
//!     `... at least N frames` when the walk gave up first, so the frames after it may not be
//!     the outermost.
//!   - `... more frames`: the stack goes on past the last frame, from writeAddresses.
//!   - `module <module> | <pdb> | <key>`: one per module the frames are in. `<key>` is the PDB
//!     identity the linker stamps into both the image and its PDB (GUID and age, as symbol
//!     stores name its directory); `-` when the image has none. Windows file names can't
//!     contain `|`, so the names may contain spaces.
//!   - `... more modules`: the trace has frames in more modules than are listed.
//!
//! Supports x86_64, aarch64 and x86, and builds with Zig 0.15.2 and 0.17.0. x86 has no unwind
//! info, so its frames are walked through the frame pointer chain: the code in the trace must keep
//! frame pointers (`.omit_frame_pointer = false`), as Windows' own x86 DLLs do.
//!
//! For crash reports with these traces, see example/main.zig.

comptime {
    if (builtin.cpu.arch == .x86 and builtin.omit_frame_pointer) @compileError(
        "wintrace on x86 walks the stack through the frame pointer, set omit_frame_pointer to false",
    );
}

/// Writes the stack of the calling thread, starting at the caller of this function. When
/// `first_address` is one of its return addresses, such as a panic handler's, the frames
/// above it are skipped too.
pub noinline fn writeCurrentStackTrace(w: *std.Io.Writer, first_address: ?usize) error{WriteFailed}!void {
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // frame 0 is this function, except on x86, where RtlCaptureContext returns its caller's
    // caller's context, as if this function had returned
    var skip: usize = if (builtin.cpu.arch == .x86) 0 else 1;
    if (first_address) |address| {
        var scan: Walker = undefined;
        scan.init(&context, no_leaf_scan);
        for (0..first_address_search) |i| {
            const ip = scan.next() orelse break;
            if (i > 0 and ip == address) {
                skip = i;
                break;
            }
        }
    }
    try writeWalk(w, &context, skip, false, no_leaf_scan);
}

/// Writes the stack starting at `context`, such as an exception's ContextRecord. The context
/// must be from the calling thread. Its first frame is marked ` (ip)`. For the current stack,
/// use writeCurrentStackTrace: on x86, RtlCaptureContext returns its caller's caller's
/// context, so a trace from it would leave out the function that called it.
pub fn writeStackTrace(w: *std.Io.Writer, context: *const windows.CONTEXT) error{WriteFailed}!void {
    try writeWalk(w, context, 0, true, yes_leaf_scan);
}

/// Fills `addresses` with the instruction pointer of each frame, starting at `context`, which
/// must be from the calling thread, and returns how many it found. When that's
/// `addresses.len`, the stack may have more (or exactly that many). Doesn't allocate and
/// doesn't need debug info. The first address is the context's instruction pointer; every
/// other one is a return address.
pub fn capture(context: *const windows.CONTEXT, addresses: []usize) usize {
    var walker: Walker = undefined;
    walker.init(context, yes_leaf_scan);
    var count: usize = 0;
    while (count < addresses.len) : (count += 1) {
        addresses[count] = walker.next() orelse break;
    }
    return count;
}

pub const WriteOptions = struct {
    /// The first address is an instruction pointer, not a return address, such as the first
    /// address `capture` returns.
    first_is_ip: bool = false,
    /// The stack has frames beyond the last address, such as when `capture` filled its buffer.
    truncated: bool = false,
};

/// Writes a trace of `addresses`, such as those from `capture`. A module the addresses are in
/// must still be loaded, at the same address, when they're written.
pub fn writeAddresses(w: *std.Io.Writer, addresses: []const usize, options: WriteOptions) error{WriteFailed}!void {
    var t: TraceWriter = .init(w);
    try t.start();
    try t.frames(addresses, options.first_is_ip);
    if (options.truncated) try t.line("    ... more frames", null);
    try t.finish();
}

/// Writes `module+0xoffset` for an address in a loaded module, or `0x<address>` otherwise.
pub fn writeAddress(w: *std.Io.Writer, address: usize) error{WriteFailed}!void {
    const base = moduleBase(address) orelse return writeHex(w, "0x", address, 1, .lower);
    try writeModuleName(w, base);
    try writeHex(w, "+0x", address - base, 1, .lower);
}

/// The PDB a loaded image was linked with, from its CodeView debug record.
pub const PdbInfo = struct {
    guid: [16]u8,
    age: u32,
    /// The path the linker wrote the PDB to. Points into the image, so it's valid while the
    /// image stays loaded.
    path: []const u8,
};

/// Reads the CodeView (RSDS) record of the image loaded at `base`, or returns null when it has
/// none, such as a stripped image. Every offset is checked against the image's size and only
/// the image's own memory is read, so it's safe to call while crashing.
pub fn pdbInfo(base: usize) ?PdbInfo {
    const image: [*]const u8 = @ptrFromInt(base);
    if (readU16(image) != 0x5a4d) return null; // "MZ"
    // The headers read below are in the image's first page, which is always mapped.
    const nt_offset = readU32(image + 0x3c);
    if (nt_offset > 4096 - nt_headers_read) return null;
    const nt = image + nt_offset;
    if (readU32(nt) != 0x4550) return null; // "PE\0\0"
    const optional = nt + 24;
    // PE32+ in a 64-bit process, PE32 in a 32-bit one, the only kinds each runs
    if (readU16(optional) != pe_magic) return null;
    const size_of_image = readU32(optional + 56);
    // NumberOfRvaAndSizes, just before the data directories; the debug directory is the 7th
    if (readU32(optional + pe_directories - 4) <= 6) return null;
    const debug_rva = readU32(optional + pe_directories + 6 * 8);
    const debug_size = readU32(optional + pe_directories + 6 * 8 + 4);
    if (debug_rva == 0 or !inImage(debug_rva, debug_size, size_of_image)) return null;
    var offset: u32 = 0;
    while (offset + 28 <= debug_size) : (offset += 28) {
        const entry = image + debug_rva + offset;
        if (readU32(entry + 12) != 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
        const data_size = readU32(entry + 16);
        const data_rva = readU32(entry + 20);
        if (data_rva == 0 or data_size < 24 or !inImage(data_rva, data_size, size_of_image)) continue;
        const cv = image[data_rva..][0..data_size];
        if (readU32(cv.ptr) != 0x53445352) continue; // "RSDS"
        const path = cv[24..];
        return .{
            .guid = cv[4..20].*,
            .age = readU32(cv.ptr + 20),
            // a plain loop: std.mem.indexOfScalar is vectorized, which adds hundreds of bytes
            .path = path[0..for (path, 0..) |c, i| {
                if (c == 0) break i;
            } else path.len],
        };
    }
    return null;
}

/// Writes a PDB's identity the way symbol stores name its directory: the GUID's fields as
/// uppercase hex, followed by the age.
pub fn writePdbKey(w: *std.Io.Writer, guid: [16]u8, age: u32) error{WriteFailed}!void {
    // the first three fields are little-endian
    for ([_]u8{ 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 }) |i| try writeHex(w, "", guid[i], 2, .upper);
    try writeHex(w, "", age, 1, .upper);
}

pub const Options = struct {
    mode: Mode,
};

pub const Mode = enum {
    /// Never reads the PDB at run time, keeping std's PDB reader out of the binary.
    small,
    /// Uses std's tracer when PDB is available (adds about 150Kb), falls back to the
    /// small wintrace otherwise.
    symbolize,
};

const mode: Mode = if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 17)
    @compileError("wintrace's crash reports need Zig 0.17.0 or later")
else if (@hasDecl(root, "wintrace_options"))
    root.wintrace_options.mode
else
    @compileError("wintrace's crash reports need the root to declare `pub const wintrace_options: wintrace.Options`");

/// For SetThreadStackGuarantee, so a stack overflow can be reported.
pub const stack_guarantee = 32 * 1024;

pub extern "kernel32" fn SetUnhandledExceptionFilter(
    filter: ?*const fn (*windows.EXCEPTION_POINTERS) callconv(.winapi) c_long,
) callconv(.winapi) ?*const anyopaque;
pub extern "kernel32" fn SetThreadStackGuarantee(size: *u32) callconv(.winapi) i32;

pub const panic = if (builtin.os.tag == .windows)
    std.debug.FullPanic(panicHandler)
else
    @compileError("wintrace.panic is only for Windows");

var panicking = false;
var reporting_exception = false;

fn panicHandler(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);
    const first_address = first_trace_addr orelse @returnAddress();
    if (!panicking) {
        panicking = true;
        var buf: [256]u8 = undefined;
        switch (mode) {
            .small => {
                var stderr = smallStderr(&buf);
                writePanic(&stderr, msg, first_address) catch {};
            },
            .symbolize => {
                if (haveSymbols()) std.debug.defaultPanic(msg, first_address);
                const stderr = std.debug.lockStderr(&buf);
                writePanic(&stderr.file_writer.interface, msg, first_address) catch {};
            },
        }
    }
    std.process.abort();
}

/// Where the small mode writes its reports: straight to the stderr handle, without std's
/// stderr lock. std.debug.lockStderr goes through std's debug io, which puts std.Io.Threaded
/// in the exe, about 300 KB that the small mode exists to avoid. build.zig's size test fails
/// if a report in the small mode reaches it again.
fn smallStderr(buffer: []u8) std.Io.Writer {
    return .{ .vtable = &.{ .drain = drainSmallStderr }, .buffer = buffer };
}

fn drainSmallStderr(w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
    try writeSmallStderr(w.buffered());
    w.end = 0;
    var written: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try writeSmallStderr(bytes);
        written += bytes.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| try writeSmallStderr(last);
    return written + splat * last.len;
}

fn writeSmallStderr(bytes: []const u8) error{WriteFailed}!void {
    const stderr = windows.peb().ProcessParameters.hStdError;
    var rest = bytes;
    while (rest.len > 0) {
        var io_status: [2]usize = undefined;
        var status = NtWriteFile(
            stderr,
            null,
            null,
            null,
            &io_status,
            rest.ptr,
            @intCast(rest.len),
            null,
            null,
        );
        if (status == status_pending) {
            // a handle opened for overlapped io, which is signaled when the write is done
            if (NtWaitForSingleObject(stderr, 0, null) != 0) return error.WriteFailed;
            status = @bitCast(@as(u32, @truncate(io_status[0])));
        }
        // no stderr, or a pipe nobody reads anymore
        if (status < 0 or io_status[1] == 0) return error.WriteFailed;
        rest = rest[io_status[1]..];
    }
}

fn writePanic(w: *std.Io.Writer, msg: []const u8, first_address: usize) error{WriteFailed}!void {
    // in pieces, here and in the other reports: std.fmt is several KB that the traces don't need
    try w.writeAll("panic: ");
    try w.writeAll(msg);
    try w.writeAll("\n");
    if (@errorReturnTrace()) |trace| if (trace.index > 0) {
        try w.writeAll("error return context:\n");
        try writeErrorReturnTrace(w, trace);
        try w.writeAll("stack trace:\n");
    };
    try w.flush();
    try writeCurrentStackTrace(w, first_address);
    try w.flush();
}

/// Reports an error returned from main like std does, then exits with 1.
pub fn exitWithErrorTrace(err: anyerror, trace: ?*std.builtin.StackTrace) noreturn {
    if (builtin.os.tag != .windows) @compileError("wintrace.exitWithErrorTrace is only for Windows");
    if (mode == .small) {
        // not std.log, its default logFn writes through std's debug io, see smallStderr
        var buf: [256]u8 = undefined;
        var stderr = smallStderr(&buf);
        write: {
            stderr.writeAll("error: ") catch break :write;
            stderr.writeAll(@errorName(err)) catch break :write;
            stderr.writeAll("\n") catch break :write;
            if (trace) |t| writeErrorReturnTrace(&stderr, t) catch break :write;
            stderr.flush() catch break :write;
        }
        std.process.exit(1);
    }
    std.log.err("{t}", .{err});
    if (trace) |t| if (mode == .symbolize and haveSymbols()) std.debug.dumpErrorReturnTrace(t) else {
        var buf: [256]u8 = undefined;
        const stderr = std.debug.lockStderr(&buf);
        const w = &stderr.file_writer.interface;
        write: {
            writeErrorReturnTrace(w, t) catch break :write;
            w.flush() catch break :write;
        }
    };
    std.process.exit(1);
}

/// For SetUnhandledExceptionFilter. Exits with the exception code.
pub fn unhandledExceptionFilter(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
    comptime {
        if (std.options.enable_segfault_handler) @compileError(
            "std's segfault handler reports exceptions before an unhandled exception filter can, " ++
                "set std_options.enable_segfault_handler to false",
        );
    }
    // from std.process.abort
    if (info.ExceptionRecord.ExceptionCode == exception_breakpoint) return exception_continue_search;
    if (reporting_exception) return exception_continue_search;
    reporting_exception = true;
    var buf: [256]u8 = undefined;
    if (mode == .small) {
        var stderr = smallStderr(&buf);
        writeExceptionReport(.{ .writer = &stderr, .mode = .no_color }, info, .wintrace) catch {};
        return exception_execute_handler;
    }
    const stderr = std.debug.lockStderr(&buf);
    defer std.debug.unlockStderr();
    if (mode == .symbolize and info.ExceptionRecord.ExceptionCode != exception_stack_overflow and haveSymbols())
        writeExceptionReport(stderr.terminal(), info, .std) catch {}
    else
        writeExceptionReport(stderr.terminal(), info, .wintrace) catch {};
    return exception_execute_handler;
}

const Tracer = enum { std, wintrace };

fn writeExceptionReport(t: std.Io.Terminal, info: *windows.EXCEPTION_POINTERS, comptime tracer: Tracer) error{WriteFailed}!void {
    const w = t.writer;
    const record = info.ExceptionRecord;
    try writeHex(w, "unhandled exception 0x", record.ExceptionCode, 8, .upper);
    switch (record.ExceptionCode) {
        exception_access_violation => if (record.NumberParameters >= 2) {
            const access = switch (record.ExceptionInformation[0]) {
                0 => "reading",
                1 => "writing",
                8 => "executing",
                else => "accessing",
            };
            try w.writeAll(" (access violation ");
            try w.writeAll(access);
            try writeHex(w, " 0x", record.ExceptionInformation[1], 1, .lower);
            try w.writeAll(")");
        },
        exception_illegal_instruction => try w.writeAll(" (illegal instruction)"),
        exception_stack_overflow => try w.writeAll(" (stack overflow)"),
        exception_int_divide_by_zero => try w.writeAll(" (integer divide by zero)"),
        else => {},
    }
    try w.writeAll(" at ");
    try writeAddress(w, @intFromPtr(record.ExceptionAddress));
    try w.writeAll("\n");
    try w.flush();
    switch (tracer) {
        .std => try std.debug.writeCurrentStackTrace(.{
            .context = &std.debug.cpu_context.fromWindowsContext(info.ContextRecord),
            .allow_unsafe_unwind = true,
        }, t),
        .wintrace => try writeStackTrace(w, info.ContextRecord),
    }
    try w.flush();
}

fn haveSymbols() bool {
    const di = std.debug.getSelfDebugInfo() catch return false;
    var arena: std.heap.ArenaAllocator = .init(std.debug.getDebugInfoAllocator());
    defer arena.deinit();
    var symbols: std.ArrayList(std.debug.Symbol) = .empty;
    di.getSymbols(std.Options.debug_io, arena.allocator(), arena.allocator(), @intFromPtr(&haveSymbols), false, &symbols) catch return false;
    return symbols.items.len > 0 and symbols.items[0].name != null;
}

fn writeErrorReturnTrace(w: *std.Io.Writer, trace: *const std.builtin.StackTrace) error{WriteFailed}!void {
    const count = @min(trace.index, trace.instruction_addresses.len);
    try writeAddresses(w, trace.instruction_addresses[0..count], .{ .truncated = trace.index > count });
}

/// Walks the stack of the calling thread one frame at a time.
const Walker = struct {
    context: windows.CONTEXT,
    history: UNWIND_HISTORY_TABLE,
    /// The committed part of this thread's stack. A frame's stack pointer outside it means the
    /// stack is corrupt, so the walk stops there rather than fault reading it.
    stack_low: usize,
    stack_high: usize,
    leaf_scan: LeafScan,
    first: bool,
    done: bool,

    fn init(walker: *Walker, context: *const windows.CONTEXT, leaf_scan: LeafScan) void {
        const tib = &windows.teb().NtTib;
        walker.* = .{
            .context = context.*,
            .history = std.mem.zeroes(UNWIND_HISTORY_TABLE),
            .stack_low = @intFromPtr(tib.StackLimit),
            .stack_high = @intFromPtr(tib.StackBase),
            .leaf_scan = leaf_scan,
            .first = true,
            .done = false,
        };
        // An exception's context usually has CONTEXT_XSTATE set, which says extended state
        // (AVX and such) follows the record in memory. This copy doesn't have it, and the
        // unwinder in an x64 process emulated on ARM64 reads it, faulting on whatever is
        // past the copy. Unwinding needs none of it.
        walker.context.ContextFlags &= ~@as(u32, switch (builtin.cpu.arch) {
            .x86_64, .x86 => 0x40,
            .aarch64 => 0x20,
            else => unreachable,
        });
    }

    /// Returns the next frame's instruction pointer, or null after the last frame.
    fn next(walker: *Walker) ?usize {
        if (walker.done) return null;
        const regs = ipSp(&walker.context);
        // An instruction pointer of 0 ends the stack, except in the first frame, which is a
        // call through a null function pointer: its caller is found like a leaf's.
        if (regs.ip == 0 and !walker.first) {
            walker.done = true;
            return null;
        }
        walker.done = !walker.unwind(regs.ip, regs.sp);
        walker.first = false;
        return regs.ip;
    }

    /// Unwinds the context to the caller of the frame at `ip` and `sp`. Returns false when it
    /// can't, which ends the walk.
    fn unwind(walker: *Walker, ip: usize, sp: usize) bool {
        if (!walker.onStack(sp, @sizeOf(usize))) return false;
        var image_base: usize = undefined;
        if (builtin.cpu.arch == .x86) {
            if (!walker.unwindFramePointer(ip, sp)) return false;
        } else if (RtlLookupFunctionEntry(ip, &image_base, &walker.history)) |function| {
            var handler_data: ?*anyopaque = null;
            var establisher_frame: usize = undefined;
            _ = RtlVirtualUnwind(unw_flag_nhandler, image_base, ip, function, &walker.context, &handler_data, &establisher_frame, null);
        } else {
            // Only a leaf function, which calls nothing, has no unwind info, so only the
            // innermost frame can be one.
            if (!walker.first) return false;
            switch (builtin.cpu.arch) {
                // The return address is on top of the stack. A few functions, like __chkstk,
                // where stack overflows usually happen, push registers first, so skip slots
                // that don't hold an address right after a call.
                .x86_64 => {
                    var slot = sp;
                    const return_address = for (0..4) |_| {
                        if (!walker.onStack(slot, @sizeOf(usize))) return false;
                        const value = @as(*const usize, @ptrFromInt(slot)).*;
                        slot += @sizeOf(usize);
                        if (isCode(value) and followsCall(value)) break value;
                    } else return false;
                    walker.context.setIp(return_address);
                    walker.context.setSp(slot);
                },
                // the return address is in the link register
                .aarch64 => walker.context.setIp(walker.context.DUMMYUNIONNAME.DUMMYSTRUCTNAME.Lr),
                else => unreachable,
            }
        }
        // The stack only grows down, so each caller's frame is above its callee's. A leaf
        // function on aarch64 needs no stack, so the innermost frame may share its caller's.
        const caller = ipSp(&walker.context);
        if (caller.sp > sp) return true;
        return caller.sp == sp and walker.first and caller.ip != ip;
    }

    /// x86 has no unwind info, so a frame's caller comes from the frame pointer chain: EBP
    /// points at the caller's saved EBP, with the return address above it.
    fn unwindFramePointer(walker: *Walker, ip: usize, sp: usize) bool {
        const bp: usize = walker.context.Ebp;
        // An exception can happen before the function has a frame of its own, at its first
        // instruction or in a leaf like __chkstk, while EBP is still its caller's. Its return
        // address is then near the top of the stack, below the caller's frame, maybe after a
        // few pushed registers as on x86_64. A function that does have a frame can have return
        // addresses there too, left by earlier calls, or one RaiseException keeps in its
        // exception record, so only one from a call to near ip counts.
        if (walker.first and walker.leaf_scan) {
            // an EBP below the stack pointer is a register in other use, not a frame
            const limit = if (bp >= sp and walker.onStack(bp, @sizeOf(usize))) bp else walker.stack_high;
            var slot = sp;
            for (0..4) |_| {
                if (slot >= limit or !walker.onStack(slot, @sizeOf(usize))) break;
                const value = @as(*const usize, @ptrFromInt(slot)).*;
                slot += @sizeOf(usize);
                if (isCode(value) and followsCall(value) and callReaches(value, ip)) {
                    walker.context.Eip = value;
                    walker.context.Esp = slot;
                    return true;
                }
            }
        }
        // a frame is above the stack pointer, like everything its function pushed
        if (bp < sp or !walker.onStack(bp, 2 * @sizeOf(usize))) return false;
        const frame: *const [2]usize = @ptrFromInt(bp);
        if (!isCode(frame[1])) return false;
        walker.context.Ebp = frame[0];
        walker.context.Eip = frame[1];
        walker.context.Esp = bp + 2 * @sizeOf(usize);
        return true;
    }

    fn onStack(walker: *const Walker, address: usize, len: usize) bool {
        return address % @sizeOf(usize) == 0 and address >= walker.stack_low and
            address <= walker.stack_high and walker.stack_high - address >= len;
    }
};

/// On x86, whether the innermost frame may not have a frame of its own yet, as at an exception
/// (see unwindFramePointer). Only x86 walks the frame pointer chain, so elsewhere it's void.
const LeafScan = if (builtin.cpu.arch == .x86) bool else void;
const no_leaf_scan = if (builtin.cpu.arch == .x86) false else {};
const yes_leaf_scan = if (builtin.cpu.arch == .x86) true else {};

/// A context's instruction and stack pointers. std's x86 getRegs has no sp before Zig 0.17.
fn ipSp(context: *const windows.CONTEXT) struct { ip: usize, sp: usize } {
    if (builtin.cpu.arch == .x86) return .{ .ip = context.Eip, .sp = context.Esp };
    const regs = context.getRegs();
    return .{ .ip = regs.ip, .sp = regs.sp };
}

/// Walks from `context`, skipping `skip` frames, and writes the first `head_frames` and last
/// `tail_frames` of the rest, with a count of those in between.
fn writeWalk(w: *std.Io.Writer, context: *const windows.CONTEXT, skip: usize, first_is_ip: bool, leaf_scan: LeafScan) error{WriteFailed}!void {
    var walker: Walker = undefined;
    walker.init(context, leaf_scan);
    for (0..skip) |_| _ = walker.next() orelse break;
    var head: [head_frames]usize = undefined;
    var tail: [tail_frames]usize = undefined;
    var count: usize = 0;
    while (count < max_walk) : (count += 1) {
        const ip = walker.next() orelse break;
        if (count < head.len) head[count] = ip else tail[(count - head.len) % tail.len] = ip;
    }
    var t: TraceWriter = .init(w);
    try t.start();
    try t.frames(head[0..@min(count, head.len)], first_is_ip);
    if (count > head.len) {
        const tail_count = @min(count - head.len, tail.len);
        const omitted = count - head.len - tail_count;
        // at max_walk the stack may go on, so the tail may not be its outermost frames
        if (count == max_walk) {
            try t.line("    ... at least ", omitted);
        } else if (omitted > 0) try t.line("    ... ", omitted);
        // the ring's oldest entry first
        const start = if (count - head.len > tail.len) (count - head.len) % tail.len else 0;
        var ordered: [tail_frames]usize = undefined;
        for (0..tail_count) |i| ordered[i] = tail[(start + i) % tail.len];
        try t.frames(ordered[0..tail_count], false);
    }
    try t.finish();
}

const TraceWriter = struct {
    w: *std.Io.Writer,
    modules: [max_modules]usize,
    module_count: usize,
    modules_dropped: bool,
    /// A run of frames at one address not written yet, which the next frames may continue.
    run_address: usize,
    run_length: usize,

    fn init(w: *std.Io.Writer) TraceWriter {
        return .{
            .w = w,
            .modules = undefined,
            .module_count = 0,
            .modules_dropped = false,
            .run_address = 0,
            .run_length = 0,
        };
    }

    fn start(t: *TraceWriter) error{WriteFailed}!void {
        try t.w.writeAll("    wintrace\n");
    }

    /// Writes one line per frame, collapsing runs of the same address, such as a stack
    /// overflow's recursion, even across calls.
    fn frames(t: *TraceWriter, addresses: []const usize, first_is_ip: bool) error{WriteFailed}!void {
        for (addresses, 0..) |address, i| {
            if (i == 0 and first_is_ip) {
                try t.endRun();
                try t.frame(address, true, 1);
            } else if (t.run_length > 0 and address == t.run_address) {
                t.run_length += 1;
            } else {
                try t.endRun();
                t.run_address = address;
                t.run_length = 1;
            }
        }
    }

    /// Writes a line that isn't a frame, after the frames before it: `text`, or `text`, then
    /// `frames` and ` frames`.
    fn line(t: *TraceWriter, text: []const u8, frames_count: ?usize) error{WriteFailed}!void {
        try t.endRun();
        try t.w.writeAll(text);
        if (frames_count) |n| {
            try writeDecimal(t.w, n);
            try t.w.writeAll(" frames");
        }
        try t.w.writeAll("\n");
    }

    fn endRun(t: *TraceWriter) error{WriteFailed}!void {
        if (t.run_length > 0) try t.frame(t.run_address, false, t.run_length);
        t.run_length = 0;
    }

    fn frame(t: *TraceWriter, address: usize, ip: bool, repeat: usize) error{WriteFailed}!void {
        try t.w.writeAll("    ");
        if (moduleBase(address)) |base| {
            try writeModuleName(t.w, base);
            try writeHex(t.w, "+0x", address - base, 1, .lower);
            const listed = for (t.modules[0..t.module_count]) |m| {
                if (m == base) break true;
            } else false;
            if (!listed) {
                if (t.module_count < t.modules.len) {
                    t.modules[t.module_count] = base;
                    t.module_count += 1;
                } else t.modules_dropped = true;
            }
        } else try writeHex(t.w, "0x", address, 1, .lower);
        if (ip) try t.w.writeAll(" (ip)");
        if (repeat > 1) {
            try t.w.writeAll(" (x");
            try writeDecimal(t.w, repeat);
            try t.w.writeAll(")");
        }
        try t.w.writeAll("\n");
    }

    /// Writes the module lines.
    fn finish(t: *TraceWriter) error{WriteFailed}!void {
        try t.endRun();
        for (t.modules[0..t.module_count]) |base| {
            try t.w.writeAll("    module ");
            try writeModuleName(t.w, base);
            if (pdbInfo(base)) |pdb| {
                try t.w.writeAll(" | ");
                try writeField(t.w, basename(u8, pdb.path));
                try t.w.writeAll(" | ");
                try writePdbKey(t.w, pdb.guid, pdb.age);
                try t.w.writeAll("\n");
            } else try t.w.writeAll(" | - | -\n");
        }
        if (t.modules_dropped) try t.w.writeAll("    ... more modules\n");
    }
};

/// Writes a name from an image's debug record, which can hold any bytes, so the line stays one
/// line with three fields.
fn writeField(w: *std.Io.Writer, name: []const u8) error{WriteFailed}!void {
    if (name.len == 0) return w.writeAll("-");
    for (name) |c| try w.writeByte(switch (c) {
        '|', '\r', '\n' => '?',
        else => c,
    });
}

fn moduleBase(address: usize) ?usize {
    var base: ?*anyopaque = null;
    _ = RtlPcToFileHeader(address, &base);
    return if (base) |b| @intFromPtr(b) else null;
}

/// Whether `address` is in a function: one with unwind info, or on x86, which has none, anywhere
/// in an executable section.
fn isCode(address: usize) bool {
    if (builtin.cpu.arch == .x86) {
        const base = moduleBase(address) orelse return false;
        return inExecutableSection(base, address - base);
    }
    var image_base: usize = undefined;
    return RtlLookupFunctionEntry(address, &image_base, null) != null;
}

/// Whether `rva` is in an executable section of the image loaded at `base`. Only reads the
/// section headers in the image's first page, which is always mapped.
fn inExecutableSection(base: usize, rva: usize) bool {
    const image: [*]const u8 = @ptrFromInt(base);
    const nt_offset = readU32(image + 0x3c);
    if (nt_offset > 4096 - 24) return false;
    const count = readU16(image + nt_offset + 6);
    const sections = nt_offset + 24 + readU16(image + nt_offset + 20);
    if (sections + @as(usize, count) * 40 > 4096) return false;
    for (0..count) |i| {
        const section = image + sections + i * 40;
        const virtual_size = readU32(section + 8);
        const virtual_address = readU32(section + 12);
        const characteristics = readU32(section + 36);
        if (characteristics & image_scn_mem_execute != 0 and rva >= virtual_address and rva - virtual_address < virtual_size)
            return true;
    }
    return false;
}

/// Whether the instruction before `address`, which isCode, is an x86 call, as it is before
/// a return address. A pushed pointer to a function usually isn't. Reading before it is safe:
/// a function is in a section, which follows the image's headers.
fn followsCall(address: usize) bool {
    const code: [*]const u8 = @ptrFromInt(address);
    // call rel32
    if ((code - 5)[0] == 0xe8) return true;
    // call r/m (FF /2), whose length its ModRM and SIB bytes give
    for (2..8) |len| {
        const op = code - len;
        const modrm = op[1];
        if (op[0] != 0xff or (modrm >> 3) & 7 != 2) continue;
        const rm = modrm & 7;
        const call_len: usize = switch (modrm >> 6) {
            0 => if (rm == 4) (if (op[2] & 7 == 5) 7 else 3) else if (rm == 5) 6 else 2,
            1 => if (rm == 4) 4 else 3,
            2 => if (rm == 4) 7 else 6,
            else => 2,
        };
        if (call_len == len) return true;
    }
    return false;
}

/// How far into a function an x86 leaf scan finds its return address: past a few pushes, or
/// in __chkstk's probing loop.
const leaf_scan_reach = 64;

/// Whether the x86 call before `return_address`, which followsCall, can be to the function at
/// `ip`, near its start. A call through a register can't be checked, so it can be, and so can
/// a call to 0, a null function pointer.
fn callReaches(return_address: usize, ip: usize) bool {
    if (ip == 0) return true;
    const code: [*]const u8 = @ptrFromInt(return_address);
    const target = if ((code - 5)[0] == 0xe8)
        return_address +% readU32(code - 4)
    else if ((code - 6)[0] == 0xff and (code - 5)[0] == 0x15)
        // call [address], through an import table
        readPointer(readU32(code - 4)) orelse return false
    else
        return true;
    if (ip >= target and ip - target < leaf_scan_reach) return true;
    // a jmp [address] thunk to an import
    if (!isCode(target)) return false;
    const thunk: [*]const u8 = @ptrFromInt(target);
    if (thunk[0] != 0xff or thunk[1] != 0x25) return false;
    const import = readPointer(readU32(thunk + 2)) orelse return false;
    return ip >= import and ip - import < leaf_scan_reach;
}

/// The pointer at `address`, when that's in a loaded image, as an import table is.
fn readPointer(address: usize) ?usize {
    if (address % @sizeOf(usize) != 0 or moduleBase(address) == null) return null;
    return @as(*const usize, @ptrFromInt(address)).*;
}

/// Calls GetModuleFileNameW, which Microsoft's "Dynamic-Link Library Best Practices" says "can
/// indirectly acquire the loader lock". That could deadlock a crash report written while
/// another thread holds it, such as during a LoadLibrary. Testing shows it doesn't, at least
/// on modern Windows: on Windows 11 it returned at once while another thread held the loader
/// lock (LdrLockLoaderLock), so we call it here.
fn writeModuleName(w: *std.Io.Writer, base: usize) error{WriteFailed}!void {
    var path_buf: [max_path]u16 = undefined;
    const len = GetModuleFileNameW(@ptrFromInt(base), &path_buf, path_buf.len);
    if (len == 0 or len == path_buf.len) return writeHex(w, "0x", base, 1, .lower);
    try writeUtf16(w, basename(u16, path_buf[0..len]));
}

// The writers below take the place of std's formatter, which would add about 1 KB.

/// Writes `prefix`, then `value` in hex with at least `width` digits.
fn writeHex(w: *std.Io.Writer, prefix: []const u8, value: u64, width: u8, case: enum { lower, upper }) error{WriteFailed}!void {
    const digits = switch (case) {
        .lower => "0123456789abcdef",
        .upper => "0123456789ABCDEF",
    };
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = value;
    while (v != 0 or buf.len - i < width) : (v >>= 4) {
        i -= 1;
        buf[i] = digits[@intCast(v & 15)];
    }
    try w.writeAll(prefix);
    try w.writeAll(buf[i..]);
}

fn writeDecimal(w: *std.Io.Writer, value: usize) error{WriteFailed}!void {
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var v = value;
    while (true) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
        if (v == 0) break;
    }
    try w.writeAll(buf[i..]);
}

/// Writes UTF-16 as UTF-8, with U+FFFD for a lone surrogate. ntdll converts it, which takes far
/// less code than encoding it here, and neither allocates nor locks.
fn writeUtf16(w: *std.Io.Writer, text: []const u16) error{WriteFailed}!void {
    var rest = text;
    while (rest.len > 0) {
        var n = @min(rest.len, 32);
        // keep a surrogate pair in one chunk
        if (n < rest.len and rest[n - 1] >= 0xd800 and rest[n - 1] < 0xdc00) n -= 1;
        var buf: [32 * 3]u8 = undefined;
        var len: u32 = 0;
        _ = RtlUnicodeToUTF8N(&buf, buf.len, &len, rest.ptr, @intCast(n * 2));
        try w.writeAll(buf[0..len]);
        rest = rest[n..];
    }
}

fn basename(comptime T: type, path: []const T) []const T {
    var start: usize = 0;
    for (path, 0..) |c, i| if (c == '\\' or c == '/') {
        start = i + 1;
    };
    return path[start..];
}

fn inImage(rva: u32, size: u32, size_of_image: u32) bool {
    return @as(u64, rva) + size <= size_of_image;
}

fn readU16(p: [*]const u8) u16 {
    return std.mem.readInt(u16, p[0..2], .little);
}
fn readU32(p: [*]const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .little);
}

/// How far into the NT headers pdbInfo reads: through the debug directory entry.
const nt_headers_read = 24 + pe_directories + 7 * 8;
/// A deep stack keeps its innermost frames, where it failed, and its outermost, where the
/// thread started and, for a stack overflow, where the recursion began.
const head_frames = 96;
const tail_frames = 32;
const max_walk = 1 << 20;
/// How deep writeCurrentStackTrace looks for first_address.
const first_address_search = 256;
const max_modules = 32;
const max_path = 260;
const unw_flag_nhandler = 0;
const image_scn_mem_execute = 0x20000000;
/// The optional header's magic for this process's images, and where its data directories start:
/// PE32 has one field fewer than PE32+.
const pe_magic: u16 = if (@sizeOf(usize) == 8) 0x20b else 0x10b;
const pe_directories: usize = if (@sizeOf(usize) == 8) 112 else 96;

/// The unwind types, which std defines only for some architectures. x86 has none.
const RUNTIME_FUNCTION = switch (builtin.cpu.arch) {
    .x86_64, .aarch64 => windows.RUNTIME_FUNCTION,
    .x86 => void,
    else => @compileError(unsupported),
};
const UNWIND_HISTORY_TABLE = switch (builtin.cpu.arch) {
    .x86_64, .aarch64 => windows.UNWIND_HISTORY_TABLE,
    .x86 => void,
    else => @compileError(unsupported),
};
const unsupported = "wintrace supports x86_64, aarch64 and x86 Windows";

// Declared here rather than taken from std, whose parameter types differ between versions.
extern "ntdll" fn RtlCaptureContext(context: *windows.CONTEXT) callconv(.winapi) void;
extern "ntdll" fn RtlLookupFunctionEntry(
    pc: usize,
    image_base: *usize,
    history: ?*UNWIND_HISTORY_TABLE,
) callconv(.winapi) ?*RUNTIME_FUNCTION;
extern "ntdll" fn RtlVirtualUnwind(
    handler_type: u32,
    image_base: usize,
    pc: usize,
    function: *RUNTIME_FUNCTION,
    context: *windows.CONTEXT,
    handler_data: *?*anyopaque,
    establisher_frame: *usize,
    context_pointers: ?*anyopaque,
) callconv(.winapi) ?*anyopaque;
extern "ntdll" fn NtWriteFile(
    file: ?*anyopaque,
    event: ?*anyopaque,
    apc_routine: ?*anyopaque,
    apc_context: ?*anyopaque,
    io_status: *[2]usize,
    buffer: [*]const u8,
    length: u32,
    byte_offset: ?*i64,
    key: ?*u32,
) callconv(.winapi) i32;
const status_pending = 0x103;
extern "ntdll" fn NtWaitForSingleObject(handle: ?*anyopaque, alertable: u8, timeout: ?*const i64) callconv(.winapi) i32;
extern "ntdll" fn RtlPcToFileHeader(pc: usize, base: *?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetModuleFileNameW(module: *anyopaque, name: [*]u16, size: u32) callconv(.winapi) u32;
extern "ntdll" fn RtlUnicodeToUTF8N(
    text: [*]u8,
    text_max: u32,
    text_len: *u32,
    wide: [*]const u16,
    wide_bytes: u32,
) callconv(.winapi) i32;

test writeCurrentStackTrace {
    const t = struct {
        var expected: usize = 0;
        noinline fn caller(w: *std.Io.Writer) !void {
            try callee(w);
            std.mem.doNotOptimizeAway(w);
        }
        noinline fn callee(w: *std.Io.Writer) !void {
            // the address in caller this returns to, which the trace must list
            expected = @returnAddress();
            try writeCurrentStackTrace(w, null);
            std.mem.doNotOptimizeAway(w);
        }
    };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try t.caller(&w);
    var line_buf: [512]u8 = undefined;
    var line: std.Io.Writer = .fixed(&line_buf);
    try writeAddress(&line, t.expected);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), line.buffered()) != null);
    // every frame is a return address
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "(ip)") == null);
    // this test binary is linked with a PDB, so its module line names it
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), ".pdb | ") != null);
}

test "writeCurrentStackTrace starts at its caller, or at first_address" {
    const First = enum { none, found, not_found };
    const t = struct {
        var return_address: usize = 0;
        noinline fn caller(w: *std.Io.Writer, first_address: First) !void {
            try callee(w, first_address);
            std.mem.doNotOptimizeAway(w);
        }
        noinline fn callee(w: *std.Io.Writer, first_address: First) !void {
            return_address = @returnAddress();
            try writeCurrentStackTrace(w, switch (first_address) {
                .none => null,
                .found => return_address,
                .not_found => 0x1234,
            });
            std.mem.doNotOptimizeAway(w);
        }
    };
    var buf: [8192]u8 = undefined;

    // the first frame is in callee, not in writeCurrentStackTrace, with no first_address or
    // one that isn't on the stack
    for ([_]First{ .none, .not_found }) |first_address| {
        var w: std.Io.Writer = .fixed(&buf);
        try t.caller(&w, first_address);
        try expectFunction(&t.callee, testFrameAddress(firstFrame(w.buffered())) orelse return error.TestUnexpectedResult);
    }

    // with first_address, callee's frame is skipped too
    var w: std.Io.Writer = .fixed(&buf);
    try t.caller(&w, .found);
    try std.testing.expectEqual(t.return_address, testFrameAddress(firstFrame(w.buffered())));
}

test "writeCurrentStackTrace finds a first_address deep in the stack" {
    const t = struct {
        var return_address: usize = 0;
        noinline fn callee(w: *std.Io.Writer) !void {
            return_address = @returnAddress();
            try recurse(w, 100);
            std.mem.doNotOptimizeAway(w);
        }
        noinline fn recurse(w: *std.Io.Writer, depth: usize) !void {
            if (depth == 0) {
                try writeCurrentStackTrace(w, return_address);
            } else try recurse(w, depth - 1);
            std.mem.doNotOptimizeAway(w);
        }
    };
    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try t.callee(&w);
    try std.testing.expectEqual(t.return_address, testFrameAddress(firstFrame(w.buffered())));
}

test writeAddresses {
    const exe = testExe();
    const a = @intFromPtr(&writeAddresses);
    const b = @intFromPtr(&writePdbKey);
    const not_in_a_module = 0x10;
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeAddresses(&w, &.{ a, a, a, b, not_in_a_module, a }, .{ .first_is_ip = true, .truncated = true });

    const pdb = pdbInfo(exe.base).?;
    var key_buf: [64]u8 = undefined;
    var key: std.Io.Writer = .fixed(&key_buf);
    try writePdbKey(&key, pdb.guid, pdb.age);
    var expected_buf: [4096]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf,
        \\    wintrace
        \\    {[n]s}+0x{[a]x} (ip)
        \\    {[n]s}+0x{[a]x} (x2)
        \\    {[n]s}+0x{[b]x}
        \\    0x10
        \\    {[n]s}+0x{[a]x}
        \\    ... more frames
        \\    module {[n]s} | {[p]s} | {[k]s}
        \\
    , .{ .n = exe.name, .a = a - exe.base, .b = b - exe.base, .p = basename(u8, pdb.path), .k = key.buffered() });
    try std.testing.expectEqualStrings(expected, w.buffered());
}

test "a deep stack keeps its innermost and outermost frames" {
    const t = struct {
        noinline fn recurse(w: *std.Io.Writer, depth: usize) !void {
            // not a tail call, so the innermost frame keeps its own return address
            if (depth == 0) try writeCurrentStackTrace(w, null) else try recurse(w, depth - 1);
            std.mem.doNotOptimizeAway(w);
        }
    };
    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try t.recurse(&w, 1000);
    const trace = w.buffered();
    // the innermost call, then the rest of the head's frames are recursive calls
    try std.testing.expect(std.mem.indexOf(u8, trace, std.fmt.comptimePrint(" (x{d})\n", .{head_frames - 1})) != null);
    const dots = std.mem.indexOf(u8, trace, "\n    ... ") orelse return error.TestUnexpectedResult;
    // the tail still has the thread's start, in kernel32
    try std.testing.expect(containsIgnoreCase(trace[dots..], "kernel32.dll+0x"));
    try std.testing.expect(containsIgnoreCase(trace[dots..], "\n    module kernel32.dll | "));
}

test "a deep stack's trace is its first 96 frames, the count left out, and its last 32" {
    const t = struct {
        var trace_buf: [16384]u8 = undefined;
        var trace: std.Io.Writer = .fixed(&trace_buf);
        var all: [2048]usize = undefined;
        var count: usize = 0;
        noinline fn recurse(depth: usize) !void {
            if (depth == 0) {
                // both walk the same stack, from the same context
                var context: windows.CONTEXT = undefined;
                RtlCaptureContext(&context);
                try writeStackTrace(&trace, &context);
                count = capture(&context, &all);
            } else try recurse(depth - 1);
            std.mem.doNotOptimizeAway(&count);
        }
    };
    try t.recurse(300);
    const n = t.count;
    try std.testing.expect(n > head_frames + tail_frames and n < t.all.len);
    var expected_buf: [16384]u8 = undefined;
    var expected: std.Io.Writer = .fixed(&expected_buf);
    var tw: TraceWriter = .init(&expected);
    try tw.start();
    try tw.frames(t.all[0..head_frames], true);
    try tw.line("    ... ", n - head_frames - tail_frames);
    try tw.frames(t.all[n - tail_frames .. n], false);
    try tw.finish();
    try std.testing.expectEqualStrings(expected.buffered(), t.trace.buffered());
}

test "writeStackTrace walks from an exception's context back into the code that raised it" {
    const t = struct {
        const code = 0xE0575401;
        var return_address: usize = 0;
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var current_buf: [8192]u8 = undefined;
        var current: std.Io.Writer = .fixed(&current_buf);
        fn handler(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
            if (info.ExceptionRecord.ExceptionCode != code) return exception_continue_search;
            writeStackTrace(&w, info.ContextRecord) catch {};
            // and from the handler itself, through the exception dispatcher
            writeCurrentStackTrace(&current, null) catch {};
            return exception_continue_execution;
        }
        noinline fn raise() void {
            return_address = @returnAddress();
            RaiseException(code, 0, 0, null);
            // not a tail call, so this function's frame is in the trace
            std.mem.doNotOptimizeAway(&return_address);
        }
    };
    const handle = AddVectoredExceptionHandler(1, &t.handler) orelse return error.TestUnexpectedResult;
    defer _ = RemoveVectoredExceptionHandler(handle);
    t.raise();
    // The faulting instruction, in RaiseException, comes first. Then its callers, not a copy
    // of the first frame from the exception record RaiseException keeps on its stack: on some
    // Windows versions a frame or more of Windows' own, then the function that called it.
    var frames = std.mem.splitScalar(u8, t.w.buffered(), '\n');
    try std.testing.expectEqualStrings("    wintrace", frames.next().?);
    const ip_line = frames.next().?;
    try std.testing.expect(std.mem.endsWith(u8, ip_line, " (ip)"));
    var frame = frames.next().?;
    try std.testing.expect(!std.mem.eql(u8, frame, ip_line[0 .. ip_line.len - " (ip)".len]));
    while (testFrameAddress(frame) == null) frame = frames.next() orelse return error.TestUnexpectedResult;
    try expectFunction(&t.raise, testFrameAddress(frame).?);
    var line_buf: [512]u8 = undefined;
    var line: std.Io.Writer = .fixed(&line_buf);
    try line.writeAll("\n    ");
    try writeAddress(&line, t.return_address);
    try line.writeAll("\n");
    try std.testing.expect(std.mem.indexOf(u8, t.w.buffered(), line.buffered()) != null);
    try std.testing.expect(std.mem.indexOf(u8, t.current.buffered(), line.buffered()) != null);
}

test "writeStackTrace walks a context whose extended state isn't there" {
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // CONTEXT_XSTATE, as in an exception's context, but the extended state that should follow
    // the record in memory is only this stack
    context.ContextFlags |= switch (builtin.cpu.arch) {
        .x86_64, .x86 => 0x40,
        .aarch64 => 0x20,
        else => unreachable,
    };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeStackTrace(&w, &context);
    try std.testing.expect(containsIgnoreCase(w.buffered(), "\n    module kernel32.dll | "));
}

test writeUtf16 {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    // 31 units, then a surrogate pair across the 32-unit chunks, an Ã©, and a lone surrogate
    const text = std.unicode.utf8ToUtf16LeStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ "\u{1F600}\u{E9}.dll") ++ [_]u16{ 0xd800, 'x' };
    try writeUtf16(&w, text);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ "\u{1F600}\u{E9}.dll\u{FFFD}x", w.buffered());
}

test writeField {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeField(&w, "a|b\r\nc.pdb");
    try w.writeAll(" ");
    try writeField(&w, "");
    try std.testing.expectEqualStrings("a?b??c.pdb -", w.buffered());
}

test "writeStackTrace walks out of a call through a null function pointer" {
    const t = struct {
        var armed = false;
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        fn handler(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
            const context = info.ContextRecord;
            if (!armed or info.ExceptionRecord.ExceptionCode != exception_access_violation or ipSp(context).ip != 0)
                return exception_continue_search;
            armed = false;
            writeStackTrace(&w, context) catch {};
            // return from the call
            switch (builtin.cpu.arch) {
                .x86_64, .x86 => testReturn(context, 0),
                .aarch64 => context.setIp(context.DUMMYUNIONNAME.DUMMYSTRUCTNAME.Lr),
                else => unreachable,
            }
            return exception_continue_execution;
        }
        noinline fn callNull() void {
            switch (builtin.cpu.arch) {
                .x86_64 => asm volatile (
                    \\xor %%eax, %%eax
                    \\call *%%rax
                    ::: .{ .rax = true, .memory = true }),
                .x86 => asm volatile (
                    \\xor %%eax, %%eax
                    \\call *%%eax
                    ::: .{ .eax = true, .memory = true }),
                .aarch64 => asm volatile (
                    \\mov x16, #0
                    \\blr x16
                    ::: .{ .x16 = true, .lr = true, .memory = true }),
                else => unreachable,
            }
            std.mem.doNotOptimizeAway(&buf);
        }
    };
    const handle = AddVectoredExceptionHandler(1, &t.handler) orelse return error.TestUnexpectedResult;
    defer _ = RemoveVectoredExceptionHandler(handle);
    t.armed = true;
    t.callNull();
    var lines = std.mem.splitScalar(u8, t.w.buffered(), '\n');
    try std.testing.expectEqualStrings("    wintrace", lines.next().?);
    try std.testing.expectEqualStrings("    0x0 (ip)", lines.next().?);
    // the function that made the call follows
    try expectFunction(&t.callNull, testFrameAddress(lines.next().?) orelse return error.TestUnexpectedResult);
}

/// A leaf function without unwind info (or on x86, without a frame) that faults, after pushing
/// `pushes` registers on x86_64 and x86, like __chkstk. The pushed values point into the image but
/// not at code, so a walk that took any address in a module for a return address would go wrong.
fn faultingLeaf(comptime pushes: enum { none, two }) type {
    return struct {
        noinline fn leaf() callconv(.naked) void {
            switch (builtin.cpu.arch) {
                .x86_64 => switch (pushes) {
                    .none => asm volatile ("ud2"),
                    .two => asm volatile (
                        \\lea __ImageBase(%%rip), %%rax
                        \\push %%rax
                        \\push %%rax
                        \\ud2
                    ),
                },
                .x86 => switch (pushes) {
                    .none => asm volatile ("ud2"),
                    // C symbols get a leading underscore on x86
                    .two => asm volatile (
                        \\push $___ImageBase
                        \\push $___ImageBase
                        \\ud2
                    ),
                },
                .aarch64 => asm volatile ("udf #0"),
                else => unreachable,
            }
        }
        const pushed: usize = switch (pushes) {
            .none => 0,
            .two => 2,
        };
    };
}

test "writeStackTrace walks out of a leaf function without unwind info" {
    inline for (.{ .none, .two }) |pushes| {
        if (pushes == .two and builtin.cpu.arch == .aarch64) continue;
        const Leaf = faultingLeaf(pushes);
        const t = struct {
            var buf: [8192]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            fn handler(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
                const context = info.ContextRecord;
                const ip = ipSp(context).ip;
                if (ip < @intFromPtr(&Leaf.leaf) or ip >= @intFromPtr(&Leaf.leaf) + 16) return exception_continue_search;
                w = .fixed(&buf);
                writeStackTrace(&w, context) catch {};
                // return from the leaf
                switch (builtin.cpu.arch) {
                    .x86_64, .x86 => testReturn(context, Leaf.pushed),
                    .aarch64 => context.setIp(context.DUMMYUNIONNAME.DUMMYSTRUCTNAME.Lr),
                    else => unreachable,
                }
                return exception_continue_execution;
            }
            noinline fn caller() void {
                // through a pointer the optimizer can't see through, so the leaf isn't inlined
                var leaf: *const fn () callconv(.c) void = @ptrCast(&Leaf.leaf);
                std.mem.doNotOptimizeAway(&leaf);
                leaf();
                std.mem.doNotOptimizeAway(&buf);
            }
        };
        // on x86 every function counts, there's no unwind info to tell a leaf apart
        if (builtin.cpu.arch != .x86) try std.testing.expect(!isCode(@intFromPtr(&Leaf.leaf)));
        const handle = AddVectoredExceptionHandler(1, &t.handler) orelse return error.TestUnexpectedResult;
        defer _ = RemoveVectoredExceptionHandler(handle);
        t.w = .fixed(&t.buf);
        t.caller();
        var lines = std.mem.splitScalar(u8, t.w.buffered(), '\n');
        try std.testing.expectEqualStrings("    wintrace", lines.next().?);
        try std.testing.expect(std.mem.endsWith(u8, lines.next().?, " (ip)"));
        // the caller's frame follows the leaf's
        try expectFunction(&t.caller, testFrameAddress(lines.next().?) orelse return error.TestUnexpectedResult);
    }
}

test "a leaf's return address is the first slot after a call, not a pushed function pointer" {
    if (builtin.cpu.arch == .aarch64) return error.SkipZigTest;
    const t = struct {
        var return_address: usize = 0;
        noinline fn callee() void {
            return_address = @returnAddress();
        }
    };
    t.callee();
    // What a leaf like __chkstk sees: a pointer to a function, such as its caller's first
    // argument, pushed above the return address.
    var stack = [_]usize{ @intFromPtr(&writePdbKey), @intFromPtr(&writeAddresses), t.return_address, 0 };
    std.mem.doNotOptimizeAway(&stack);
    try std.testing.expect(isCode(stack[0]) and isCode(stack[1]));
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // at the first instruction of the function the return address returns from; on x86_64, a
    // leaf without unwind info, as only those are scanned
    testSetIp(&context, if (builtin.cpu.arch == .x86) @intFromPtr(&t.callee) else @intFromPtr(&faultingLeaf(.none).leaf));
    testSetSp(&context, @intFromPtr(&stack));
    var addresses: [2]usize = undefined;
    try std.testing.expectEqual(2, capture(&context, &addresses));
    try std.testing.expectEqual(t.return_address, addresses[1]);
}

/// Two return addresses, each from a call to a different function.
const TestCalls = struct {
    var first: usize = 0;
    var second: usize = 0;
    noinline fn callFirst() void {
        first = @returnAddress();
    }
    noinline fn callSecond() void {
        second = @returnAddress();
    }
    noinline fn init() void {
        callFirst();
        callSecond();
    }
};

test "on x86, a stale return address on top of a framed function's stack isn't a frame" {
    if (builtin.cpu.arch != .x86) return error.SkipZigTest;
    TestCalls.init();
    // A function that faults before writing its locals, which still hold a return address
    // from an earlier call to another function, and whose frame returns to its real caller.
    var stack = [_]usize{ TestCalls.first, 0, 0, 0, 0, TestCalls.second, 0 };
    std.mem.doNotOptimizeAway(&stack);
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // in a function other than the one the stale return address returns from
    context.Eip = @intFromPtr(&writePdbKey) + 8;
    try std.testing.expect(context.Eip -% @intFromPtr(&TestCalls.callFirst) >= leaf_scan_reach);
    context.Esp = @intFromPtr(&stack);
    context.Ebp = @intFromPtr(&stack[4]);
    var addresses: [3]usize = undefined;
    try std.testing.expectEqual(2, capture(&context, &addresses));
    try std.testing.expectEqual(TestCalls.second, addresses[1]);
}

test "on x86, a leaf is found while EBP holds something other than a frame" {
    if (builtin.cpu.arch != .x86) return error.SkipZigTest;
    TestCalls.init();
    var stack = [_]usize{ TestCalls.first, 0 };
    std.mem.doNotOptimizeAway(&stack);
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // at the start of the function the return address returns from, in code that uses EBP
    // as an ordinary register
    context.Eip = @intFromPtr(&TestCalls.callFirst);
    context.Esp = @intFromPtr(&stack);
    context.Ebp = 7;
    var addresses: [2]usize = undefined;
    try std.testing.expectEqual(2, capture(&context, &addresses));
    try std.testing.expectEqual(TestCalls.first, addresses[1]);
}

test "runs of a frame are collapsed across the head and tail" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var t: TraceWriter = .init(&w);
    try t.frames(&.{ 0x10, 0x20, 0x20 }, true);
    try t.frames(&.{ 0x20, 0x30 }, false);
    try t.finish();
    try std.testing.expectEqualStrings("    0x10 (ip)\n    0x20 (x3)\n    0x30\n", w.buffered());
}

test "a trace lists the first 32 modules and says there are more" {
    // loaded without running their initialization, which a module line doesn't need
    const names = [_][]const u8{
        "user32",   "gdi32",   "advapi32", "ole32",        "oleaut32", "shell32",  "shlwapi",
        "ws2_32",   "crypt32", "comctl32", "comdlg32",     "version",  "winmm",    "dbghelp",
        "iphlpapi", "secur32", "setupapi", "wininet",      "winhttp",  "urlmon",   "uxtheme",
        "dwmapi",   "msimg32", "imm32",    "psapi",        "userenv",  "wtsapi32", "netapi32",
        "rpcrt4",   "combase", "bcrypt",   "ncrypt",       "dnsapi",   "cfgmgr32", "powrprof",
        "propsys",  "d3d11",   "dxgi",     "winspool.drv",
    };
    var addresses: [names.len + 2]usize = undefined;
    var count: usize = 0;
    for ([_]usize{ @intFromPtr(GetModuleHandleW(null).?), @intFromPtr(&RtlCaptureContext) } ++ @as([names.len]usize, @splat(0)), 0..) |known, i| {
        const base = if (i < 2) moduleBase(known).? else blk: {
            var name_buf: [64]u16 = undefined;
            const len = std.unicode.utf8ToUtf16Le(&name_buf, names[i - 2]) catch unreachable;
            name_buf[len] = 0;
            const module = LoadLibraryExW(name_buf[0..len :0], null, dont_resolve_dll_references) orelse continue;
            break :blk @intFromPtr(module);
        };
        if (std.mem.indexOfScalar(usize, addresses[0..count], base + 0x1000) != null) continue;
        addresses[count] = base + 0x1000;
        count += 1;
    }
    try std.testing.expect(count > max_modules);
    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeAddresses(&w, addresses[0..count], .{});
    // every frame is still written, with its module's name
    try std.testing.expectEqual(1 + count + max_modules + 1, std.mem.count(u8, w.buffered(), "\n"));
    try std.testing.expectEqual(max_modules, std.mem.count(u8, w.buffered(), "\n    module "));
    try std.testing.expect(std.mem.endsWith(u8, w.buffered(), "\n    ... more modules\n"));
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "    0x") == null);
}

test "writeStackTrace stops instead of faulting on a corrupt stack pointer" {
    var start: windows.CONTEXT = undefined;
    RtlCaptureContext(&start);
    // a stack whose return address points nowhere
    var junk: [64]usize = @splat(@truncate(0x4141_4141_4141_4140));
    std.mem.doNotOptimizeAway(&junk);
    const stack_high = @intFromPtr(windows.teb().NtTib.StackBase);
    // kernel space, or on x86 the reserved top 64 KB
    const high: usize = if (@sizeOf(usize) == 8) 0xffff_8000_0000_0000 else 0xffff_0000;
    // Not one just below stack_high: unwinding a frame there reads past the top of the stack,
    // which the walker can't check without parsing the frame's unwind info.
    const sps = [_]usize{ 0, 0x8, @intFromPtr(&junk) + 1, high, stack_high, @intFromPtr(&junk) };
    // a function with unwind info, at its first instruction, and a leaf without
    const ips = [_]usize{ @intFromPtr(&writePdbKey), @intFromPtr(&faultingLeaf(.none).leaf) };
    for (ips) |ip| for (sps) |sp| {
        var context = start;
        testSetIp(&context, ip);
        testSetSp(&context, sp);
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeStackTrace(&w, &context);
        try std.testing.expect(std.mem.endsWith(u8, firstFrame(w.buffered()), " (ip)"));
    };
}

test "stack use stays within its budget" {
    const t = struct {
        var buf: [16384]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const paint = 0xa5;
        const depth = 32 * 1024;
        /// Paints the stack below the caller's `top`, runs `work`, and returns how far below
        /// `top` the deepest byte it changed is.
        noinline fn measure(work: *const fn () void) usize {
            var marker: u8 = 0;
            std.mem.doNotOptimizeAway(&marker);
            const top = @intFromPtr(&marker);
            paintBelow(top);
            work();
            var a = top - depth;
            while (a < top - gap and @as(*volatile u8, @ptrFromInt(a)).* == paint) a += 1;
            return top - a;
        }
        /// Leaves this frame and paintBelow's own unpainted.
        const gap = 2048;
        noinline fn paintBelow(top: usize) void {
            // downward, so each guard page is touched in order
            var a = top - gap;
            while (a > top - depth) {
                a -= 1;
                @as(*volatile u8, @ptrFromInt(a)).* = paint;
            }
        }
        fn current() void {
            w = .fixed(&buf);
            writeCurrentStackTrace(&w, null) catch {};
        }
        fn fromContext() void {
            var context: windows.CONTEXT = undefined;
            RtlCaptureContext(&context);
            w = .fixed(&buf);
            writeStackTrace(&w, &context) catch {};
        }
        fn captured() void {
            var context: windows.CONTEXT = undefined;
            RtlCaptureContext(&context);
            var addresses: [64]usize = undefined;
            const n = capture(&context, &addresses);
            w = .fixed(&buf);
            writeAddresses(&w, addresses[0..n], .{ .first_is_ip = true, .truncated = n == addresses.len }) catch {};
        }
    };
    const works = [_]struct { name: []const u8, work: *const fn () void }{
        .{ .name = "writeCurrentStackTrace", .work = &t.current },
        .{ .name = "writeStackTrace", .work = &t.fromContext },
        .{ .name = "capture and writeAddresses", .work = &t.captured },
    };
    var ok = true;
    for (works) |work| {
        const used = t.measure(work.work);
        // a measurement this small would mean the paint never got overwritten, not a result
        try std.testing.expect(used > t.gap);
        if (used > stack_budget) {
            std.debug.print("{s} used {d} bytes of stack, over the budget of {d}\n", .{ work.name, used, stack_budget });
            ok = false;
        }
    }
    if (!ok) return error.TestUnexpectedResult;
}

test "a stack overflow is reported from a 16 KiB stack guarantee" {
    const t = struct {
        var buf: [16384]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        threadlocal var overflowing = false;
        /// Frames of 4 KiB or more probe the stack with __chkstk, so it faults there; smaller
        /// ones fault in the function's body.
        fn thread(frame_size: ?*anyopaque) callconv(.winapi) u32 {
            var size: u32 = 16 * 1024;
            if (SetThreadStackGuarantee(&size) == 0) return 1;
            overflowing = true;
            std.mem.doNotOptimizeAway(switch (@intFromPtr(frame_size)) {
                4096 => recurse(4096, 0),
                256 => recurse(256, 0),
                else => unreachable,
            });
            return 2;
        }
        /// Runs on what's left of the stack, then ends the thread, which can't continue. If
        /// the trace needs more than the guarantee, the second overflow ends the test process.
        fn handler(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
            if (info.ExceptionRecord.ExceptionCode != exception_stack_overflow or !overflowing) return exception_continue_search;
            writeStackTrace(&w, info.ContextRecord) catch {};
            ExitThread(0);
        }
        noinline fn recurse(comptime frame_size: usize, depth: usize) usize {
            var b: [frame_size]u8 = undefined;
            b[depth % b.len] = @truncate(depth);
            std.mem.doNotOptimizeAway(&b);
            return recurse(frame_size, depth + 1) + b[depth % b.len];
        }
    };
    const handle = AddVectoredExceptionHandler(1, &t.handler) orelse return error.TestUnexpectedResult;
    defer _ = RemoveVectoredExceptionHandler(handle);
    for ([_]usize{ 4096, 256 }) |frame_size| {
        t.w = .fixed(&t.buf);
        const thread = CreateThread(null, 1024 * 1024, &t.thread, @ptrFromInt(frame_size), stack_size_param_is_a_reservation, null) orelse return error.TestUnexpectedResult;
        defer _ = CloseHandle(thread);
        try std.testing.expectEqual(0, WaitForSingleObject(thread, std.math.maxInt(u32)));
        var exit_code: u32 = undefined;
        try std.testing.expect(GetExitCodeThread(thread, &exit_code) != 0);
        try std.testing.expectEqual(0, exit_code);

        const trace = t.w.buffered();
        try std.testing.expect(std.mem.endsWith(u8, firstFrame(trace), " (ip)"));
        // the recursion, collapsed, then the frames below it down to the thread's start
        try std.testing.expect(std.mem.indexOf(u8, trace, " (x") != null);
        const dots = std.mem.indexOf(u8, trace, "\n    ... ") orelse return error.TestUnexpectedResult;
        try std.testing.expect(containsIgnoreCase(trace[dots..], "kernel32.dll+0x"));
    }
}

test writePdbKey {
    // {12345678-9ABC-DEF0-1122-334455667788} as an image stores it: the first three fields
    // little-endian, the last eight bytes in order
    const guid = [16]u8{ 0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePdbKey(&w, guid, 42);
    try std.testing.expectEqualStrings("123456789ABCDEF011223344556677882A", w.buffered());
}

test pdbInfo {
    const pdb = pdbInfo(testExe().base) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.ascii.endsWithIgnoreCase(pdb.path, ".pdb"));
    try std.testing.expect(pdb.age > 0);
    try std.testing.expect(!std.mem.allEqual(u8, &pdb.guid, 0));
}

test "pdbInfo rejects malformed images" {
    const Image = struct {
        bytes: [8192]u8 align(16),

        fn init() @This() {
            var image: @This() = .{ .bytes = @splat(0) };
            const b = &image.bytes;
            b[0..2].* = "MZ".*;
            std.mem.writeInt(u32, b[0x3c..0x40], 0x80, .little);
            b[0x80..0x84].* = "PE\x00\x00".*;
            const optional = 0x80 + 24;
            // this process's kind, PE32+ or PE32
            std.mem.writeInt(u16, b[optional..][0..2], pe_magic, .little);
            std.mem.writeInt(u32, b[optional + 56 ..][0..4], b.len, .little); // SizeOfImage
            std.mem.writeInt(u32, b[optional + pe_directories - 4 ..][0..4], 16, .little); // NumberOfRvaAndSizes
            std.mem.writeInt(u32, b[optional + pe_directories + 6 * 8 ..][0..4], 0x400, .little);
            std.mem.writeInt(u32, b[optional + pe_directories + 6 * 8 + 4 ..][0..4], 28, .little);
            std.mem.writeInt(u32, b[0x400 + 12 ..][0..4], 2, .little); // CODEVIEW
            std.mem.writeInt(u32, b[0x400 + 16 ..][0..4], 24 + 5, .little); // SizeOfData
            std.mem.writeInt(u32, b[0x400 + 20 ..][0..4], 0x500, .little);
            b[0x500..0x504].* = "RSDS".*;
            b[0x504..0x514].* = @splat(0xab);
            std.mem.writeInt(u32, b[0x514..0x518], 7, .little);
            // no NUL within SizeOfData
            b[0x518..0x521].* = "a.pdbjunk".*;
            return image;
        }
        fn info(image: *const @This()) ?PdbInfo {
            return pdbInfo(@intFromPtr(&image.bytes));
        }
        fn set(image: *@This(), offset: usize, value: u32) void {
            std.mem.writeInt(u32, image.bytes[offset..][0..4], value, .little);
        }
    };
    const optional = 0x80 + 24;

    var image: Image = .init();
    const good = image.info() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("a.pdb", good.path);
    try std.testing.expectEqual(7, good.age);

    image = .init();
    image.set(0x3c, 0x10000); // NT headers past the first page
    try std.testing.expect(image.info() == null);

    image = .init();
    image.set(optional + pe_directories - 4, 6); // no debug directory
    try std.testing.expect(image.info() == null);

    image = .init();
    image.set(optional + pe_directories + 6 * 8, 8192 - 4); // debug directory past the image's end
    try std.testing.expect(image.info() == null);

    image = .init();
    // the other bitness's magic, which this process never loads
    std.mem.writeInt(u16, image.bytes[optional..][0..2], 0x20b ^ 0x10b ^ pe_magic, .little);
    try std.testing.expect(image.info() == null);

    image = .init();
    image.set(0x400 + 20, 8192 - 8); // record past the image's end
    try std.testing.expect(image.info() == null);

    image = .init();
    image.set(0x400 + 16, 20); // record too small for its own header
    try std.testing.expect(image.info() == null);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

/// The line after a trace's header.
fn firstFrame(trace: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, trace, '\n');
    _ = lines.next();
    return lines.next() orelse "";
}

/// Expects the return address `address` to be in `function`, from the call it returns from.
fn expectFunction(function: *const anyopaque, address: usize) !void {
    if (builtin.cpu.arch == .x86) {
        // No function table to look it up in, but the tests keep frame pointers, so a function
        // starts with push %ebp; mov %esp, %ebp: the nearest one before the call is its start.
        try std.testing.expect(followsCall(address));
        const code: [*]const u8 = @ptrFromInt(address);
        const start = for (1..4096) |back| {
            if (std.mem.eql(u8, (code - back)[0..3], "\x55\x89\xe5")) break address - back;
        } else return error.TestUnexpectedResult;
        try std.testing.expectEqual(@intFromPtr(function), start);
        return;
    }
    var image_base: usize = undefined;
    const entry = RtlLookupFunctionEntry(address - 1, &image_base, null) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@intFromPtr(function), image_base + entry.BeginAddress);
}

/// The address a `    <test exe>+0xoffset` line stands for.
fn testFrameAddress(line: []const u8) ?usize {
    const exe = testExe();
    const rest = std.mem.trimStart(u8, line, " ");
    if (!std.mem.startsWith(u8, rest, exe.name) or !std.mem.startsWith(u8, rest[exe.name.len..], "+0x")) return null;
    const hex = rest[exe.name.len + 3 ..];
    return exe.base + (std.fmt.parseInt(usize, hex[0 .. std.mem.indexOfScalar(u8, hex, ' ') orelse hex.len], 16) catch return null);
}

fn testExe() struct { base: usize, name: []const u8 } {
    const S = struct {
        var name_buf: [max_path * 3]u8 = undefined;
    };
    const base = GetModuleHandleW(null).?;
    var path: [max_path]u16 = undefined;
    const len = GetModuleFileNameW(base, &path, path.len);
    const name = basename(u16, path[0..len]);
    const n = std.unicode.utf16LeToUtf8(&S.name_buf, name) catch unreachable;
    return .{ .base = @intFromPtr(base), .name = S.name_buf[0..n] };
}

/// std's x86 CONTEXT has no setIp or setSp.
fn testSetIp(context: *windows.CONTEXT, ip: usize) void {
    if (builtin.cpu.arch == .x86) context.Eip = ip else context.setIp(ip);
}
fn testSetSp(context: *windows.CONTEXT, sp: usize) void {
    if (builtin.cpu.arch == .x86) context.Esp = sp else context.setSp(sp);
}

/// Returns from an x86_64 or x86 function that faulted after pushing `pushed` values.
fn testReturn(context: *windows.CONTEXT, pushed: usize) void {
    const sp = ipSp(context).sp + pushed * @sizeOf(usize);
    testSetIp(context, @as(*const usize, @ptrFromInt(sp)).*);
    testSetSp(context, sp + @sizeOf(usize));
}

test "a crash report: a stack overflow's uses at most half the stack guarantee" {
    if (builtin.zig_version.minor < 17) return error.SkipZigTest;
    const t = struct {
        var buf: [16384]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var result: error{WriteFailed}!void = undefined;
        var used: usize = 0;
        threadlocal var overflowing = false;
        fn thread(_: ?*anyopaque) callconv(.winapi) u32 {
            var guarantee: u32 = stack_guarantee;
            if (SetThreadStackGuarantee(&guarantee) == 0) return 2;
            overflowing = true;
            std.mem.doNotOptimizeAway(recurse(0));
            return 1;
        }
        /// Vectored, since the test runner's handler runs before an unhandled exception filter.
        fn handler(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
            if (info.ExceptionRecord.ExceptionCode != exception_stack_overflow or !overflowing) return exception_continue_search;
            // the lowest byte of the pattern the report changes is how deep it went
            var marker: u8 = 0;
            const top = @intFromPtr(&marker) - 1024;
            const low = @intFromPtr(windows.teb().NtTib.StackLimit);
            const free: [*]volatile u8 = @ptrFromInt(low);
            @memset(free[0 .. top - low], 0xaa);
            result = writeExceptionReport(.{ .writer = &w, .mode = .no_color }, info, .wintrace);
            const deepest = for (low..top) |a| {
                if (free[a - low] != 0xaa) break a;
            } else top;
            used = @intFromPtr(&marker) - deepest;
            ExitThread(0);
        }
        noinline fn recurse(depth: usize) usize {
            var b: [4096]u8 = undefined;
            b[depth % b.len] = @truncate(depth);
            std.mem.doNotOptimizeAway(&b);
            return recurse(depth + 1) + b[depth % b.len];
        }
    };
    const handle = AddVectoredExceptionHandler(1, &t.handler) orelse return error.TestUnexpectedResult;
    defer _ = RemoveVectoredExceptionHandler(handle);
    const thread = CreateThread(null, 1024 * 1024, &t.thread, null, stack_size_param_is_a_reservation, null) orelse return error.TestUnexpectedResult;
    defer _ = CloseHandle(thread);
    try std.testing.expectEqual(0, WaitForSingleObject(thread, std.math.maxInt(u32)));
    var exit_code: u32 = undefined;
    try std.testing.expect(GetExitCodeThread(thread, &exit_code) != 0);
    try std.testing.expectEqual(0, exit_code);
    try t.result;
    if (t.used > stack_guarantee / 2) {
        std.debug.print("the report used {d} bytes of stack, over half the guarantee of {d}\n", .{ t.used, stack_guarantee });
        return error.TestUnexpectedResult;
    }
    const report = t.w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, report, "unhandled exception 0xC00000FD (stack overflow) at "));
    try std.testing.expect(std.mem.indexOf(u8, report, " (x") != null);
    try std.testing.expect(containsIgnoreCase(report, "\n    kernel32.dll+0x"));
}

test "a crash report: an exception's, with either trace, and what was accessed" {
    if (builtin.zig_version.minor < 17) return error.SkipZigTest;
    try std.testing.expect(haveSymbols());
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    var record: windows.EXCEPTION_RECORD = .{
        .ExceptionCode = exception_access_violation,
        .ExceptionFlags = 0,
        .ExceptionRecord = undefined,
        .ExceptionAddress = @ptrFromInt(ipSp(&context).ip),
        .NumberParameters = 2,
        .ExceptionInformation = .{ 1, 8 } ++ @as([13]usize, @splat(0)),
    };
    var info: windows.EXCEPTION_POINTERS = .{ .ExceptionRecord = &record, .ContextRecord = &context };
    inline for (.{ Tracer.std, Tracer.wintrace }) |tracer| {
        var buf: [16384]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeExceptionReport(.{ .writer = &w, .mode = .no_color }, &info, tracer);
        const report = w.buffered();
        try std.testing.expect(std.mem.startsWith(u8, report, "unhandled exception 0xC0000005 (access violation writing 0x8) at "));
        // on x86 the context is in the test runner, not this test
        try std.testing.expectEqual(tracer == .std, std.mem.indexOf(u8, report, ".zig:") != null);
        try std.testing.expectEqual(tracer == .wintrace, std.mem.indexOf(u8, report, "\n    wintrace\n") != null);
    }
}

test "a crash report: a panic's" {
    if (builtin.zig_version.minor < 17) return error.SkipZigTest;
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePanic(&w, "boom", @returnAddress());
    try std.testing.expect(std.mem.startsWith(u8, w.buffered(), "panic: boom\n    wintrace\n"));
}

const exception_continue_search = 0;
const exception_continue_execution = -1;
const exception_execute_handler = 1;
const exception_breakpoint = 0x80000003;
const exception_stack_overflow = 0xC00000FD;
const exception_access_violation = 0xC0000005;
const exception_illegal_instruction = 0xC000001D;
const exception_int_divide_by_zero = 0xC0000094;
/// Stack the tracing functions may use, ntdll's included: about 2 KiB more than they use on
/// Windows 11 x64, for differences between Windows versions. Well under the 16 KiB guarantee
/// the overflow test uses.
// Zig 0.17 spells the mode .debug
const stack_budget: usize = if (std.ascii.eqlIgnoreCase(@tagName(builtin.mode), "debug")) 12 * 1024 else 10 * 1024;
const stack_size_param_is_a_reservation = 0x10000;
const dont_resolve_dll_references = 0x1;
extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: ?*anyopaque, flags: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn AddVectoredExceptionHandler(
    first: u32,
    handler: *const fn (*windows.EXCEPTION_POINTERS) callconv(.winapi) c_long,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn RemoveVectoredExceptionHandler(handle: *anyopaque) callconv(.winapi) u32;
extern "kernel32" fn RaiseException(code: u32, flags: u32, count: u32, args: ?[*]const usize) callconv(.winapi) void;
extern "kernel32" fn CreateThread(
    attributes: ?*anyopaque,
    stack_size: usize,
    start: *const fn (?*anyopaque) callconv(.winapi) u32,
    parameter: ?*anyopaque,
    flags: u32,
    id: ?*u32,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WaitForSingleObject(handle: *anyopaque, milliseconds: u32) callconv(.winapi) u32;
extern "kernel32" fn GetExitCodeThread(thread: *anyopaque, code: *u32) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: *anyopaque) callconv(.winapi) i32;
extern "kernel32" fn ExitThread(code: u32) callconv(.winapi) noreturn;

const builtin = @import("builtin");
const root = @import("root");
const std = @import("std");
const windows = std.os.windows;
