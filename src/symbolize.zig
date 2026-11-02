//! wintrace-symbolize: adds function names and source lines to wintrace traces.
//!
//!     wintrace-symbolize <trace-file> <pdb>...
//!
//! A trace file of `-` reads standard input.
//!
//! The trace file can be a whole log; each trace in it is symbolized on its own, and every
//! other line is copied unchanged. A frame is matched to a PDB by the identity on its trace's
//! `module` lines, so a PDB from a different build is never used by mistake. Only when no
//! trace in the file has `module` lines are frames matched by file name instead. A log line
//! written into the middle of a trace splits it, and the part without `module` lines isn't
//! symbolized.
//!
//! Uses dbghelp.dll, which ships with Windows, and needs only the PDBs, not the images. Exits
//! with 2 for bad arguments and 1 when a PDB couldn't be loaded or anything else failed.

const usage = "usage: wintrace-symbolize <trace-file | -> <pdb>...\n";

pub fn main() void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();

    var argc: c_int = 0;
    const argv = CommandLineToArgvW(GetCommandLineW(), &argc) orelse fatal("CommandLineToArgvW failed, error={d}", .{GetLastError()});
    const args = argv[1..@intCast(argc)];
    if (args.len >= 1 and isHelp(std.mem.span(args[0]))) {
        writeOutput(GetStdHandle(std_output_handle), arena, usage);
        ExitProcess(0);
    }
    if (args.len < 2) {
        writeOutput(GetStdHandle(std_error_handle), arena, usage);
        ExitProcess(2);
    }

    const trace = decode(arena, readFile(arena, std.mem.span(args[0]))) catch fatal("out of memory", .{});
    var pdb_paths: std.ArrayList([:0]const u16) = .empty;
    for (args[1..]) |a| pdb_paths.append(arena, std.mem.span(a)) catch fatal("out of memory", .{});
    var out: std.Io.Writer.Allocating = .init(arena);
    var diag: std.Io.Writer.Allocating = .init(arena);
    const all_loaded = symbolize(arena, trace, pdb_paths.items, &out.writer, &diag.writer) catch |e| fatal("{t}", .{e});
    writeOutput(GetStdHandle(std_error_handle), arena, diag.written());
    writeOutput(GetStdHandle(std_output_handle), arena, out.written());
    ExitProcess(if (all_loaded) 0 else 1);
}

const Error = error{ WriteFailed, OutOfMemory, SymInitializeFailed };

/// Writes `trace` to `w` with each frame symbolized from `pdb_paths`, and a line to `diag` for
/// each PDB that couldn't be loaded. Returns whether all of them were.
fn symbolize(
    arena: std.mem.Allocator,
    trace: []const u8,
    pdb_paths: []const [:0]const u16,
    w: *std.Io.Writer,
    diag: *std.Io.Writer,
) Error!bool {
    // dbghelp keys its state on a process handle. Nothing is read from this process; every
    // module is loaded from a PDB at a made-up base.
    const process: windows.HANDLE = @ptrFromInt(0x5754); // "WT"
    _ = SymSetOptions(symopt_undname | symopt_load_lines | symopt_fail_critical_errors | symopt_no_prompts);
    if (0 == SymInitializeW(process, null, 0)) return error.SymInitializeFailed;
    defer _ = SymCleanup(process);

    var all_loaded = true;
    var pdbs: std.ArrayList(Pdb) = .empty;
    for (pdb_paths, 0..) |path, i| {
        // Each PDB gets a 4 GiB range, the most a PE image can span, so no offset reaches
        // the next one's.
        const base: u64 = (@as(u64, max_image_size) + 1) * (i + 1);
        if (0 == SymLoadModuleExW(process, null, path, null, base, max_image_size, null, 0)) {
            // dbghelp sets no error for a file that isn't a PDB or an image
            const code = GetLastError();
            if (code == 0) {
                try diag.print("wintrace-symbolize: can't load {f}: not a PDB\n", .{std.unicode.fmtUtf16Le(path)});
            } else try diag.print("wintrace-symbolize: can't load {f}, error={d}\n", .{ std.unicode.fmtUtf16Le(path), code });
            all_loaded = false;
            continue;
        }
        var info: IMAGEHLP_MODULEW64 = std.mem.zeroes(IMAGEHLP_MODULEW64);
        info.SizeOfStruct = @sizeOf(IMAGEHLP_MODULEW64);
        if (0 == SymGetModuleInfoW64(process, base, &info)) {
            try diag.print("wintrace-symbolize: can't read {f}, error={d}\n", .{ std.unicode.fmtUtf16Le(path), GetLastError() });
            all_loaded = false;
            continue;
        }
        var key: std.Io.Writer.Allocating = .init(arena);
        try wintrace.writePdbKey(&key.writer, @bitCast(info.PdbSig70), info.PdbAge);
        const name = try std.unicode.wtf16LeToWtf8Alloc(arena, basename(u16, path));
        try pdbs.append(arena, .{ .base = base, .key = key.written(), .name = name });
    }

    const lines = try splitLines(arena, trace);
    // every module named on a module line anywhere in the file
    var listed: std.StringHashMapUnmanaged(void) = .empty;
    for (lines) |line| if (parseModuleLine(line.text)) |m| try listed.put(arena, m.name, {});
    var i: usize = 0;
    while (i < lines.len) {
        if (classify(lines[i].text) == .other) {
            try w.print("{s}{s}", .{ lines[i].text, lines[i].end });
            i += 1;
            continue;
        }
        // A trace is a run of its lines that ends before the next header or after its module
        // lines, so traces written back to back are still told apart.
        var end = i;
        var in_modules = false;
        while (end < lines.len) : (end += 1) {
            const kind = classify(lines[end].text);
            if (kind == .other or (kind == .header and end > i)) break;
            const module_section = kind == .module or kind == .more_modules;
            if (in_modules and !module_section) break;
            in_modules = module_section;
        }
        try writeTrace(arena, process, pdbs.items, &listed, lines[i..end], w);
        i = end;
    }
    return all_loaded;
}

const Pdb = struct { base: u64, key: []const u8, name: []const u8 };

/// A PDB key a trace's module line gives for a module name, or why it can't be used.
const ModuleKey = union(enum) {
    key: struct { key: []const u8, pdb: ?[]const u8 },
    /// The image had no PDB identity, such as a stripped one.
    none,
    /// Two modules in the trace have this name, so its frames can't be told apart.
    ambiguous,
};

fn writeTrace(
    arena: std.mem.Allocator,
    process: windows.HANDLE,
    pdbs: []const Pdb,
    listed: *const std.StringHashMapUnmanaged(void),
    lines: []const Line,
    w: *std.Io.Writer,
) Error!void {
    var modules: std.StringHashMapUnmanaged(ModuleKey) = .empty;
    for (lines) |line| {
        const m = parseModuleLine(line.text) orelse continue;
        const value: ModuleKey = if (m.key) |k| .{ .key = .{ .key = k, .pdb = m.pdb } } else .none;
        const entry = try modules.getOrPut(arena, m.name);
        if (!entry.found_existing) {
            entry.value_ptr.* = value;
        } else if (!sameKey(entry.value_ptr.*, value)) {
            entry.value_ptr.* = .ambiguous;
        }
    }
    for (lines) |line| {
        try w.writeAll(line.text);
        if (parseFrame(line.text)) |frame| {
            const eol = if (line.end.len > 0) line.end else "\n";
            if (modules.count() > 0) {
                if (findPdb(pdbs, &modules, frame.module)) |pdb| {
                    try writeFrameSymbols(w, process, pdb, frame, eol);
                } else |e| try w.print(" ({s})", .{switch (e) {
                    error.NoPdb => "no pdb",
                    error.Mismatch => "pdb is from a different build",
                    error.NotListed => "module not listed in the trace",
                    error.NoIdentity => "image has no pdb identity",
                    error.Ambiguous => "two modules in the trace have this name",
                }});
            } else if (listed.count() > 0) {
                // Part of a trace split by another line, whose module lines say which build
                // it's from. A line that names no listed module may not be a frame at all.
                if (listed.contains(frame.module)) try w.writeAll(" (no module lines in this part of the trace)");
            } else {
                // No trace in the file has module lines: by name, ignoring case and extension.
                // A line that matches no PDB is left alone, as it may not be a frame at all.
                for (pdbs) |p| if (std.ascii.eqlIgnoreCase(stem(p.name), stem(frame.module))) {
                    try writeFrameSymbols(w, process, p, frame, eol);
                    break;
                };
            }
        }
        try w.writeAll(line.end);
    }
}

fn sameKey(a: ModuleKey, b: ModuleKey) bool {
    return switch (a) {
        .key => |k| b == .key and std.mem.eql(u8, k.key, b.key.key),
        .none => b == .none,
        .ambiguous => false,
    };
}

fn writeFrameSymbols(w: *std.Io.Writer, process: windows.HANDLE, pdb: Pdb, frame: Frame, eol: []const u8) error{WriteFailed}!void {
    // A return address points after its call; the byte before it is in the call, so its
    // function and line are the call's.
    if (frame.offset > max_image_size or (!frame.ip and frame.offset == 0)) return w.writeAll(" (offset outside module)");
    try writeSymbols(w, process, pdb.base + if (frame.ip) frame.offset else frame.offset - 1, eol);
}

fn findPdb(
    pdbs: []const Pdb,
    modules: *const std.StringHashMapUnmanaged(ModuleKey),
    module: []const u8,
) error{ NoPdb, Mismatch, NotListed, NoIdentity, Ambiguous }!Pdb {
    const k = switch (modules.get(module) orelse return error.NotListed) {
        .key => |k| k,
        .none => return error.NoIdentity,
        .ambiguous => return error.Ambiguous,
    };
    for (pdbs) |p| if (std.mem.eql(u8, p.key, k.key)) return p;
    // a PDB with the module's name is the right PDB of another build
    for (pdbs) |p| {
        if (std.ascii.eqlIgnoreCase(stem(p.name), stem(module)) or
            (k.pdb != null and std.ascii.eqlIgnoreCase(p.name, k.pdb.?))) return error.Mismatch;
    }
    return error.NoPdb;
}

/// Writes ` in function (file:line)` for `address`, then a line for each function it was
/// inlined into, ending with the function the code physically belongs to.
fn writeSymbols(w: *std.Io.Writer, process: windows.HANDLE, address: u64, eol: []const u8) error{WriteFailed}!void {
    var context: u32 = 0;
    var inline_printed: u32 = 0;
    const inline_count = SymAddrIncludeInlineTrace(process, address);
    var queried = false;
    if (inline_count > 0) {
        var frame_index: u32 = 0;
        queried = 0 != SymQueryInlineTrace(process, address, 0, address, address, &context, &frame_index);
        if (queried) {
            for (0..inline_count) |i| {
                var sym: SymbolBuf = .init;
                var displacement: u64 = 0;
                const ctx = context + @as(u32, @intCast(i));
                if (0 == SymFromInlineContextW(process, address, ctx, &displacement, &sym.info)) break;
                if (inline_printed == 0) try w.writeAll(" in ") else try w.print("{s}        inlined into ", .{eol});
                try w.print("{f}", .{std.unicode.fmtUtf16Le(sym.name())});
                try writeLine(w, process, address, ctx);
                inline_printed += 1;
            }
        }
    }
    var sym: SymbolBuf = .init;
    var displacement: u64 = 0;
    // Past the end of a function of known size is padding or another image's code, not it.
    if (0 == SymFromAddrW(process, address, &displacement, &sym.info) or (sym.info.Size != 0 and displacement >= sym.info.Size)) {
        if (inline_printed == 0) try w.writeAll(" (no symbol)");
        return;
    }
    if (inline_printed == 0) try w.writeAll(" in ") else try w.print("{s}        inlined into ", .{eol});
    try w.print("{f}+0x{x}", .{ std.unicode.fmtUtf16Le(sym.name()), displacement });
    // With inlined frames that couldn't be listed, the address's line is an inlined function's,
    // not this one's, so there's none to give.
    if (queried) {
        // the context after the inlined frames is the physical function's
        try writeLine(w, process, address, context + inline_count);
    } else if (inline_count == 0) {
        var line: IMAGEHLP_LINEW64 = std.mem.zeroes(IMAGEHLP_LINEW64);
        line.SizeOfStruct = @sizeOf(IMAGEHLP_LINEW64);
        var line_displacement: u32 = 0;
        if (0 != SymGetLineFromAddrW64(process, address, &line_displacement, &line)) try writeFileLine(w, line);
    }
}

fn writeLine(w: *std.Io.Writer, process: windows.HANDLE, address: u64, inline_context: u32) error{WriteFailed}!void {
    var line: IMAGEHLP_LINEW64 = std.mem.zeroes(IMAGEHLP_LINEW64);
    line.SizeOfStruct = @sizeOf(IMAGEHLP_LINEW64);
    var displacement: u32 = 0;
    if (0 != SymGetLineFromInlineContextW(process, address, inline_context, 0, &displacement, &line)) try writeFileLine(w, line);
}

fn writeFileLine(w: *std.Io.Writer, line: IMAGEHLP_LINEW64) error{WriteFailed}!void {
    const file = line.FileName orelse return;
    try w.print(" ({f}:{d})", .{ std.unicode.fmtUtf16Le(std.mem.span(file)), line.LineNumber });
}

const Line = struct {
    text: []const u8,
    /// `\n`, `\r\n`, or empty for a last line without one
    end: []const u8,
};

fn splitLines(arena: std.mem.Allocator, text: []const u8) error{OutOfMemory}![]const Line {
    var lines: std.ArrayList(Line) = .empty;
    var rest = text;
    while (rest.len > 0) {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse {
            try lines.append(arena, .{ .text = rest, .end = "" });
            break;
        };
        const text_end = if (nl > 0 and rest[nl - 1] == '\r') nl - 1 else nl;
        try lines.append(arena, .{ .text = rest[0..text_end], .end = rest[text_end .. nl + 1] });
        rest = rest[nl + 1 ..];
    }
    return lines.items;
}

const Kind = enum { header, frame, address, omitted, module, more_modules, other };

/// What a line of a trace is; see the format in wintrace.zig.
fn classify(line: []const u8) Kind {
    if (!std.mem.startsWith(u8, line, indent)) return .other;
    if (std.mem.eql(u8, line, indent ++ "wintrace")) return .header;
    if (parseModuleLine(line) != null) return .module;
    if (std.mem.eql(u8, line, indent ++ "... more modules")) return .more_modules;
    if (std.mem.startsWith(u8, line, indent ++ "...")) return .omitted;
    if (parseFrame(line) != null) return .frame;
    const rest = stripSuffixes(line[indent.len..]).text;
    if (std.mem.startsWith(u8, rest, "0x") and rest.len > 2 and isHex(rest[2..])) return .address;
    return .other;
}

const Frame = struct { module: []const u8, offset: u64, ip: bool };

/// Parses `    <module>+0x<offset>`, with an optional ` (ip)` or ` (xN)`. The module name may
/// contain spaces and even `+0x`.
fn parseFrame(line: []const u8) ?Frame {
    if (!std.mem.startsWith(u8, line, indent)) return null;
    const stripped = stripSuffixes(line[indent.len..]);
    const rest = stripped.text;
    if (rest.len == 0 or rest[0] == ' ') return null;
    const plus = std.mem.lastIndexOf(u8, rest, "+0x") orelse return null;
    const hex = rest[plus + 3 ..];
    if (plus == 0 or hex.len == 0 or hex.len > 16 or !isHex(hex)) return null;
    return .{
        .module = rest[0..plus],
        .offset = std.fmt.parseInt(u64, hex, 16) catch unreachable,
        .ip = stripped.ip,
    };
}

fn stripSuffixes(text: []const u8) struct { text: []const u8, ip: bool } {
    var rest = text;
    if (std.mem.endsWith(u8, rest, " (ip)")) return .{ .text = rest[0 .. rest.len - 5], .ip = true };
    if (std.mem.endsWith(u8, rest, ")")) {
        if (std.mem.lastIndexOf(u8, rest, " (x")) |p| {
            const digits = rest[p + 3 .. rest.len - 1];
            if (digits.len > 0 and std.mem.indexOfNone(u8, digits, "0123456789") == null) rest = rest[0..p];
        }
    }
    return .{ .text = rest, .ip = false };
}

const ModuleLine = struct { name: []const u8, pdb: ?[]const u8, key: ?[]const u8 };

/// Parses `    module <module> | <pdb> | <key>`, where `-` means none.
fn parseModuleLine(line: []const u8) ?ModuleLine {
    const prefix = indent ++ "module ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    var fields = std.mem.splitScalar(u8, line[prefix.len..], '|');
    const name = std.mem.trim(u8, fields.next().?, " ");
    const pdb = std.mem.trim(u8, fields.next() orelse return null, " ");
    const key = std.mem.trim(u8, fields.next() orelse return null, " ");
    if (fields.next() != null or name.len == 0 or pdb.len == 0) return null;
    if (!std.mem.eql(u8, key, "-") and (key.len < 33 or !isHex(key))) return null;
    return .{
        .name = name,
        .pdb = if (std.mem.eql(u8, pdb, "-")) null else pdb,
        .key = if (std.mem.eql(u8, key, "-")) null else key,
    };
}

const indent = "    ";

fn isHex(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn stem(name: []const u8) []const u8 {
    return name[0 .. std.mem.lastIndexOfScalar(u8, name, '.') orelse name.len];
}

fn basename(comptime T: type, path: []const T) []const T {
    const i = std.mem.lastIndexOfAny(T, path, &[_]T{ '\\', '/' }) orelse return path;
    return path[i + 1 ..];
}

fn isHelp(arg: []const u16) bool {
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    return std.mem.eql(u16, arg, L("-h")) or std.mem.eql(u16, arg, L("--help")) or std.mem.eql(u16, arg, L("/?"));
}

/// The trace file's text as UTF-8. A file starting with a UTF-16 byte order mark, such as
/// Windows PowerShell's `>` writes, is converted; a UTF-8 one is skipped.
fn decode(arena: std.mem.Allocator, bytes: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.startsWith(u8, bytes, "\xEF\xBB\xBF")) return bytes[3..];
    const endian: std.builtin.Endian = if (std.mem.startsWith(u8, bytes, "\xFF\xFE"))
        .little
    else if (std.mem.startsWith(u8, bytes, "\xFE\xFF"))
        .big
    else
        return bytes;
    const units = try arena.alloc(u16, (bytes.len - 2) / 2);
    for (units, 0..) |*u, i| u.* = std.mem.readInt(u16, bytes[2 + 2 * i ..][0..2], endian);
    return std.unicode.wtf16LeToWtf8Alloc(arena, units);
}

/// Reads the file at `path`, or standard input for `-`, to its end.
fn readFile(arena: std.mem.Allocator, path: [:0]const u16) []const u8 {
    const stdin = std.mem.eql(u16, path, std.unicode.utf8ToUtf16LeStringLiteral("-"));
    // shared with a process that still has the log open for writing
    const file = if (stdin) GetStdHandle(std_input_handle) else CreateFileW(path, generic_read, file_share_read | file_share_write | file_share_delete, null, open_existing, 0, null);
    if (file == windows.INVALID_HANDLE_VALUE) fatal("can't open {f}, error={d}", .{ std.unicode.fmtUtf16Le(path), GetLastError() });
    var data: std.ArrayList(u8) = .empty;
    while (true) {
        data.ensureUnusedCapacity(arena, 1 << 16) catch fatal("out of memory", .{});
        const free = data.allocatedSlice()[data.items.len..];
        var read: u32 = 0;
        if (0 == ReadFile(file, free.ptr, @intCast(@min(free.len, 1 << 30)), &read, null)) {
            // the end of a pipe
            if (GetLastError() == error_broken_pipe) break;
            fatal("can't read {f}, error={d}", .{ std.unicode.fmtUtf16Le(path), GetLastError() });
        }
        if (read == 0) break;
        data.items.len += read;
    }
    return data.items;
}
/// Writes UTF-8 text to a console as UTF-16, so it shows right whatever its code page, and to
/// anything else as is. Exits with 1 when it can't.
fn writeOutput(handle: windows.HANDLE, arena: std.mem.Allocator, text: []const u8) void {
    var mode: u32 = 0;
    if (0 != GetConsoleMode(handle, &mode) and text.len <= std.math.maxInt(i32)) {
        if (toUtf16(arena, text)) |wide| {
            var rest = wide;
            while (rest.len > 0) {
                var len = @min(rest.len, 1 << 14);
                // keep a surrogate pair in one write
                if (len < rest.len and std.unicode.utf16IsHighSurrogate(rest[len - 1])) len -= 1;
                var written: u32 = 0;
                if (0 == WriteConsoleW(handle, rest.ptr, @intCast(len), &written, null)) writeFailed();
                rest = rest[written..];
            }
            return;
        }
    }
    var rest = text;
    while (rest.len > 0) {
        var written: u32 = 0;
        if (0 == WriteFile(handle, rest.ptr, @intCast(@min(rest.len, 1 << 30)), &written, null)) writeFailed();
        rest = rest[written..];
    }
}

/// Converts `text`, with U+FFFD in place of what isn't UTF-8, such as a log line in another
/// encoding. Null when out of memory.
fn toUtf16(arena: std.mem.Allocator, text: []const u8) ?[]const u16 {
    if (text.len == 0) return &.{};
    const len = MultiByteToWideChar(cp_utf8, 0, text.ptr, @intCast(text.len), null, 0);
    const wide = arena.alloc(u16, @intCast(len)) catch return null;
    return wide[0..@intCast(MultiByteToWideChar(cp_utf8, 0, text.ptr, @intCast(text.len), wide.ptr, len))];
}

fn writeFailed() noreturn {
    const code = GetLastError();
    // the failed write may have been stdout's, so the message goes to stderr
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "wintrace-symbolize: write failed, error={d}\n", .{code}) catch unreachable;
    var written: u32 = 0;
    _ = WriteFile(GetStdHandle(std_error_handle), msg.ptr, @intCast(msg.len), &written, null);
    ExitProcess(1);
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "wintrace-symbolize: " ++ fmt ++ "\n", args) catch "wintrace-symbolize: error\n";
    var written: u32 = 0;
    _ = WriteFile(GetStdHandle(std_error_handle), msg.ptr, @intCast(msg.len), &written, null);
    ExitProcess(1);
}

/// PE images are at most 4 GiB.
const max_image_size: u32 = std.math.maxInt(u32);

const SymbolBuf = extern struct {
    info: SYMBOL_INFOW,
    // the rest of the name; SYMBOL_INFOW.Name is declared with one element
    rest: [max_name]u16,

    const max_name = 1024;
    const init: SymbolBuf = blk: {
        var s = std.mem.zeroes(SymbolBuf);
        s.info.SizeOfStruct = @sizeOf(SYMBOL_INFOW);
        s.info.MaxNameLen = max_name;
        break :blk s;
    };
    fn name(s: *const SymbolBuf) []const u16 {
        const p: [*]const u16 = @ptrCast(&s.info.Name);
        return p[0..@min(s.info.NameLen, max_name)];
    }
};

const SYMBOL_INFOW = extern struct {
    SizeOfStruct: u32,
    TypeIndex: u32,
    Reserved: [2]u64,
    Index: u32,
    Size: u32,
    ModBase: u64,
    Flags: u32,
    Value: u64,
    Address: u64,
    Register: u32,
    Scope: u32,
    Tag: u32,
    NameLen: u32,
    MaxNameLen: u32,
    Name: [1]u16,
};
const IMAGEHLP_LINEW64 = extern struct {
    SizeOfStruct: u32,
    Key: ?*anyopaque,
    LineNumber: u32,
    FileName: ?[*:0]const u16,
    Address: u64,
};
const IMAGEHLP_MODULEW64 = extern struct {
    SizeOfStruct: u32,
    BaseOfImage: u64,
    ImageSize: u32,
    TimeDateStamp: u32,
    CheckSum: u32,
    NumSyms: u32,
    SymType: u32,
    ModuleName: [32]u16,
    ImageName: [256]u16,
    LoadedImageName: [256]u16,
    LoadedPdbName: [256]u16,
    CVSig: u32,
    CVData: [260 * 3]u16,
    PdbSig: u32,
    PdbSig70: [16]u8 align(4),
    PdbAge: u32,
    PdbUnmatched: i32,
    DbgUnmatched: i32,
    LineNumbers: i32,
    GlobalSymbols: i32,
    TypeInfo: i32,
    SourceIndexed: i32,
    Publics: i32,
    MachineType: u32,
    Reserved: u32,
};
comptime {
    // the sizes dbghelp.h gives for 64-bit Windows
    std.debug.assert(@sizeOf(SYMBOL_INFOW) == 88);
    std.debug.assert(@sizeOf(IMAGEHLP_LINEW64) == 40);
    std.debug.assert(@sizeOf(IMAGEHLP_MODULEW64) == 3264);
}

const symopt_undname = 0x2;
const symopt_load_lines = 0x10;
const symopt_fail_critical_errors = 0x200;
const symopt_no_prompts = 0x80000;
const generic_read = 0x80000000;
const file_share_read = 1;
const file_share_write = 2;
const file_share_delete = 4;
const open_existing = 3;
const std_output_handle: u32 = @bitCast(@as(i32, -11));
const std_error_handle: u32 = @bitCast(@as(i32, -12));
const std_input_handle: u32 = @bitCast(@as(i32, -10));
const error_broken_pipe = 109;

const BOOL = i32;
extern "dbghelp" fn SymSetOptions(options: u32) callconv(.winapi) u32;
extern "dbghelp" fn SymInitializeW(process: windows.HANDLE, search_path: ?[*:0]const u16, invade: BOOL) callconv(.winapi) BOOL;
extern "dbghelp" fn SymCleanup(process: windows.HANDLE) callconv(.winapi) BOOL;
extern "dbghelp" fn SymLoadModuleExW(
    process: windows.HANDLE,
    file: ?windows.HANDLE,
    image_name: ?[*:0]const u16,
    module_name: ?[*:0]const u16,
    base: u64,
    size: u32,
    data: ?*anyopaque,
    flags: u32,
) callconv(.winapi) u64;
extern "dbghelp" fn SymGetModuleInfoW64(process: windows.HANDLE, address: u64, info: *IMAGEHLP_MODULEW64) callconv(.winapi) BOOL;
extern "dbghelp" fn SymFromAddrW(process: windows.HANDLE, address: u64, displacement: ?*u64, symbol: *SYMBOL_INFOW) callconv(.winapi) BOOL;
extern "dbghelp" fn SymGetLineFromAddrW64(process: windows.HANDLE, address: u64, displacement: *u32, line: *IMAGEHLP_LINEW64) callconv(.winapi) BOOL;
extern "dbghelp" fn SymAddrIncludeInlineTrace(process: windows.HANDLE, address: u64) callconv(.winapi) u32;
extern "dbghelp" fn SymQueryInlineTrace(
    process: windows.HANDLE,
    start_address: u64,
    start_context: u32,
    start_ret_address: u64,
    cur_address: u64,
    cur_context: *u32,
    cur_frame_index: *u32,
) callconv(.winapi) BOOL;
extern "dbghelp" fn SymFromInlineContextW(process: windows.HANDLE, address: u64, inline_context: u32, displacement: ?*u64, symbol: *SYMBOL_INFOW) callconv(.winapi) BOOL;
extern "dbghelp" fn SymGetLineFromInlineContextW(
    process: windows.HANDLE,
    address: u64,
    inline_context: u32,
    module_base: u64,
    displacement: *u32,
    line: *IMAGEHLP_LINEW64,
) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "kernel32" fn GetCommandLineW() callconv(.winapi) [*:0]const u16;
extern "shell32" fn CommandLineToArgvW(cmdline: [*:0]const u16, argc: *c_int) callconv(.winapi) ?[*][*:0]u16;
extern "kernel32" fn CreateFileW(
    name: [*:0]const u16,
    access: u32,
    share: u32,
    security: ?*anyopaque,
    disposition: u32,
    flags: u32,
    template: ?windows.HANDLE,
) callconv(.winapi) windows.HANDLE;
extern "kernel32" fn ReadFile(file: windows.HANDLE, buf: [*]u8, len: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn WriteFile(file: windows.HANDLE, buf: [*]const u8, len: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
const cp_utf8 = 65001;
extern "kernel32" fn MultiByteToWideChar(code_page: u32, flags: u32, text: [*]const u8, len: c_int, wide: ?[*]u16, wide_len: c_int) callconv(.winapi) c_int;
extern "kernel32" fn GetConsoleMode(console: windows.HANDLE, mode: *u32) callconv(.winapi) BOOL;
extern "kernel32" fn WriteConsoleW(console: windows.HANDLE, buf: [*]const u16, len: u32, written: *u32, reserved: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) windows.HANDLE;
extern "kernel32" fn ExitProcess(code: u32) callconv(.winapi) noreturn;
extern "kernel32" fn GetModuleFileNameW(module: ?*anyopaque, name: [*]u16, size: u32) callconv(.winapi) u32;

/// Traces this test binary writes, with frames in `outer` and `traceMe` at known lines.
const Fixture = struct {
    trace: []const u8,
    pdb: [:0]const u16,
    /// the test exe's file name, as frame lines name it
    exe: []const u8,
    trace_me_line: u32,
    outer_line: u32,

    const t = struct {
        var outer_line: u32 = 0;
        var trace_me_line: u32 = 0;
        noinline fn outer(w: *std.Io.Writer) !void {
            outer_line = @src().line + 1;
            try traceMe(w);
            std.mem.doNotOptimizeAway(w);
        }
        noinline fn traceMe(w: *std.Io.Writer) !void {
            trace_me_line = @src().line + 1;
            try wintrace.writeCurrentStackTrace(w, null);
            std.mem.doNotOptimizeAway(w);
        }
    };

    fn init(arena: std.mem.Allocator) !Fixture {
        var trace: std.Io.Writer.Allocating = .init(arena);
        try t.outer(&trace.writer);
        var path_buf: [1024]u16 = undefined;
        const len = GetModuleFileNameW(null, &path_buf, path_buf.len);
        const exe_path = path_buf[0..len];
        return .{
            .trace = trace.written(),
            // the linker writes the test binary's PDB next to it
            .pdb = try std.mem.concatWithSentinel(arena, u16, &.{ exe_path[0 .. exe_path.len - 3], &[_]u16{ 'p', 'd', 'b' } }, 0),
            .exe = try std.unicode.wtf16LeToWtf8Alloc(arena, basename(u16, exe_path)),
            .trace_me_line = t.trace_me_line,
            .outer_line = t.outer_line,
        };
    }

    fn run(f: Fixture, arena: std.mem.Allocator, trace: []const u8) ![]const u8 {
        var out: std.Io.Writer.Allocating = .init(arena);
        var diag: std.Io.Writer.Allocating = .init(arena);
        try std.testing.expect(try symbolize(arena, trace, &.{f.pdb}, &out.writer, &diag.writer));
        try std.testing.expectEqualStrings("", diag.written());
        return out.written();
    }

    /// The trace with this exe's module line removed, or all of them.
    fn withoutModuleLines(f: Fixture, arena: std.mem.Allocator, which: enum { exe, all }) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var lines = std.mem.splitScalar(u8, f.trace, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (parseModuleLine(line)) |m| if (which == .all or std.mem.eql(u8, m.name, f.exe)) continue;
            try out.appendSlice(arena, line);
            try out.append(arena, '\n');
        }
        return out.items;
    }

    /// The trace with the key on this exe's module line changed, as if from another build.
    fn fromAnotherBuild(f: Fixture, arena: std.mem.Allocator) ![]const u8 {
        const copy = try arena.dupe(u8, f.trace);
        const needle = try std.fmt.allocPrint(arena, "module {s} | ", .{f.exe});
        const start = std.mem.indexOf(u8, copy, needle).?;
        const key = std.mem.lastIndexOfScalar(u8, copy[0..std.mem.indexOfScalarPos(u8, copy, start, '\n').?], ' ').? + 1;
        copy[key] = if (copy[key] == '0') '1' else '0';
        return copy;
    }
};

test "frames get their function and the line of their call" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const text = try f.run(arena, f.trace);
    // Both are return addresses, which point after their call and must be looked up one byte
    // earlier to land on the call's line.
    try expectFrame(text, 0, "traceMe+0x", f.trace_me_line);
    try expectFrame(text, 1, "outer+0x", f.outer_line);
    // the module lines are copied through
    try std.testing.expect(std.mem.indexOf(u8, text, "\n    module ") != null);
}

test "a frame marked (ip) is looked up at its own address, any other one byte before it" {
    const t = struct {
        noinline fn ipTarget() void {
            std.mem.doNotOptimizeAway(&ipTarget);
        }
    };
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    t.ipTarget();
    for ([_]bool{ true, false }) |ip| {
        var trace: std.Io.Writer.Allocating = .init(arena);
        try wintrace.writeAddresses(&trace.writer, &.{@intFromPtr(&t.ipTarget)}, .{ .first_is_ip = ip });
        const text = try f.run(arena, trace.written());
        try std.testing.expectEqual(ip, std.mem.indexOf(u8, text, "ipTarget+0x0") != null);
    }
}

test "each trace in a log uses its own module lines" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const other_build = try f.fromAnotherBuild(arena);
    // a trace from another build with a log line before it, then one from this build right after
    const log = try std.mem.concat(arena, u8, &.{ "panic: first\n", other_build, f.trace, "done\n" });
    const text = try f.run(arena, log);
    const mismatch = std.mem.indexOf(u8, text, " (pdb is from a different build)\n") orelse return error.TestUnexpectedResult;
    const symbolized = std.mem.indexOf(u8, text, "traceMe+0x") orelse return error.TestUnexpectedResult;
    try std.testing.expect(mismatch < symbolized);
    try std.testing.expectEqual(1, std.mem.count(u8, text, "traceMe+0x"));
    try std.testing.expect(std.mem.startsWith(u8, text, "panic: first\n"));
    try std.testing.expect(std.mem.endsWith(u8, text, "\ndone\n"));
}

test "a trace with module lines is never matched by name" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    // other modules are listed, this exe isn't
    var text = try f.run(arena, try f.withoutModuleLines(arena, .exe));
    try std.testing.expect(std.mem.indexOf(u8, text, "traceMe") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, " (module not listed in the trace)\n") != null);
    // no module lines at all: by name
    text = try f.run(arena, try f.withoutModuleLines(arena, .all));
    try expectFrame(text, 0, "traceMe+0x", f.trace_me_line);
}

test "a log line inside a trace isn't mistaken for the end of one" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    // after the header and the first frame
    const first_end = std.mem.indexOfScalarPos(u8, f.trace, std.mem.indexOfScalar(u8, f.trace, '\n').? + 1, '\n').? + 1;

    // A bare address, written for code outside any module, is part of the trace.
    var text = try f.run(arena, try std.mem.concat(arena, u8, &.{ f.trace[0..first_end], "    0x12340000\n", f.trace[first_end..] }));
    try expectFrame(text, 0, "traceMe+0x", f.trace_me_line);
    // expectFrame counts the address line as a frame
    try expectFrame(text, 2, "outer+0x", f.outer_line);
    try std.testing.expect(std.mem.indexOf(u8, text, "\n    0x12340000\n") != null);

    // Another thread's log line splits it. The part before has no module lines, and isn't
    // matched by name, which could pick a PDB from another build.
    text = try f.run(arena, try std.mem.concat(arena, u8, &.{ f.trace[0..first_end], "[thread 2] hello\n", f.trace[first_end..] }));
    try std.testing.expect(std.mem.startsWith(u8, text, try std.mem.concat(arena, u8, &.{ f.trace[0 .. first_end - 1], " (no module lines in this part of the trace)\n[thread 2] hello\n" })));
    try expectFrame(text, 1, "outer+0x", f.outer_line);
}

test "a log without traces is copied unchanged" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const log =
        \\starting
        \\    foo+0x10
        \\    total+0x10 (ip)
        \\    Program Files+0x0
        \\    0x10
        \\    ...
        \\  * not a frame
        \\
        \\end
    ;
    try std.testing.expectEqualStrings(log, try f.run(arena, log));
}

test "module names may contain spaces" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const renamed = try std.mem.replaceOwned(u8, arena, f.trace, f.exe, "my app (x86).exe");
    const text = try f.run(arena, renamed);
    try expectFrame(text, 0, "traceMe+0x", f.trace_me_line);
}

test "offsets outside an image aren't looked up" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const trace = try std.fmt.allocPrint(arena,
        \\    {[n]s}+0x0 (ip)
        \\    {[n]s}+0x0
        \\    {[n]s}+0xffffffffffffffff
        \\    {[n]s}+0x100000000
        \\
    , .{ .n = f.exe });
    const text = try f.run(arena, trace);
    try std.testing.expectEqual(3, std.mem.count(u8, text, " (offset outside module)\n"));
}

test "line endings are kept" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const crlf = try std.mem.replaceOwned(u8, arena, f.trace, "\n", "\r\n");
    // a CRLF trace, then an LF one, in one log whose last line has no line break
    const text = try f.run(arena, try std.mem.concat(arena, u8, &.{ "start\r\n", crlf, "mid\n", f.trace, "end" }));
    try std.testing.expectEqual(2, std.mem.count(u8, text, "traceMe+0x"));
    const mid = std.mem.indexOf(u8, text, "mid\n") orelse return error.TestUnexpectedResult;
    // every line break before it is still \r\n, including those of the added inlined-into
    // lines, and every one after it \n
    const before = text[0..mid];
    try std.testing.expect(std.mem.startsWith(u8, before, "start\r\n"));
    try std.testing.expectEqual(std.mem.count(u8, before, "\n"), std.mem.count(u8, before, "\r\n"));
    try std.testing.expect(std.mem.indexOfScalar(u8, text[mid..], '\r') == null);
    try std.testing.expect(std.mem.endsWith(u8, text, "\nend"));
}

test "two modules with one name are reported instead of guessed" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    var out: std.Io.Writer.Allocating = .init(arena);
    var diag: std.Io.Writer.Allocating = .init(arena);
    _ = try symbolize(arena,
        \\    side.dll+0x10
        \\    module side.dll | side.pdb | 0123456789ABCDEF0123456789ABCDEF1
        \\    module side.dll | side.pdb | 0123456789ABCDEF0123456789ABCDEF2
        \\
    , &.{}, &out.writer, &diag.writer);
    try std.testing.expect(std.mem.startsWith(u8, out.written(), "    side.dll+0x10 (two modules in the trace have this name)\n"));
}

test "a PDB that can't be loaded is reported and the others still used" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    const missing = std.unicode.utf8ToUtf16LeStringLiteral("C:\\no\\such\\file.pdb");
    var out: std.Io.Writer.Allocating = .init(arena);
    var diag: std.Io.Writer.Allocating = .init(arena);
    try std.testing.expect(!try symbolize(arena, f.trace, &.{ missing, f.pdb }, &out.writer, &diag.writer));
    try std.testing.expect(std.mem.startsWith(u8, diag.written(), "wintrace-symbolize: can't load C:\\no\\such\\file.pdb"));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "traceMe+0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "can't load") == null);
}

test "an inlined frame is listed with the function it was inlined into" {
    const t = struct {
        var inlined_line: u32 = 0;
        var physical_line: u32 = 0;
        noinline fn physical(w: *std.Io.Writer) !void {
            physical_line = @src().line + 1;
            try inlined(w);
            std.mem.doNotOptimizeAway(w);
        }
        inline fn inlined(w: *std.Io.Writer) !void {
            inlined_line = @src().line + 1;
            try wintrace.writeCurrentStackTrace(w, null);
        }
    };
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    var trace: std.Io.Writer.Allocating = .init(arena);
    try t.physical(&trace.writer);
    const text = try f.run(arena, trace.written());
    // the first frame is in inlined, at the call that wrote the trace, then in physical, at
    // the call to inlined
    var lines = std.mem.splitScalar(u8, text, '\n');
    try std.testing.expectEqualStrings("    wintrace", lines.next().?);
    const inlined = lines.next().?;
    const physical = lines.next().?;
    errdefer std.debug.print("got:\n{s}\n", .{text});
    try std.testing.expect(std.mem.indexOf(u8, inlined, " in ") != null and std.mem.indexOf(u8, inlined, "inlined (") != null);
    try std.testing.expect(std.mem.endsWith(u8, inlined, try std.fmt.allocPrint(arena, "symbolize.zig:{d})", .{t.inlined_line})));
    try std.testing.expect(std.mem.startsWith(u8, physical, "        inlined into ") and std.mem.indexOf(u8, physical, "physical+0x") != null);
    try std.testing.expect(std.mem.endsWith(u8, physical, try std.fmt.allocPrint(arena, "symbolize.zig:{d})", .{t.physical_line})));
}

test decode {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    try std.testing.expectEqualStrings("    a.exe+0x1\r\n", try decode(arena, "\xFF\xFE \x00 \x00 \x00 \x00a\x00.\x00e\x00x\x00e\x00+\x000\x00x\x001\x00\r\x00\n\x00"));
    try std.testing.expectEqualStrings("a\n", try decode(arena, "\xFE\xFF\x00a\x00\n"));
    try std.testing.expectEqualStrings("x\n", try decode(arena, "\xEF\xBB\xBFx\n"));
    try std.testing.expectEqualStrings("x\n", try decode(arena, "x\n"));
}

test toUtf16 {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    // a cp1252 é in a log line, then a character outside the BMP
    try std.testing.expectEqualSlices(u16, L("a\u{FFFD}b \u{1F600}"), toUtf16(arena, "a\xE9b \xF0\x9F\x98\x80").?);
    try std.testing.expectEqualSlices(u16, &.{}, toUtf16(arena, "").?);
}

test "a trace cut short isn't taken for part of the next" {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const f: Fixture = try .init(arena);
    // the header and first frame of a trace from this build, then one from another build
    const first_end = std.mem.indexOfScalarPos(u8, f.trace, std.mem.indexOfScalar(u8, f.trace, '\n').? + 1, '\n').? + 1;
    const text = try f.run(arena, try std.mem.concat(arena, u8, &.{ f.trace[0..first_end], try f.fromAnotherBuild(arena) }));
    try std.testing.expect(std.mem.startsWith(u8, text, try std.mem.concat(arena, u8, &.{ f.trace[0 .. first_end - 1], " (no module lines in this part of the trace)\n    wintrace\n" })));
    try std.testing.expectEqual(0, std.mem.count(u8, text, "traceMe+0x"));
}

test parseFrame {
    const f = parseFrame("    my app.exe+0x1f2e (x3)").?;
    try std.testing.expectEqualStrings("my app.exe", f.module);
    try std.testing.expectEqual(0x1f2e, f.offset);
    try std.testing.expect(!f.ip);
    try std.testing.expect(parseFrame("    a+0x10 (ip)").?.ip);
    try std.testing.expectEqualStrings("a+0xb.dll", parseFrame("    a+0xb.dll+0x10").?.module);
    // not frames: unindented text, bare addresses, module and omission lines, bad offsets
    try std.testing.expect(parseFrame("panic: a+0x10") == null);
    try std.testing.expect(parseFrame("    0x7ff612340000") == null);
    try std.testing.expect(parseFrame("    module a.exe | a.pdb | -") == null);
    try std.testing.expect(parseFrame("    ... 12 frames") == null);
    try std.testing.expect(parseFrame("    a+0x10g") == null);
    try std.testing.expect(parseFrame("    a+0x10000000000000000") == null);
}

test parseModuleLine {
    const m = parseModuleLine("    module my app.exe | my app.pdb | 0123456789ABCDEF0123456789ABCDEF1").?;
    try std.testing.expectEqualStrings("my app.exe", m.name);
    try std.testing.expectEqualStrings("my app.pdb", m.pdb.?);
    try std.testing.expectEqualStrings("0123456789ABCDEF0123456789ABCDEF1", m.key.?);
    const none = parseModuleLine("    module a.dll | - | -").?;
    try std.testing.expect(none.pdb == null and none.key == null);
    // a log line that happens to start with "module", indented or not
    try std.testing.expect(parseModuleLine("module a.exe | a.pdb | 0123456789ABCDEF0123456789ABCDEF1") == null);
    try std.testing.expect(parseModuleLine("    module a.exe was loaded") == null);
    try std.testing.expect(parseModuleLine("    module a.exe | a.pdb | not-a-key") == null);
}

test "README's example trace is in the format the symbolizer reads" {
    const readme = @embedFile("readme");
    // the first fenced block; a checkout may have either line ending
    const fence = std.mem.indexOf(u8, readme, "```") orelse return error.TestUnexpectedResult;
    const start = std.mem.indexOfScalarPos(u8, readme, fence, '\n').? + 1;
    const block = readme[start..std.mem.indexOfPos(u8, readme, start, "```").?];
    var header = false;
    var frames = false;
    var modules = false;
    var omitted = false;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, block, "\r\n"), '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const kind = classify(line);
        if (kind == .other) {
            std.debug.print("README line isn't part of a trace: '{s}'\n", .{line});
            return error.TestUnexpectedResult;
        }
        switch (kind) {
            .header => header = true,
            .frame => frames = true,
            .module => modules = true,
            .omitted => omitted = true,
            else => {},
        }
    }
    try std.testing.expect(header and frames and modules and omitted);
}

/// Expects frame `index` of a symbolized trace to name `function` with `symbolize.zig:<line>`.
fn expectFrame(text: []const u8, index: usize, function: []const u8, line: u32) !void {
    var frames: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        // a frame line, symbolized or not; inlined-into lines are indented further
        if (!std.mem.startsWith(u8, l, indent) or std.mem.startsWith(u8, l, indent ++ " ") or classify(l) == .header or
            std.mem.startsWith(u8, l, indent ++ "module ") or std.mem.startsWith(u8, l, indent ++ "...")) continue;
        if (frames == index) {
            var buf: [64]u8 = undefined;
            const suffix = try std.fmt.bufPrint(&buf, "symbolize.zig:{d})", .{line});
            if (std.mem.indexOf(u8, l, function) == null or !std.mem.endsWith(u8, l, suffix)) {
                std.debug.print("frame {d}: expected {s}...{s}, got: {s}\n", .{ index, function, suffix, l });
                return error.TestUnexpectedResult;
            }
            return;
        }
        frames += 1;
    }
    std.debug.print("no frame {d} in:\n{s}\n", .{ index, text });
    return error.TestUnexpectedResult;
}

const std = @import("std");
const windows = std.os.windows;
const wintrace = @import("wintrace");
