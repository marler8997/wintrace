//! A program that reports its crashes with wintrace in the small mode, for build.zig's tests.
//! Crash it with `panic`, `segfault` or `error` at the end of its command line. With `reports`
//! off it's the same program without wintrace, so the two builds differ only by what the
//! reports add.

pub const panic = if (options.reports) wintrace.panic else std.debug.no_panic;
pub const wintrace_options: wintrace.Options = .{ .mode = .small };
pub const std_options: std.Options = .{ .enable_segfault_handler = false };

pub fn main() void {
    if (options.reports) {
        if (wintrace.SetUnhandledExceptionFilter(&wintrace.unhandledExceptionFilter) != null) unreachable;
    }
    run() catch |err| {
        if (options.reports) wintrace.exitWithErrorTrace(err, @errorReturnTrace());
        std.process.exit(1);
    };
}

fn run() !void {
    const command_line = std.os.windows.peb().ProcessParameters.CommandLine;
    const args = command_line.Buffer.?[0 .. command_line.Length / 2];
    useMemoryRoutines(args);
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    if (std.mem.endsWith(u16, args, L("panic"))) @panic("fixture panic");
    if (std.mem.endsWith(u16, args, L("segfault"))) @as(*volatile u8, @ptrFromInt(8)).* = 1;
    if (std.mem.endsWith(u16, args, L("error"))) return error.FixtureError;
}

/// Calls memcpy, memmove and memset, as nearly every program does. The reports call them too,
/// and with Zig 0.17 on x86_64 the first call brings in 46 KB of compiler-rt, which isn't what
/// the reports add.
noinline fn useMemoryRoutines(args: []const u16) void {
    var buf: [64]u16 = undefined;
    const len = @min(args.len, buf.len / 2);
    @memset(buf[0 .. 2 * len], 0);
    @memcpy(buf[0..len], args[0..len]);
    @memmove(buf[len..][0..len], buf[len / 2 ..][0..len]);
    std.mem.doNotOptimizeAway(&buf);
}

const std = @import("std");
const options = @import("options");
const wintrace = @import("wintrace");
