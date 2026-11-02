//! Writes a trace to stdout, for build.zig's tests of wintrace-symbolize. With `trace` off it
//! writes an address instead, so the two builds differ only by what wintrace adds.

pub fn main() void {
    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    if (options.trace) {
        traceMe(&w) catch unreachable;
    } else w.print("0x{x}\n", .{@returnAddress()}) catch unreachable;
    var written: u32 = 0;
    _ = WriteFile(GetStdHandle(std_output_handle), w.buffered().ptr, @intCast(w.buffered().len), &written, null);
}

noinline fn traceMe(w: *std.Io.Writer) !void {
    try wintrace.writeCurrentStackTrace(w, null);
    std.mem.doNotOptimizeAway(w);
}

const std_output_handle: u32 = @bitCast(@as(i32, -11));
extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) std.os.windows.HANDLE;
extern "kernel32" fn WriteFile(file: std.os.windows.HANDLE, buf: [*]const u8, len: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;

const std = @import("std");
const options = @import("options");
const wintrace = @import("wintrace");
