//! A cross-platform program that reports its crashes with wintrace on Windows and with std's
//! reports elsewhere. Crash it with `example panic`, `segfault`, `overflow` or `error`.

pub const panic = if (builtin.os.tag == .windows) wintrace.panic else std.debug.FullPanic(std.debug.defaultPanic);
pub const wintrace_options: wintrace.Options = .{ .mode = .symbolize };
pub const std_options: std.Options = .{ .enable_segfault_handler = builtin.os.tag != .windows };

pub fn main(init: std.process.Init.Minimal) !void {
    if (builtin.os.tag == .windows) {
        if (SetUnhandledExceptionFilter(&wintrace.unhandledExceptionFilter) != null) unreachable;
        var guarantee: u32 = wintrace.stack_guarantee;
        if (SetThreadStackGuarantee(&guarantee) == 0) std.debug.panic(
            "SetThreadStackGuarantee failed, error={d}",
            .{std.os.windows.GetLastError()},
        );
    }
    run(init) catch |err| {
        if (builtin.os.tag == .windows) wintrace.exitWithErrorTrace(err, @errorReturnTrace());
        return err;
    };
}

fn run(init: std.process.Init.Minimal) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try init.args.toSlice(arena.allocator());
    const crash = if (args.len == 2) args[1] else "";
    if (std.mem.eql(u8, crash, "panic")) @panic("example panic");
    if (std.mem.eql(u8, crash, "segfault")) @as(*volatile u8, @ptrFromInt(8)).* = 1;
    if (std.mem.eql(u8, crash, "overflow")) std.mem.doNotOptimizeAway(recurse(0));
    if (std.mem.eql(u8, crash, "error")) return error.ExampleError;
    std.log.err("usage: example panic|segfault|overflow|error", .{});
    std.process.exit(2);
}

noinline fn recurse(depth: usize) usize {
    var buf: [4096]u8 = undefined;
    buf[depth % buf.len] = @truncate(depth);
    std.mem.doNotOptimizeAway(&buf);
    return recurse(depth + 1) + buf[depth % buf.len];
}

extern "kernel32" fn SetUnhandledExceptionFilter(
    filter: ?*const fn (*std.os.windows.EXCEPTION_POINTERS) callconv(.winapi) c_long,
) callconv(.winapi) ?*const anyopaque;
extern "kernel32" fn SetThreadStackGuarantee(size: *u32) callconv(.winapi) i32;

const builtin = @import("builtin");
const std = @import("std");
const wintrace = @import("wintrace");
