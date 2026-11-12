//! Runs a command with a pipe opened for overlapped io as its stderr, and writes what the
//! command wrote to it to our own stderr, for build.zig's tests. The pipe has no buffer and
//! isn't read for a moment, so the command's first write to it can't finish at once, which
//! NtWriteFile reports as STATUS_PENDING.
//!
//!     run-overlapped EXE ARG

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    var args = try init.args.iterateAllocator(arena);
    _ = args.skip();
    const exe = args.next() orelse @panic("expected EXE and ARG");
    const arg = args.next() orelse @panic("expected EXE and ARG");
    const command_line = try std.unicode.wtf8ToWtf16LeAllocZ(arena, try std.fmt.allocPrint(arena, "\"{s}\" {s}", .{ exe, arg }));

    var name_buf: [64]u8 = undefined;
    const name = try std.unicode.wtf8ToWtf16LeAllocZ(arena, try std.fmt.bufPrint(
        &name_buf,
        "\\\\.\\pipe\\wintrace-run-overlapped-{}",
        .{GetCurrentProcessId()},
    ));
    const pipe_access_inbound = 1;
    const server = CreateNamedPipeW(name, pipe_access_inbound, 0, 1, 0, 0, 0, null);
    if (server == windows.INVALID_HANDLE_VALUE) std.debug.panic("CreateNamedPipeW failed, error={}", .{GetLastError()});
    var inherit: SECURITY_ATTRIBUTES = .{ .nLength = @sizeOf(SECURITY_ATTRIBUTES), .lpSecurityDescriptor = null, .bInheritHandle = 1 };
    const generic_write = 0x40000000;
    const open_existing = 3;
    const file_flag_overlapped = 0x40000000;
    const client = CreateFileW(name, generic_write, 0, &inherit, open_existing, file_flag_overlapped, null);
    if (client == windows.INVALID_HANDLE_VALUE) std.debug.panic("CreateFileW failed, error={}", .{GetLastError()});

    const startf_usestdhandles = 0x100;
    var startup: STARTUPINFOW = .{ .cb = @sizeOf(STARTUPINFOW), .dwFlags = startf_usestdhandles, .hStdError = client };
    var process: PROCESS_INFORMATION = undefined;
    if (CreateProcessW(null, command_line, null, null, 1, 0, null, null, &startup, &process) == 0)
        std.debug.panic("CreateProcessW failed, error={}", .{GetLastError()});
    _ = CloseHandle(client);

    // long enough for the command to reach its write before anything reads the pipe
    Sleep(500);
    var total: usize = 0;
    var buf: [4096]u8 = undefined;
    while (true) {
        var len: u32 = 0;
        // fails once the command exits, which closes the last handle to the other end
        if (ReadFile(server, &buf, buf.len, &len, null) == 0) break;
        std.debug.print("{s}", .{buf[0..len]});
        total += len;
    }
    return if (total == 0) 1 else 0;
}

const HANDLE = windows.HANDLE;
const BOOL = i32;
const SECURITY_ATTRIBUTES = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};
const STARTUPINFOW = extern struct {
    cb: u32,
    lpReserved: ?[*:0]u16 = null,
    lpDesktop: ?[*:0]u16 = null,
    lpTitle: ?[*:0]u16 = null,
    dwX: u32 = 0,
    dwY: u32 = 0,
    dwXSize: u32 = 0,
    dwYSize: u32 = 0,
    dwXCountChars: u32 = 0,
    dwYCountChars: u32 = 0,
    dwFillAttribute: u32 = 0,
    dwFlags: u32 = 0,
    wShowWindow: u16 = 0,
    cbReserved2: u16 = 0,
    lpReserved2: ?*u8 = null,
    hStdInput: ?HANDLE = null,
    hStdOutput: ?HANDLE = null,
    hStdError: ?HANDLE = null,
};
const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
};

extern "kernel32" fn CreateNamedPipeW(name: [*:0]const u16, open_mode: u32, pipe_mode: u32, max_instances: u32, out_size: u32, in_size: u32, timeout: u32, security: ?*SECURITY_ATTRIBUTES) callconv(.winapi) HANDLE;
extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, security: ?*SECURITY_ATTRIBUTES, disposition: u32, flags: u32, template: ?HANDLE) callconv(.winapi) HANDLE;
extern "kernel32" fn CreateProcessW(application: ?[*:0]const u16, command_line: [*:0]u16, process_attributes: ?*anyopaque, thread_attributes: ?*anyopaque, inherit_handles: BOOL, flags: u32, environment: ?*anyopaque, current_directory: ?[*:0]const u16, startup: *STARTUPINFOW, process: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
extern "kernel32" fn ReadFile(file: HANDLE, buffer: [*]u8, len: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(handle: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;

const std = @import("std");
const windows = std.os.windows;
