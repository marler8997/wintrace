//! Checks what wintrace adds to an exe against README's size table. build.zig builds
//! src/fixture.zig with and without wintrace for each arch, in ReleaseSmall, and embeds both.

test "wintrace adds what README's size table says" {
    var ok = true;
    inline for (.{ "x86_64", "aarch64" }) |arch| {
        const added = try sectionsSize(@embedFile("with-" ++ arch)) - try sectionsSize(@embedFile("without-" ++ arch));
        if (readmeSize(builtin.zig_version_string, arch)) |expected| {
            if (added != expected) {
                std.debug.print("Zig {s} {s}: wintrace adds {d} bytes, README.md says {d}\n", .{ builtin.zig_version_string, arch, added, expected });
                ok = false;
            }
        } else {
            std.debug.print("README.md has no '| {s} | {s} | N bytes |' row; wintrace adds {d}\n", .{ builtin.zig_version_string, arch, added });
            ok = false;
        }
    }
    if (!ok) return error.TestUnexpectedResult;
}

/// The size of every section of a PE image, without the padding that file alignment adds.
fn sectionsSize(image: []const u8) !u64 {
    const pe = std.mem.readInt(u32, image[0x3c..][0..4], .little);
    if (!std.mem.eql(u8, image[pe..][0..4], "PE\x00\x00")) return error.NotAnImage;
    const count = std.mem.readInt(u16, image[pe + 6 ..][0..2], .little);
    const optional_size = std.mem.readInt(u16, image[pe + 20 ..][0..2], .little);
    const sections = pe + 24 + optional_size;
    var total: u64 = 0;
    for (0..count) |i| total += std.mem.readInt(u32, image[sections + 40 * i + 8 ..][0..4], .little);
    return total;
}

/// From README's size table, a row like "| 0.17.0 | x86_64 | 6,468 bytes |".
fn readmeSize(zig_version: []const u8, arch: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, @embedFile("readme"), '\n');
    while (lines.next()) |line| {
        var cells = std.mem.tokenizeAny(u8, line, "| \r");
        if (!std.mem.eql(u8, cells.next() orelse continue, zig_version)) continue;
        if (!std.mem.eql(u8, cells.next() orelse continue, arch)) continue;
        const size = cells.next() orelse return null;
        if (!std.mem.eql(u8, cells.next() orelse return null, "bytes")) return null;
        var n: u64 = 0;
        for (size) |c| switch (c) {
            '0'...'9' => n = n * 10 + (c - '0'),
            ',' => {},
            else => return null,
        };
        return n;
    }
    return null;
}

const builtin = @import("builtin");
const std = @import("std");
