const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wintrace = b.addModule("wintrace", .{
        .root_source_file = b.path("src/wintrace.zig"),
    });

    const symbolize = b.createModule(.{
        .root_source_file = b.path("src/symbolize.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "wintrace", .module = wintrace }},
    });
    const exe = b.addExecutable(.{
        .name = "wintrace-symbolize",
        .root_module = symbolize,
    });
    const install = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install.step);

    // Once for each arch this machine can run: 64-bit Windows also runs x86 (natively, under
    // WoW64), and arm64 Windows runs x86_64 (emulated).
    const test_step = b.step("test", "Run the tests");
    const host = b.graph.host.result;
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64, .x86 }) |arch| {
        const runnable = host.os.tag == .windows and (arch == host.cpu.arch or arch == .x86 or
            (arch == .x86_64 and host.cpu.arch == .aarch64));
        if (!runnable) continue;
        const test_target = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .windows });
        const wintrace_test = b.addTest(.{
            .name = b.fmt("wintrace-{s}", .{@tagName(arch)}),
            .root_module = testModule(b, "src/wintrace.zig", test_target, optimize),
        });
        test_step.dependOn(&b.addRunArtifact(wintrace_test).step);
        // the symbolizer runs on a 64-bit machine, an x86 trace is tested below
        if (arch == .x86) continue;
        const symbolize_test_module = testModule(b, "src/symbolize.zig", test_target, optimize);
        symbolize_test_module.addImport("wintrace", b.createModule(.{
            .root_source_file = b.path("src/wintrace.zig"),
        }));
        // the example trace the tests check
        symbolize_test_module.addAnonymousImport("readme", .{
            .root_source_file = b.path("README.md"),
        });
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{
            .name = b.fmt("symbolize-{s}", .{@tagName(arch)}),
            .root_module = symbolize_test_module,
        })).step);
    }

    // What wintrace adds to a ReleaseSmall exe, for each arch, which must match README's table.
    // The builds are reproducible, so any change to the code changes it.
    const size_test = b.createModule(.{
        .root_source_file = b.path("src/size.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    size_test.addAnonymousImport("readme", .{
        .root_source_file = b.path("README.md"),
    });
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64, .x86 }) |arch| {
        const fixture_target = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .windows });
        for ([_]bool{ false, true }) |trace| {
            const name = b.fmt("{s}-{s}", .{ if (trace) "with" else "without", @tagName(arch) });
            size_test.addAnonymousImport(name, .{
                .root_source_file = addFixture(b, fixture_target, .ReleaseSmall, trace).getEmittedBin(),
            });
        }
    }
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .name = "size",
        .root_module = size_test,
    })).step);

    // wintrace-symbolize itself, on a trace from a program built here
    if (host.os.tag == .windows) {
        const fixture = addFixture(b, target, optimize, true);
        const run_fixture = b.addRunArtifact(fixture);
        const trace = if (@hasDecl(std.Build.Step.Run, "CapturedStdIo"))
            run_fixture.captureStdOut(.{})
        else
            run_fixture.captureStdOut();

        const symbolized = b.addRunArtifact(exe);
        symbolized.setName("symbolize the fixture's trace");
        symbolized.addFileArg(trace);
        symbolized.addFileArg(fixture.getEmittedPdb());
        symbolized.addCheck(.{ .expect_stdout_match = "traceMe+0x" });
        symbolized.expectExitCode(0);
        test_step.dependOn(&symbolized.step);

        const missing_pdb = b.addRunArtifact(exe);
        missing_pdb.setName("symbolize with a missing pdb");
        missing_pdb.addFileArg(trace);
        missing_pdb.addArg("missing.pdb");
        missing_pdb.addCheck(.{ .expect_stderr_match = "can't load missing.pdb" });
        missing_pdb.expectExitCode(1);
        test_step.dependOn(&missing_pdb.step);

        const from_stdin = b.addRunArtifact(exe);
        from_stdin.setName("symbolize from stdin");
        from_stdin.addArg("-");
        from_stdin.addFileArg(fixture.getEmittedPdb());
        from_stdin.setStdIn(.{ .lazy_path = trace });
        from_stdin.addCheck(.{ .expect_stdout_match = "traceMe+0x" });
        from_stdin.expectExitCode(0);
        test_step.dependOn(&from_stdin.step);

        const not_a_pdb = b.addRunArtifact(exe);
        not_a_pdb.setName("symbolize with a file that isn't a pdb");
        not_a_pdb.addFileArg(trace);
        not_a_pdb.addFileArg(trace);
        not_a_pdb.addCheck(.{ .expect_stderr_match = ": not a PDB" });
        not_a_pdb.expectExitCode(1);
        test_step.dependOn(&not_a_pdb.step);

        // a trace from an x86 program, with its 32-bit PDB
        const fixture_x86 = addFixture(b, b.resolveTargetQuery(.{ .cpu_arch = .x86, .os_tag = .windows }), optimize, true);
        const run_fixture_x86 = b.addRunArtifact(fixture_x86);
        const trace_x86 = if (@hasDecl(std.Build.Step.Run, "CapturedStdIo"))
            run_fixture_x86.captureStdOut(.{})
        else
            run_fixture_x86.captureStdOut();
        const symbolized_x86 = b.addRunArtifact(exe);
        symbolized_x86.setName("symbolize an x86 fixture's trace");
        symbolized_x86.addFileArg(trace_x86);
        symbolized_x86.addFileArg(fixture_x86.getEmittedPdb());
        symbolized_x86.addCheck(.{ .expect_stdout_match = "traceMe+0x" });
        symbolized_x86.expectExitCode(0);
        test_step.dependOn(&symbolized_x86.step);

        const no_args = b.addRunArtifact(exe);
        no_args.setName("symbolize without arguments");
        no_args.addCheck(.{ .expect_stderr_match = "usage: " });
        no_args.expectExitCode(2);
        test_step.dependOn(&no_args.step);
    }
}

/// src/fixture.zig, with or without wintrace.
fn addFixture(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    trace: bool,
) *std.Build.Step.Compile {
    const options = b.addOptions();
    options.addOption(bool, "trace", trace);
    return b.addExecutable(.{
        // one name for both, so the PDB path each embeds is the same length
        .name = "fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fixture.zig"),
            .target = target,
            .optimize = optimize,
            .strip = false,
            .imports = &.{
                .{ .name = "options", .module = options.createModule() },
                .{ .name = "wintrace", .module = b.createModule(.{
                    .root_source_file = b.path("src/wintrace.zig"),
                }) },
            },
        }),
    });
}

fn testModule(
    b: *std.Build,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
        // The tests read the PDB identity the linker stamps into the image, which a stripped
        // build (ReleaseSmall's default) doesn't get.
        .strip = false,
    });
}
