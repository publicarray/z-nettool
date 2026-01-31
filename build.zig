const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const is_static = b.option(bool, "static", "Build fully static binary") orelse false;

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "netool",
        .root_module = root_mod,
    });

    if (is_static) {
        exe.linkage = .static;
    }
    exe.linkLibC();

    if (target.result.os.tag == .linux) {
        exe.linkSystemLibrary("pcap");
    }
    // Windows: embed manifest (requireAdministrator)
    if (target.result.os.tag == .windows) {
        exe.addWin32ResourceFile(.{
            .file = b.path("windows/netool.rc"),
        });
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run netool");
    run_step.dependOn(&run_cmd.step);
}
