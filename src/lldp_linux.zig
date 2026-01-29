const std = @import("std");

pub fn printLLDP(alloc: std.mem.Allocator, iface: []const u8) !void {
    const out = std.io.getStdOut().writer();
    try out.print("Switch/VLAN (LLDP):\n", .{});

    var child = std.process.Child.init(&.{ "lldpctl", iface }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    const term = child.spawnAndWait() catch {
        try out.print("  [!] lldpctl not found or failed\n", .{});
        return;
    };
    if (term.Exited != 0) {
        try out.print("  [!] lldpctl failed\n", .{});
        return;
    }
}
