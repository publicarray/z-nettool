const std = @import("std");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
    force_udp: bool,
) !void {
    _ = alloc;
    _ = iface_name;
    _ = mac;
    _ = listen_seconds;
    _ = force_udp;
    @compileError("darwin support not implemented: dhcp_darwin.zig");
}
