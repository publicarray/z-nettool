const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
    force_udp: bool,
) !void {
    _ = force_udp;
    return dhcp_common.sendAndListenUdp(alloc, iface_name, mac, listen_seconds, true);
}
