const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");

pub fn discoverAndListenUdp(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
) !void {
    _ = try dhcp_common.sendAndListenUdpWithResult(alloc, iface_name, mac, listen_seconds, true);
}
