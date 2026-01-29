const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");
const dhcp_tcpdump = @import("dhcp_tcpdump_darwin.zig");
const dhcp_udp = @import("dhcp_udp_darwin.zig");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
    force_udp: bool,
) !void {
    if (force_udp) return dhcp_udp.discoverAndListenUdp(alloc, iface_name, mac, listen_seconds);
    return dhcp_tcpdump.captureOfferViaTcpdump(alloc, iface_name, mac, listen_seconds);
}
