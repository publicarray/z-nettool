const std = @import("std");
const builtin = @import("builtin");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
    force_udp: bool,
) !void {
    if (builtin.os.tag == .windows) {
        return @import("dhcp_windows.zig").discoverAndListen(alloc, iface_name, mac, listen_seconds, force_udp);
    }
    if (builtin.os.tag == .linux) {
        return @import("dhcp_linux.zig").discoverAndListen(alloc, iface_name, mac, listen_seconds, force_udp);
    }
    if (builtin.os.tag == .macos) {
        return @import("dhcp_darwin.zig").discoverAndListen(alloc, iface_name, mac, listen_seconds, force_udp);
    }
    return error.UnsupportedOS;
}
