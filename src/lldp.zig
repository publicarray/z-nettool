const std = @import("std");
const builtin = @import("builtin");
const common = @import("lldp_common.zig");

pub fn collectAndParseCommon(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    if (builtin.os.tag == .windows) return @import("lldp_windows.zig").collectAndParseCommon(alloc, listen_seconds);
    if (builtin.os.tag == .linux) return @import("lldp_linux.zig").collectAndParseCommon(alloc, iface);
    if (builtin.os.tag == .macos) return @import("lldp_darwin.zig").collectAndParseCommon(alloc, iface, listen_seconds);
    return error.UnsupportedOS;
}
