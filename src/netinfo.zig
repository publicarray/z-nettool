const std = @import("std");
const builtin = @import("builtin");
const common = @import("netinfo_common.zig");

pub fn getNetInfoCommon(alloc: std.mem.Allocator, iface: []const u8) !common.NetInfo {
    if (builtin.os.tag == .windows) return @import("netinfo_windows.zig").getNetInfoCommon(alloc, iface);
    if (builtin.os.tag == .linux) return @import("netinfo_linux.zig").getNetInfoCommon(alloc, iface);
    if (builtin.os.tag == .macos) return @import("netinfo_darwin.zig").getNetInfoCommon(alloc, iface);
    return error.UnsupportedOS;
}
