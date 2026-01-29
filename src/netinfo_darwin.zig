const std = @import("std");
const common = @import("netinfo_common.zig");

pub fn getNetInfoCommon(alloc: std.mem.Allocator, iface: []const u8) !common.NetInfo {
    _ = alloc;
    _ = iface;
    @compileError("darwin support not implemented: netinfo_darwin.zig");
}
