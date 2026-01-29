const std = @import("std");
const common = @import("lldp_common.zig");

pub fn collectAndParseCommon(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    _ = alloc;
    _ = iface;
    _ = listen_seconds;
    @compileError("darwin support not implemented: lldp_darwin.zig");
}
