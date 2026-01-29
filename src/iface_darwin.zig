const std = @import("std");
const iface_common = @import("iface_common.zig");

pub fn chooseInterface(alloc: std.mem.Allocator, forced: ?[]const u8) !iface_common.Interface {
    _ = alloc;
    _ = forced;
    @compileError("darwin support not implemented: iface_darwin.zig");
}
