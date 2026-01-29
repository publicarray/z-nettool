const std = @import("std");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    _ = alloc;
    _ = host;
    @compileError("darwin support not implemented: ping_darwin.zig");
}
