const std = @import("std");
const builtin = @import("builtin");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    if (builtin.os.tag == .windows) return @import("ping_windows.zig").pingMs(alloc, host);
    if (builtin.os.tag == .linux) return @import("ping_linux.zig").pingMs(alloc, host);
    return null;
}
