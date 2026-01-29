const std = @import("std");
const builtin = @import("builtin");
const iface_common = @import("iface_common.zig");

pub fn chooseInterface(alloc: std.mem.Allocator, forced: ?[]const u8) !iface_common.Interface {
    if (builtin.os.tag == .windows) return @import("iface_windows.zig").chooseInterface(alloc, forced);
    if (builtin.os.tag == .linux) return @import("iface_linux.zig").chooseInterface(alloc, forced);
    if (builtin.os.tag == .macos) return @import("iface_darwin.zig").chooseInterface(alloc, forced);
    return error.UnsupportedOS;
}
