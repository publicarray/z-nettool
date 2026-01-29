const std = @import("std");

pub const Interface = struct {
    name: []u8, // owned
    mac: [6]u8,

    pub fn deinit(self: *Interface, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        self.* = undefined;
    }
};
