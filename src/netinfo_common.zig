const std = @import("std");

pub const NetInfo = struct {
    ip_cidr: []u8,
    ip6_cidr: []u8,
    link_state: []u8,
    link_kind: []u8,
    link_speed: []u8,
    link_duplex: []u8,

    pub fn deinit(self: *NetInfo, alloc: std.mem.Allocator) void {
        alloc.free(self.ip_cidr);
        alloc.free(self.ip6_cidr);
        alloc.free(self.link_state);
        alloc.free(self.link_kind);
        alloc.free(self.link_speed);
        alloc.free(self.link_duplex);
        self.* = undefined;
    }
};
