const std = @import("std");

pub const Neighbor = struct {
    chassis_id: []u8,
    port_id: []u8,
    system_name: []u8,
    system_desc: []u8,
    port_desc: []u8,
    vlans_csv: []u8,

    pub fn deinit(self: *Neighbor, alloc: std.mem.Allocator) void {
        alloc.free(self.chassis_id);
        alloc.free(self.port_id);
        alloc.free(self.system_name);
        alloc.free(self.system_desc);
        alloc.free(self.port_desc);
        alloc.free(self.vlans_csv);
        self.* = undefined;
    }
};
