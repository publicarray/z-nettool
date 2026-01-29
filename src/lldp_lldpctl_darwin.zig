const std = @import("std");
const common = @import("lldp_common.zig");

pub const LldpError = error{LldpctlFailed} || std.mem.Allocator.Error;

pub fn collectAndParseCommonCtl(allocator: std.mem.Allocator, iface: []const u8) ![]common.Neighbor {
    var info = try parseLLDP(allocator, iface);
    errdefer info.deinit(allocator);
    return lldpInfoToNeighbors(allocator, &info);
}

const LldpInfo = struct {
    chassis_id: ?[]u8 = null,
    sys_name: ?[]u8 = null,
    sys_desc: ?[]u8 = null,
    port_id: ?[]u8 = null,
    port_descr: ?[]u8 = null,
    vlans: std.ArrayListUnmanaged([]u8) = .{},

    pub fn deinit(self: *LldpInfo, allocator: std.mem.Allocator) void {
        if (self.chassis_id) |s| allocator.free(s);
        if (self.sys_name) |s| allocator.free(s);
        if (self.sys_desc) |s| allocator.free(s);
        if (self.port_id) |s| allocator.free(s);
        if (self.port_descr) |s| allocator.free(s);

        for (self.vlans.items) |v| allocator.free(v);
        self.vlans.deinit(allocator);

        self.* = undefined;
    }
};

fn lldpInfoToNeighbors(allocator: std.mem.Allocator, info: *LldpInfo) ![]common.Neighbor {
    const name = try allocator.dupe(u8, info.sys_name orelse "(none)");
    errdefer allocator.free(name);
    const desc = try allocator.dupe(u8, info.sys_desc orelse "(none)");
    errdefer allocator.free(desc);
    const port_id = try allocator.dupe(u8, info.port_id orelse "(none)");
    errdefer allocator.free(port_id);
    const port_desc = try allocator.dupe(u8, info.port_descr orelse "(none)");
    errdefer allocator.free(port_desc);
    const chassis = try allocator.dupe(u8, info.chassis_id orelse "(none)");
    errdefer allocator.free(chassis);

    var vlans_csv: []u8 = undefined;
    if (info.vlans.items.len == 0) {
        vlans_csv = try allocator.dupe(u8, "(none)");
    } else {
        var buf = try std.ArrayList(u8).initCapacity(allocator, 32);
        errdefer buf.deinit(allocator);
        for (info.vlans.items, 0..) |v, i| {
            if (i != 0) try buf.appendSlice(allocator, ", ");
            try buf.appendSlice(allocator, v);
        }
        vlans_csv = try buf.toOwnedSlice(allocator);
    }

    var out = try std.ArrayList(common.Neighbor).initCapacity(allocator, 1);
    errdefer {
        for (out.items) |*n| n.deinit(allocator);
        out.deinit(allocator);
    }

    try out.append(allocator, .{
        .chassis_id = chassis,
        .port_id = port_id,
        .system_name = name,
        .system_desc = desc,
        .port_desc = port_desc,
        .vlans_csv = vlans_csv,
    });

    info.deinit(allocator);
    return try out.toOwnedSlice(allocator);
}

fn parseLLDP(allocator: std.mem.Allocator, iface: []const u8) LldpError!LldpInfo {
    var info: LldpInfo = .{};
    errdefer info.deinit(allocator);

    var child = std.process.Child.init(&[_][]const u8{ "lldpctl", iface }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return LldpError.LldpctlFailed;

    const out = child.stdout.?.readToEndAlloc(allocator, 256 * 1024) catch
        return LldpError.LldpctlFailed;
    defer allocator.free(out);

    const term = child.wait() catch return LldpError.LldpctlFailed;
    switch (term) {
        .Exited => |code| {
            if (code != 0 and out.len == 0) return info;
        },
        else => return LldpError.LldpctlFailed,
    }

    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");

        if (parseValueAfterPrefix(line, "SysName:")) |val| {
            if (info.sys_name) |old| allocator.free(old);
            info.sys_name = try allocator.dupe(u8, val);
            continue;
        }
        if (parseValueAfterPrefix(line, "SysDescr:")) |val| {
            if (info.sys_desc) |old| allocator.free(old);
            info.sys_desc = try allocator.dupe(u8, val);
            continue;
        }
        if (parseValueAfterPrefix(line, "ChassisID:")) |val| {
            if (info.chassis_id) |old| allocator.free(old);
            info.chassis_id = try allocator.dupe(u8, val);
            continue;
        }
        if (parseValueAfterPrefix(line, "PortID:")) |val| {
            if (info.port_id) |old| allocator.free(old);
            info.port_id = try allocator.dupe(u8, val);
            continue;
        }
        if (parseValueAfterPrefix(line, "PortDescr:")) |val| {
            if (info.port_descr) |old| allocator.free(old);
            info.port_descr = try allocator.dupe(u8, val);
            continue;
        }
        if (parseValueAfterPrefix(line, "VLAN:")) |val| {
            const v = try allocator.dupe(u8, val);
            try info.vlans.append(allocator, v);
            continue;
        }
    }

    return info;
}

fn parseValueAfterPrefix(line: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    return std.mem.trim(u8, line[prefix.len..], " \t\r");
}
