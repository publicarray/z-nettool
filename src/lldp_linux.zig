const std = @import("std");

pub const LldpError = error{LldpctlFailed} || std.mem.Allocator.Error;

pub const LldpInfo = struct {
    sys_name: ?[]u8 = null,
    port_id: ?[]u8 = null,
    port_descr: ?[]u8 = null,
    vlans: std.ArrayListUnmanaged([]u8) = .{},

    pub fn deinit(self: *LldpInfo, allocator: std.mem.Allocator) void {
        if (self.sys_name) |s| allocator.free(s);
        if (self.port_id) |s| allocator.free(s);
        if (self.port_descr) |s| allocator.free(s);

        for (self.vlans.items) |v| allocator.free(v);
        self.vlans.deinit(allocator);

        self.* = undefined;
    }
};

pub fn parseLLDP(allocator: std.mem.Allocator, iface: []const u8) LldpError!LldpInfo {
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
        .Exited => |code| if (code != 0) return LldpError.LldpctlFailed,
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
