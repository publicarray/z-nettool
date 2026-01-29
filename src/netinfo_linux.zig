const std = @import("std");

pub const NetInfo = struct {
    ip_cidr: []u8, // owned, like "10.0.0.107/24" or ""
    link: []u8, // owned, like "up 1000Mb/s" or "[unknown]"
    pub fn deinit(self: *NetInfo, alloc: std.mem.Allocator) void {
        alloc.free(self.ip_cidr);
        alloc.free(self.link);
        self.* = undefined;
    }
};

pub fn getNetInfo(alloc: std.mem.Allocator, iface: []const u8) !NetInfo {
    const ip = try ipCidrFromIpJson(alloc, iface);
    const link = try linkFromSysfs(alloc, iface);
    return .{ .ip_cidr = ip, .link = link };
}

fn ipCidrFromIpJson(alloc: std.mem.Allocator, iface: []const u8) ![]u8 {
    // ip -j addr show dev <iface>
    var child = std.process.Child.init(&.{ "ip", "-j", "addr", "show", "dev", iface }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(out_bytes);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return try alloc.dupe(u8, ""),
        else => return try alloc.dupe(u8, ""),
    }

    // Parse JSON: [ { "addr_info": [ { "family":"inet", "local":"10.0.0.107", "prefixlen":24 }, ... ] } ]
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out_bytes, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .array or root.array.items.len == 0) return try alloc.dupe(u8, "");

    const obj = root.array.items[0];
    if (obj != .object) return try alloc.dupe(u8, "");

    const addr_info_v = obj.object.get("addr_info") orelse return try alloc.dupe(u8, "");
    if (addr_info_v != .array) return try alloc.dupe(u8, "");

    for (addr_info_v.array.items) |ai| {
        if (ai != .object) continue;

        const fam_v = ai.object.get("family") orelse continue;
        if (fam_v != .string) continue;
        if (!std.mem.eql(u8, fam_v.string, "inet")) continue;

        const local_v = ai.object.get("local") orelse continue;
        const pre_v = ai.object.get("prefixlen") orelse continue;
        if (local_v != .string or pre_v != .integer) continue;

        return try std.fmt.allocPrint(alloc, "{s}/{d}", .{ local_v.string, pre_v.integer });
    }

    return try alloc.dupe(u8, "");
}

fn readSysfsTrim(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.openFileAbsolute(path, .{});
    defer f.close();
    var buf: [128]u8 = undefined;
    const n = try f.readAll(&buf);
    return try alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \t\r\n"));
}

fn linkFromSysfs(alloc: std.mem.Allocator, iface: []const u8) ![]u8 {
    var p1: [256]u8 = undefined;
    var p2: [256]u8 = undefined;

    const oper = try std.fmt.bufPrint(&p1, "/sys/class/net/{s}/operstate", .{iface});
    const speedp = try std.fmt.bufPrint(&p2, "/sys/class/net/{s}/speed", .{iface});

    const oper_s = readSysfsTrim(alloc, oper) catch return try alloc.dupe(u8, "[unknown]");
    defer alloc.free(oper_s);

    // speed may not exist (wifi often doesn't expose)
    const speed_s = readSysfsTrim(alloc, speedp) catch return try std.fmt.allocPrint(alloc, "{s} [unknown]", .{oper_s});
    defer alloc.free(speed_s);

    // speed is typically "1000" meaning Mb/s
    const sp = std.fmt.parseInt(u32, speed_s, 10) catch return try std.fmt.allocPrint(alloc, "{s} [unknown]", .{oper_s});

    return try std.fmt.allocPrint(alloc, "{s} {d}Mb/s", .{ oper_s, sp });
}
