const std = @import("std");
const common = @import("netinfo_common.zig");

pub fn getNetInfoCommon(alloc: std.mem.Allocator, iface: []const u8) !common.NetInfo {
    const ip = try ipAddrsFromIpJson(alloc, iface);
    var ip4 = ip.ip4;
    var ip6 = ip.ip6;
    if (ip4.len == 0) {
        alloc.free(ip4);
        ip4 = try alloc.dupe(u8, "[unknown]");
    }
    if (ip6.len == 0) {
        alloc.free(ip6);
        ip6 = try alloc.dupe(u8, "");
    }

    const link = try linkPartsFromSysfs(alloc, iface);
    return .{
        .ip_cidr = ip4,
        .ip6_cidr = ip6,
        .link_state = link.state,
        .link_kind = link.kind,
        .link_speed = link.speed,
        .link_duplex = link.duplex,
    };
}

const IpAddrs = struct {
    ip4: []u8,
    ip6: []u8,
};

fn ipAddrsFromIpJson(alloc: std.mem.Allocator, iface: []const u8) !IpAddrs {
    // ip -j addr show dev <iface>
    var child = std.process.Child.init(&.{ "ip", "-j", "addr", "show", "dev", iface }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(out_bytes);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") },
        else => return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") },
    }

    // Parse JSON: [ { "addr_info": [ { "family":"inet", "local":"10.0.0.107", "prefixlen":24 }, ... ] } ]
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out_bytes, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .array or root.array.items.len == 0)
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };

    const obj = root.array.items[0];
    if (obj != .object)
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };

    const addr_info_v = obj.object.get("addr_info") orelse
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };
    if (addr_info_v != .array)
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };

    var ip4: ?[]u8 = null;
    var ip6: ?[]u8 = null;
    for (addr_info_v.array.items) |ai| {
        if (ai != .object) continue;

        const fam_v = ai.object.get("family") orelse continue;
        if (fam_v != .string) continue;

        const local_v = ai.object.get("local") orelse continue;
        const pre_v = ai.object.get("prefixlen") orelse continue;
        if (local_v != .string or pre_v != .integer) continue;

        if (std.mem.eql(u8, fam_v.string, "inet")) {
            if (ip4 == null)
                ip4 = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ local_v.string, pre_v.integer });
        } else if (std.mem.eql(u8, fam_v.string, "inet6")) {
            if (ip6 == null) {
                if (std.ascii.startsWithIgnoreCase(local_v.string, "fe80:")) continue;
                ip6 = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ local_v.string, pre_v.integer });
            }
        }
    }

    return .{
        .ip4 = ip4 orelse try alloc.dupe(u8, ""),
        .ip6 = ip6 orelse try alloc.dupe(u8, ""),
    };
}

fn readSysfsTrim(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.openFileAbsolute(path, .{});
    defer f.close();
    var buf: [128]u8 = undefined;
    const n = try f.readAll(&buf);
    return try alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \t\r\n"));
}

const LinkParts = struct {
    state: []u8,
    kind: []u8,
    speed: []u8,
    duplex: []u8,
};

fn linkPartsFromSysfs(alloc: std.mem.Allocator, iface: []const u8) !LinkParts {
    var p1: [256]u8 = undefined;
    var p2: [256]u8 = undefined;
    var p3: [256]u8 = undefined;

    const oper = try std.fmt.bufPrint(&p1, "/sys/class/net/{s}/operstate", .{iface});
    const speedp = try std.fmt.bufPrint(&p2, "/sys/class/net/{s}/speed", .{iface});
    const duplp = try std.fmt.bufPrint(&p3, "/sys/class/net/{s}/duplex", .{iface});

    const oper_s = readSysfsTrim(alloc, oper) catch return LinkParts{
        .state = try alloc.dupe(u8, "unknown"),
        .kind = try alloc.dupe(u8, "unknown"),
        .speed = try alloc.dupe(u8, "unknown speed"),
        .duplex = try alloc.dupe(u8, "unknown"),
    };

    const duplex_s = readSysfsTrim(alloc, duplp) catch try alloc.dupe(u8, "unknown");

    // speed may not exist (wifi often doesn't expose)
    const speed_s = readSysfsTrim(alloc, speedp) catch try alloc.dupe(u8, "unknown");

    var kind_s: []u8 = undefined;
    var speed_out: []u8 = undefined;

    const sp = std.fmt.parseInt(u32, speed_s, 10) catch null;
    if (sp) |mbps| {
        kind_s = try alloc.dupe(u8, "ethernet");
        if (mbps >= 1000) {
            const gbps = @as(f64, @floatFromInt(mbps)) / 1000.0;
            speed_out = try std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{gbps});
        } else {
            speed_out = try std.fmt.allocPrint(alloc, "{d} Mbps", .{mbps});
        }
    } else {
        kind_s = try alloc.dupe(u8, "unknown");
        speed_out = try alloc.dupe(u8, "unknown speed");
    }

    const state_s = try alloc.dupe(u8, oper_s);

    alloc.free(oper_s);
    alloc.free(speed_s);

    return .{
        .state = state_s,
        .kind = kind_s,
        .speed = speed_out,
        .duplex = duplex_s,
    };
}
