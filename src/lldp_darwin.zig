const std = @import("std");
const common = @import("lldp_common.zig");

pub fn collectAndParseCommon(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    return collectAndParseCommonDarwin(alloc, iface, listen_seconds);
}

pub const LldpError = error{LldpctlFailed} || std.mem.Allocator.Error;

pub const LldpInfo = struct {
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

fn collectAndParseCommonDarwin(allocator: std.mem.Allocator, iface: []const u8, listen_seconds: u32) LldpError![]common.Neighbor {
    var info = parseLLDP(allocator, iface) catch |e| switch (e) {
        LldpError.LldpctlFailed => {
            return captureViaTcpdump(allocator, iface, listen_seconds) catch e;
        },
        else => return e,
    };
    errdefer info.deinit(allocator);

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

fn captureViaTcpdump(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    var child = std.process.Child.init(&[_][]const u8{
        "tcpdump", "-n", "-s", "1600", "-c", "1", "-XX", "-i", iface, "ether", "proto", "0x88cc",
    }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.stdin_behavior = .Ignore;

    child.spawn() catch return LldpError.LldpctlFailed;

    var poller = std.Io.poll(alloc, enum { stdout }, .{ .stdout = child.stdout.? });
    defer poller.deinit();

    var output = try std.ArrayList(u8).initCapacity(alloc, 4096);
    errdefer output.deinit(alloc);

    var timer = try std.time.Timer.start();
    const timeout_ns: u64 = @as(u64, listen_seconds) * std.time.ns_per_s;

    while (true) {
        const elapsed = timer.read();
        if (elapsed >= timeout_ns) {
            _ = child.kill() catch {};
            break;
        }
        const remaining = timeout_ns - elapsed;
        const ready = try poller.pollTimeout(remaining);
        if (!ready) continue;

        var reader = poller.reader(.stdout);
        var buf: [1024]u8 = undefined;
        const n = reader.readSliceShort(&buf) catch {
            break;
        };
        if (n == 0) continue;
        try output.appendSlice(alloc, buf[0..n]);
    }

    _ = child.wait() catch {};

    if (output.items.len == 0) {
        var empty = try std.ArrayList(common.Neighbor).initCapacity(alloc, 0);
        return empty.toOwnedSlice(alloc);
    }

    return parseTcpdumpText(alloc, output.items);
}

fn parseTcpdumpText(alloc: std.mem.Allocator, text: []const u8) ![]common.Neighbor {
    var out = try std.ArrayList(common.Neighbor).initCapacity(alloc, 0);
    errdefer {
        for (out.items) |*n| n.deinit(alloc);
        out.deinit(alloc);
    }

    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();
    var seen_keys = try std.ArrayList([]u8).initCapacity(alloc, 0);
    defer {
        for (seen_keys.items) |k| alloc.free(k);
        seen_keys.deinit(alloc);
    }

    var current_hex = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer current_hex.deinit(alloc);

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");

        if (std.mem.indexOf(u8, line, "0x") != null and std.mem.indexOfScalar(u8, line, ':') != null) {
            const colon = std.mem.indexOfScalar(u8, line, ':').?;
            const rhs = line[colon + 1 ..];
            try appendHexDigits(alloc, &current_hex, rhs);
            continue;
        }

        if (current_hex.items.len > 0) {
            try consumeFrameHex(alloc, current_hex.items, &out, &seen, &seen_keys);
            current_hex.clearRetainingCapacity();
        }
    }

    if (current_hex.items.len > 0) {
        try consumeFrameHex(alloc, current_hex.items, &out, &seen, &seen_keys);
    }

    return try out.toOwnedSlice(alloc);
}

fn appendHexDigits(alloc: std.mem.Allocator, dst: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
            try dst.append(alloc, std.ascii.toLower(c));
        }
    }
}

fn consumeFrameHex(
    alloc: std.mem.Allocator,
    frame_hex: []const u8,
    out: *std.ArrayList(common.Neighbor),
    seen: *std.StringHashMap(void),
    seen_keys: *std.ArrayList([]u8),
) !void {
    const idx = std.mem.indexOf(u8, frame_hex, "88cc") orelse return;
    const payload_hex = frame_hex[idx + 4 ..];
    const payload = try hexToBytesAlloc(alloc, payload_hex);
    defer alloc.free(payload);

    var info = try parseLLDPFromBytes(alloc, payload) orelse return;
    defer info.deinit(alloc);

    const key = try std.fmt.allocPrint(alloc, "{s}|{s}|{s}", .{ info.chassis_id.?, info.port_id.?, info.sys_name.? });
    if (seen.contains(key)) {
        alloc.free(key);
        return;
    }
    try seen.put(key, {});
    try seen_keys.append(alloc, key);

    const vlans_csv = if (info.vlans.items.len == 0) try alloc.dupe(u8, "(none)") else blk: {
        var buf = try std.ArrayList(u8).initCapacity(alloc, 32);
        errdefer buf.deinit(alloc);
        for (info.vlans.items, 0..) |v, i| {
            if (i != 0) try buf.appendSlice(alloc, ", ");
            try buf.appendSlice(alloc, v);
        }
        break :blk try buf.toOwnedSlice(alloc);
    };

    try out.append(alloc, .{
        .chassis_id = try alloc.dupe(u8, info.chassis_id.?),
        .port_id = try alloc.dupe(u8, info.port_id.?),
        .system_name = try alloc.dupe(u8, info.sys_name.?),
        .system_desc = try alloc.dupe(u8, info.sys_desc.?),
        .port_desc = try alloc.dupe(u8, info.port_descr.?),
        .vlans_csv = vlans_csv,
    });
}

fn hexToBytesAlloc(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len < 2) return error.BadHex;
    const n = hex.len / 2;
    var out = try alloc.alloc(u8, n);
    errdefer alloc.free(out);

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const hi = fromHex(hex[i * 2]) orelse return error.BadHex;
        const lo = fromHex(hex[i * 2 + 1]) orelse return error.BadHex;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn fromHex(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => 10 + (c - 'a'),
        'A'...'F' => 10 + (c - 'A'),
        else => null,
    };
}

fn parseLLDPFromBytes(alloc: std.mem.Allocator, lldpdu: []const u8) !?LldpInfo {
    var info: LldpInfo = .{};
    errdefer info.deinit(alloc);

    var chassis: ?[]u8 = null;
    var portid: ?[]u8 = null;
    var ttl_seen = false;

    var i: usize = 0;
    while (i + 2 <= lldpdu.len) {
        const h = (@as(u16, lldpdu[i]) << 8) | lldpdu[i + 1];
        i += 2;

        const tlv_type: u8 = @intCast(h >> 9);
        const tlv_len: usize = @intCast(h & 0x01ff);

        if (i + tlv_len > lldpdu.len) break;
        const v = lldpdu[i .. i + tlv_len];
        i += tlv_len;

        if (tlv_type == 0) break;

        switch (tlv_type) {
            1 => {
                if (v.len >= 2) chassis = try decodeIdValue(alloc, v);
            },
            2 => {
                if (v.len >= 2) portid = try decodeIdValue(alloc, v);
            },
            3 => ttl_seen = true,
            4 => info.port_descr = try alloc.dupe(u8, v),
            5 => info.sys_name = try alloc.dupe(u8, v),
            6 => info.sys_desc = try alloc.dupe(u8, v),
            127 => {
                if (v.len >= 6 and v[0] == 0x00 and v[1] == 0x80 and v[2] == 0xC2) {
                    const subtype = v[3];
                    if (subtype == 0x01 and v.len >= 6) {
                        const vlan = (@as(u16, v[4]) << 8) | v[5];
                        const s = try std.fmt.allocPrint(alloc, "{d}", .{vlan});
                        try info.vlans.append(alloc, s);
                    }
                }
            },
            else => {},
        }
    }

    if (chassis == null or portid == null or !ttl_seen) {
        if (chassis) |s| alloc.free(s);
        if (portid) |s| alloc.free(s);
        return null;
    }

    info.chassis_id = chassis;
    info.port_id = portid;
    if (info.sys_name == null) info.sys_name = try alloc.dupe(u8, "");
    if (info.sys_desc == null) info.sys_desc = try alloc.dupe(u8, "");
    if (info.port_descr == null) info.port_descr = try alloc.dupe(u8, "");

    return info;
}

fn decodeIdValue(alloc: std.mem.Allocator, v: []const u8) ![]u8 {
    const subtype = v[0];
    const value = v[1..];

    if ((subtype == 3 or subtype == 4) and value.len == 6) {
        return try std.fmt.allocPrint(alloc, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
            value[0], value[1], value[2], value[3], value[4], value[5],
        });
    }

    if ((subtype == 4 or subtype == 5) and value.len >= 5 and value[0] == 1) {
        const ip = value[1..5];
        return try std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    if ((subtype == 4 or subtype == 5) and value.len >= 17 and value[0] == 2) {
        const ip6 = value[1..17];
        return try std.fmt.allocPrint(
            alloc,
            "{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}",
            .{
                ip6[0], ip6[1], ip6[2],  ip6[3],  ip6[4],  ip6[5],  ip6[6],  ip6[7],
                ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15],
            },
        );
    }

    if (subtype == 1 or subtype == 2 or subtype == 5 or subtype == 6 or subtype == 7) {
        var printable = true;
        for (value) |c| {
            if (!std.ascii.isPrint(c)) {
                printable = false;
                break;
            }
        }
        if (printable) return try alloc.dupe(u8, value);

        var buf = try std.ArrayList(u8).initCapacity(alloc, value.len * 3);
        errdefer buf.deinit(alloc);
        for (value, 0..) |c, i| {
            if (i != 0) try buf.append(alloc, ':');
            var tmp: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&tmp, "{X:0>2}", .{c}) catch {};
            try buf.appendSlice(alloc, &tmp);
        }
        return try buf.toOwnedSlice(alloc);
    }

    return try alloc.dupe(u8, value);
}
