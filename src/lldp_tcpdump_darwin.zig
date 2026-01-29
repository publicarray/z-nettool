const std = @import("std");
const common = @import("lldp_common.zig");

pub const LldpError = error{CaptureFailed} || std.mem.Allocator.Error;

pub fn collectAndParseCommon(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    return captureViaTcpdump(alloc, iface, listen_seconds);
}

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

fn captureViaTcpdump(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    var child = std.process.Child.init(&[_][]const u8{
        "tcpdump", "-n", "-l", "-U", "-s", "1600", "-c", "1", "-XX", "-i", iface, "ether", "proto", "0x88cc",
    }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior = .Ignore;

    child.spawn() catch return LldpError.CaptureFailed;

    var output = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer output.deinit(alloc);

    var timer = try std.time.Timer.start();
    const timeout_ns: u64 = @as(u64, listen_seconds) * std.time.ns_per_s;

    const stdout_file = child.stdout.?;
    const stdout_fd = stdout_file.handle;

    while (true) {
        const elapsed = timer.read();
        if (elapsed >= timeout_ns) break;

        const remaining_ns = timeout_ns - elapsed;
        const wait_ms: i32 = @intCast(@max(@as(u64, 1), remaining_ns / std.time.ns_per_ms));
        var fds = [_]std.posix.pollfd{.{ .fd = stdout_fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = try std.posix.poll(&fds, wait_ms);
        if (rc == 0) continue;

        var buf: [1024]u8 = undefined;
        const n = stdout_file.read(&buf) catch break;
        if (n == 0) break;
        try output.appendSlice(alloc, buf[0..n]);
    }

    _ = child.kill() catch {};
    const term = child.wait() catch return LldpError.CaptureFailed;

    var stderr_buf: []u8 = &.{};
    if (child.stderr) |stderr_file| {
        stderr_buf = stderr_file.readToEndAlloc(alloc, 8 * 1024) catch &.{};
    }
    defer if (stderr_buf.len != 0) alloc.free(stderr_buf);

    if (output.items.len == 0) {
        if (stderr_buf.len != 0) return LldpError.CaptureFailed;
        switch (term) {
            .Exited => |code| if (code != 0) return LldpError.CaptureFailed,
            else => {},
        }
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
    var it = std.mem.tokenizeAny(u8, s, " \t");
    while (it.next()) |tok| {
        if (tok.len == 0 or (tok.len % 2) != 0) break;
        var all_hex = true;
        for (tok) |c| {
            if (fromHex(c) == null) {
                all_hex = false;
                break;
            }
        }
        if (!all_hex) break;
        var i: usize = 0;
        while (i < tok.len) : (i += 2) {
            try dst.append(alloc, std.ascii.toLower(tok[i]));
            try dst.append(alloc, std.ascii.toLower(tok[i + 1]));
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
