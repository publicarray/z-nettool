const std = @import("std");
const common = @import("lldp_common.zig");

pub const Neighbor = struct {
    chassis_id: []u8,
    port_id: []u8,
    system_name: []u8,
    port_desc: []u8,
    sys_desc: []u8,
    vlan: ?u16,

    pub fn deinit(self: *Neighbor, alloc: std.mem.Allocator) void {
        alloc.free(self.chassis_id);
        alloc.free(self.port_id);
        alloc.free(self.system_name);
        alloc.free(self.port_desc);
        alloc.free(self.sys_desc);
    }
};

const PktmonFile = "PktMon-lldp.etl";
const PktmonTxt = "PktMon-lldp.txt";

pub fn collectAndParse(alloc: std.mem.Allocator, listen_seconds: u32) ![]Neighbor {
    // Stop any previous capture and remove old files
    _ = run(alloc, &.{ "pktmon", "stop" }) catch {};
    _ = std.fs.cwd().deleteFile(PktmonFile) catch {};
    _ = std.fs.cwd().deleteFile(PktmonTxt) catch {};

    errdefer {
        _ = std.fs.cwd().deleteFile(PktmonFile) catch {};
        _ = std.fs.cwd().deleteFile(PktmonTxt) catch {};
    }

    // Start capture (LLDP ethertype)
    // NOTE: requires Admin (your manifest already forces this)
    try run(alloc, &.{
        "pktmon",      "start",
        "--capture",   "--pkt-size",
        "1600",        "--etw",
        "-f",          "ethernet.type==0x88cc",
        "--file-name", PktmonFile,
    });

    // Wait capture window with a simple countdown
    try printCountdown(listen_seconds);

    // Stop + convert to text with hex
    _ = run(alloc, &.{ "pktmon", "stop" }) catch {};
    try run(alloc, &.{ "pktmon", "etl2txt", PktmonFile, "--hex", "--out", PktmonTxt });

    // Parse & Cleanup
    const data = try parsePktmonTxt(alloc, PktmonTxt);
    _ = std.fs.cwd().deleteFile(PktmonFile) catch {};
    _ = std.fs.cwd().deleteFile(PktmonTxt) catch {};
    return data;
}

pub fn collectAndParseCommon(alloc: std.mem.Allocator, listen_seconds: u32) ![]common.Neighbor {
    const neigh = try collectAndParse(alloc, listen_seconds);
    defer {
        for (neigh) |*n| n.deinit(alloc);
        alloc.free(neigh);
    }

    var out = try std.ArrayList(common.Neighbor).initCapacity(alloc, neigh.len);
    errdefer {
        for (out.items) |*n| n.deinit(alloc);
        out.deinit(alloc);
    }

    for (neigh) |n| {
        const vlans_csv = if (n.vlan) |v|
            try std.fmt.allocPrint(alloc, "{d}", .{v})
        else
            try alloc.dupe(u8, "(none)");

        try out.append(alloc, .{
            .chassis_id = try alloc.dupe(u8, n.chassis_id),
            .port_id = try alloc.dupe(u8, n.port_id),
            .system_name = try alloc.dupe(u8, n.system_name),
            .system_desc = try alloc.dupe(u8, n.sys_desc),
            .port_desc = try alloc.dupe(u8, n.port_desc),
            .vlans_csv = vlans_csv,
        });
    }

    return try out.toOwnedSlice(alloc);
}

fn printCountdown(listen_seconds: u32) !void {
    var out_buf: [256]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var remaining: u32 = listen_seconds;
    while (remaining > 0) : (remaining -= 1) {
        try out.print("\r  Capturing LLDP... {d}s remaining ", .{remaining});
        try out.flush();
        std.Thread.sleep(std.time.ns_per_s);
    }

    try out.print("\r  Capturing LLDP... done.          \n", .{});
    try out.flush();
}

fn run(alloc: std.mem.Allocator, argv: []const []const u8) !void {
    var cp = std.process.Child.init(argv, alloc);
    cp.stdin_behavior = .Ignore;
    cp.stdout_behavior = .Ignore;
    cp.stderr_behavior = .Ignore;
    const term = try cp.spawnAndWait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn parsePktmonTxt(alloc: std.mem.Allocator, path: []const u8) ![]Neighbor {
    const data = try std.fs.cwd().readFileAlloc(alloc, path, 50 * 1024 * 1024);
    defer alloc.free(data);

    // pktmon often outputs UTF-16LE. Detect and convert to UTF-8.
    const text = try decodePossiblyUtf16LeToUtf8Alloc(alloc, data);
    defer alloc.free(text);

    var out = try std.ArrayList(Neighbor).initCapacity(alloc, 0);
    errdefer {
        for (out.items) |*n| n.deinit(alloc);
        out.deinit(alloc);
    }

    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();

    // keep keys so we can free them (StringHashMap does not free key memory)
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

        if (std.mem.indexOf(u8, line, "PktGroupId") != null) {
            if (current_hex.items.len > 0) {
                try consumeFrameHex(alloc, current_hex.items, &out, &seen, &seen_keys);
                current_hex.clearRetainingCapacity();
            }
            continue;
        }

        // Lines like: "  0x0000: 01 80 c2 ..."
        if (std.mem.indexOf(u8, line, "0x") != null and std.mem.indexOfScalar(u8, line, ':') != null) {
            const colon = std.mem.indexOfScalar(u8, line, ':').?;
            const rhs = line[colon + 1 ..];
            try appendHexDigits(alloc, &current_hex, rhs);
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
    out: *std.ArrayList(Neighbor),
    seen: *std.StringHashMap(void),
    seen_keys: *std.ArrayList([]u8),
) !void {
    // Find ethertype 88cc
    const idx = std.mem.indexOf(u8, frame_hex, "88cc") orelse return;

    // After ethertype is LLDPDU
    const payload_hex = frame_hex[idx + 4 ..];
    const payload = try hexToBytesAlloc(alloc, payload_hex);
    defer alloc.free(payload);

    const info = try parseLLDP(alloc, payload) orelse return;

    // Dedup key: chassis|port|system
    const key = try std.fmt.allocPrint(alloc, "{s}|{s}|{s}", .{ info.chassis_id, info.port_id, info.system_name });

    // If already present, free key + neighbor and bail
    if (seen.contains(key)) {
        alloc.free(key);
        var tmp = info;
        tmp.deinit(alloc);
        return;
    }

    // Insert and remember key for later freeing
    try seen.put(key, {});
    try seen_keys.append(alloc, key);

    try out.append(alloc, info);
}

fn hexToBytesAlloc(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    // Must be even length; if odd, drop last nibble
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

// -------- LLDP parsing --------

fn parseLLDP(alloc: std.mem.Allocator, lldpdu: []const u8) !?Neighbor {
    var chassis: ?[]u8 = null;
    var portid: ?[]u8 = null;
    var ttl_seen = false;
    var port_desc: ?[]u8 = null;
    var sys_name: ?[]u8 = null;
    var sys_desc: ?[]u8 = null;
    var vlan: ?u16 = null;

    var i: usize = 0;
    while (i + 2 <= lldpdu.len) {
        const h = (@as(u16, lldpdu[i]) << 8) | lldpdu[i + 1];
        i += 2;

        const tlv_type: u8 = @intCast(h >> 9);
        const tlv_len: usize = @intCast(h & 0x01ff);

        if (i + tlv_len > lldpdu.len) break;
        const v = lldpdu[i .. i + tlv_len];
        i += tlv_len;

        if (tlv_type == 0) break; // end

        switch (tlv_type) {
            1 => { // Chassis ID
                if (v.len >= 2) chassis = try decodeIdValue(alloc, v);
            },
            2 => { // Port ID
                if (v.len >= 2) portid = try decodeIdValue(alloc, v);
            },
            3 => { // TTL
                ttl_seen = true;
            },
            4 => { // Port Description
                port_desc = try alloc.dupe(u8, v);
            },
            5 => { // System Name
                sys_name = try alloc.dupe(u8, v);
            },
            6 => { // System Description
                sys_desc = try alloc.dupe(u8, v);
            },
            127 => { // Org specific
                // IEEE 802.1 OUI 00-80-C2, subtype 1 = Port VLAN ID
                if (v.len >= 6 and v[0] == 0x00 and v[1] == 0x80 and v[2] == 0xC2) {
                    const subtype = v[3];
                    if (subtype == 0x01 and v.len >= 6) {
                        vlan = (@as(u16, v[4]) << 8) | v[5];
                    }
                }
            },
            else => {},
        }
    }

    if (chassis == null or portid == null or !ttl_seen) {
        // Not a valid LLDP neighbor record
        if (chassis) |s| alloc.free(s);
        if (portid) |s| alloc.free(s);
        if (port_desc) |s| alloc.free(s);
        if (sys_name) |s| alloc.free(s);
        if (sys_desc) |s| alloc.free(s);
        return null;
    }

    return Neighbor{
        .chassis_id = chassis.?,
        .port_id = portid.?,
        .system_name = sys_name orelse try alloc.dupe(u8, ""),
        .port_desc = port_desc orelse try alloc.dupe(u8, ""),
        .sys_desc = sys_desc orelse try alloc.dupe(u8, ""),
        .vlan = vlan,
    };
}

fn decodeIdValue(alloc: std.mem.Allocator, v: []const u8) ![]u8 {
    // first byte is subtype, rest is value. We’ll render common ones.
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

// -------- UTF-16LE decode for pktmon output --------

fn decodePossiblyUtf16LeToUtf8Alloc(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    // BOM for UTF-16LE is FF FE
    const looks_utf16le = (data.len >= 2 and data[0] == 0xFF and data[1] == 0xFE) or looksLikeUtf16(data);

    if (!looks_utf16le) return try alloc.dupe(u8, data);

    // Convert bytes (little-endian) to u16 slice
    const start: usize = if (data.len >= 2 and data[0] == 0xFF and data[1] == 0xFE) 2 else 0;
    const n16 = (data.len - start) / 2;

    var u16s = try alloc.alloc(u16, n16);
    defer alloc.free(u16s);

    var i: usize = 0;
    while (i < n16) : (i += 1) {
        const lo = data[start + i * 2];
        const hi = data[start + i * 2 + 1];
        u16s[i] = (@as(u16, hi) << 8) | lo;
    }

    // Now encode to UTF-8 (best-effort)
    var out = try std.ArrayList(u8).initCapacity(alloc, data.len);
    defer out.deinit(alloc);

    var it = std.unicode.Utf16LeIterator.init(u16s);
    while (true) {
        const cp_opt = it.nextCodepoint() catch break;
        if (cp_opt == null) break;
        var tmp: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(cp_opt.?, &tmp) catch continue;
        try out.appendSlice(alloc, tmp[0..len]);
    }

    return try out.toOwnedSlice(alloc);
}

fn looksLikeUtf16(data: []const u8) bool {
    if (data.len < 8) return false;
    var zeros: usize = 0;
    var i: usize = 1;
    while (i < data.len and i < 200) : (i += 2) {
        if (data[i] == 0) zeros += 1;
    }
    return zeros > 10;
}
