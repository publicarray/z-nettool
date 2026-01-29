const std = @import("std");
const Interface = @import("iface_common.zig").Interface;

pub fn chooseInterface(alloc: std.mem.Allocator, forced: ?[]const u8) !Interface {
    if (forced) |name| {
        const mac = try readMac(alloc, name);
        return .{ .name = try alloc.dupe(u8, name), .mac = mac };
    }

    var entries = try std.ArrayList([]u8).initCapacity(alloc, 0);
    defer {
        for (entries.items) |s| alloc.free(s);
        entries.deinit(alloc);
    }

    var dir = try std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |e| {
        if (e.kind != .directory and e.kind != .sym_link) continue;
        if (std.mem.eql(u8, e.name, ".") or std.mem.eql(u8, e.name, "..")) continue;
        // Skip loopback in the menu
        if (std.mem.eql(u8, e.name, "lo")) continue;
        try entries.append(alloc, try alloc.dupe(u8, e.name));
    }

    if (entries.items.len == 0) return error.NoInterfaces;

    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    try out.print("Select interface:\n", .{});
    for (entries.items, 0..) |name, idx| {
        const mac = readMac(alloc, name) catch [_]u8{0} ** 6;
        try out.print("  {d}) {s}  ({s})\n", .{ idx + 1, name, fmtMac(mac) });
    }
    try out.flush();

    const choice = try readChoice(entries.items.len);
    const selected = entries.items[choice - 1];
    const mac = try readMac(alloc, selected);

    return .{ .name = try alloc.dupe(u8, selected), .mac = mac };
}

fn readMac(alloc: std.mem.Allocator, ifname: []const u8) ![6]u8 {
    _ = alloc;
    var path_buf: [256]u8 = undefined;
    const p = try std.fmt.bufPrint(&path_buf, "/sys/class/net/{s}/address", .{ifname});

    const file = try std.fs.openFileAbsolute(p, .{});
    defer file.close();

    var buf: [64]u8 = undefined;
    const n = try file.readAll(&buf);
    const s = std.mem.trim(u8, buf[0..n], " \r\n\t");

    // Format: "aa:bb:cc:dd:ee:ff"
    if (s.len < 17) return error.BadMac;
    return parseMac(s[0..17]);
}

fn parseMac(s: []const u8) ![6]u8 {
    var mac: [6]u8 = undefined;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        const off = i * 3;
        mac[i] = try std.fmt.parseInt(u8, s[off .. off + 2], 16);
    }
    return mac;
}

fn fmtMac(mac: [6]u8) [17:0]u8 {
    var buf: [17:0]u8 = undefined;
    _ = std.fmt.bufPrintZ(&buf, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch {};
    return buf;
}

fn readChoice(max: usize) !usize {
    var stdin_buf: [1024]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const stdin = &stdin_reader.interface;

    var out_buf: [1024]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var line: [64]u8 = undefined;

    while (true) {
        try out.print("Enter number (1..{d}): ", .{max});
        try out.flush();

        var len: usize = 0;

        while (true) {
            const b = stdin.takeByte() catch |e| switch (e) {
                error.EndOfStream => return error.EndOfStream,
                else => return e,
            };

            if (b == '\n') break;
            if (b == '\r') continue;

            if (len < line.len) {
                line[len] = b;
                len += 1;
            }
        }

        const s = std.mem.trim(u8, line[0..len], " \t\r\n");
        const v = std.fmt.parseInt(usize, s, 10) catch continue;
        if (v >= 1 and v <= max) return v;
    }
}
