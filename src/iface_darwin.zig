const std = @import("std");
const iface_common = @import("iface_common.zig");
const d = @import("darwin_if.zig");

pub fn chooseInterface(alloc: std.mem.Allocator, forced: ?[]const u8) !iface_common.Interface {
    const adapters = try getAdapters(alloc);
    defer {
        for (adapters) |a| alloc.free(a.name);
        alloc.free(adapters);
    }

    if (adapters.len == 0) return error.NoInterfaces;

    if (forced) |name| {
        for (adapters) |a| {
            if (std.mem.eql(u8, a.name, name)) {
                return .{ .name = try alloc.dupe(u8, a.name), .mac = a.mac };
            }
        }
        return error.InterfaceNotFound;
    }

    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    try out.print("Select interface:\n", .{});
    for (adapters, 0..) |a, idx| {
        try out.print("  {d}) {s}  ({s})\n", .{ idx + 1, a.name, fmtMac(a.mac) });
    }
    try out.flush();

    const choice = try readChoice(adapters.len);
    const selected = adapters[choice - 1];
    return .{ .name = try alloc.dupe(u8, selected.name), .mac = selected.mac };
}

const Adapter = struct {
    name: []u8,
    mac: [6]u8,
};

fn getAdapters(alloc: std.mem.Allocator) ![]Adapter {
    var ifap: ?*d.ifaddrs = null;
    if (d.getifaddrs(&ifap) != 0) return error.GetIfAddrsFailed;
    defer d.freeifaddrs(ifap);

    var list = try std.ArrayList(Adapter).initCapacity(alloc, 0);
    errdefer {
        for (list.items) |a| alloc.free(a.name);
        list.deinit(alloc);
    }

    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_name == null) continue;
        if ((ifa.ifa_flags & d.IFF_LOOPBACK) != 0) continue;

        const name = std.mem.span(@as([*:0]const u8, @ptrCast(ifa.ifa_name)));
        if (seen.contains(name)) continue;

        const addr = ifa.ifa_addr orelse continue;
        if (addr.*.sa_family != d.AF_LINK) continue;
        const sdl = @as(*const d.sockaddr_dl, @ptrCast(@alignCast(addr)));
        if (sdl.sdl_alen < 6) continue;

        const data_ptr: [*]const u8 = @ptrCast(&sdl.sdl_data);
        const mac_ptr = data_ptr + @as(usize, sdl.sdl_nlen);
        var mac: [6]u8 = undefined;
        @memcpy(&mac, mac_ptr[0..6]);

        const name_copy = try alloc.dupe(u8, name);
        try seen.put(name_copy, {});
        try list.append(alloc, .{ .name = name_copy, .mac = mac });
    }

    return try list.toOwnedSlice(alloc);
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
