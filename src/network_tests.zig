const std = @import("std");
const builtin = @import("builtin");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    return @import("ping.zig").pingMs(alloc, host);
}

pub fn dnsLookupA(alloc: std.mem.Allocator, name: []const u8) !?[]u8 {
    var list = try std.net.getAddressList(alloc, name, 0);
    defer list.deinit();

    for (list.addrs) |a| {
        if (a.any.family == std.posix.AF.INET) {
            const ip = a.in.sa.addr; // u32 IPv4 (network byte order)
            const b0: u8 = @intCast((ip >> 0) & 0xff);
            const b1: u8 = @intCast((ip >> 8) & 0xff);
            const b2: u8 = @intCast((ip >> 16) & 0xff);
            const b3: u8 = @intCast((ip >> 24) & 0xff);
            return try std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 });
        }
    }
    return null;
}

pub fn httpsStatus(alloc: std.mem.Allocator, url: []const u8) !?u16 {
    var client: std.http.Client = .{ .allocator = alloc };
    defer client.deinit();

    const result = std.http.Client.fetch(&client, .{
        .location = .{ .url = url },
        .method = .GET,
        .keep_alive = false,
    }) catch return null;

    return @as(u16, @intFromEnum(result.status));
}
