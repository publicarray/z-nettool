const std = @import("std");

pub fn resolveIpv4(alloc: std.mem.Allocator, host: []const u8) !?std.net.Address {
    var list = try std.net.getAddressList(alloc, host, 0);
    defer list.deinit();

    for (list.addrs) |a| {
        if (a.any.family == std.posix.AF.INET) return a;
    }
    return null;
}

pub fn icmpChecksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum));
}

pub fn fillRandom(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

pub fn randomU16() u16 {
    var b: [2]u8 = undefined;
    fillRandom(&b);
    return std.mem.readInt(u16, &b, .big);
}
