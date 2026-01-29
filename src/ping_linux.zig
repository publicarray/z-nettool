const std = @import("std");
const ping_common = @import("ping_common.zig");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    const addr = (try ping_common.resolveIpv4(alloc, host)) orelse return null;

    const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW, std.posix.IPPROTO.ICMP) catch return null;
    defer std.posix.close(sock);

    const id: u16 = @truncate(@as(u32, @intCast(std.posix.getpid())));
    const seq: u16 = 1;

    var payload: [32]u8 = undefined;
    @memset(&payload, 0xA5);

    var packet: [8 + payload.len]u8 = undefined;
    packet[0] = 8; // echo request
    packet[1] = 0; // code
    packet[2] = 0;
    packet[3] = 0;
    std.mem.writeInt(u16, packet[4..6], id, .big);
    std.mem.writeInt(u16, packet[6..8], seq, .big);
    @memcpy(packet[8..], &payload);
    const sum = ping_common.icmpChecksum(&packet);
    std.mem.writeInt(u16, packet[2..4], sum, .big);

    const start_ns = std.time.nanoTimestamp();
    _ = std.posix.sendto(sock, &packet, 0, &addr.any, addr.getOsSockLen()) catch return null;

    const timeout_ns: i64 = 2 * std.time.ns_per_s;
    while (true) {
        const now = std.time.nanoTimestamp();
        const elapsed = now - start_ns;
        if (elapsed >= timeout_ns) return null;
        const remaining_ms: i32 = @intCast((timeout_ns - elapsed + std.time.ns_per_ms - 1) / std.time.ns_per_ms);

        var pfd = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = std.posix.poll(&pfd, remaining_ms) catch return null;
        if (rc == 0) return null;

        var recv_buf: [1024]u8 = undefined;
        const n = std.posix.recvfrom(sock, &recv_buf, 0, null, null) catch continue;
        if (n < 20 + 8) continue;

        const ip_header_len = (@as(usize, recv_buf[0] & 0x0F)) * 4;
        if (n < ip_header_len + 8) continue;
        const icmp = recv_buf[ip_header_len..n];
        if (icmp[0] != 0 or icmp[1] != 0) continue;
        const r_id = std.mem.readInt(u16, icmp[4..6], .big);
        const r_seq = std.mem.readInt(u16, icmp[6..8], .big);
        if (r_id != id or r_seq != seq) continue;

        const end_ns = std.time.nanoTimestamp();
        return @as(f64, @floatFromInt(end_ns - start_ns)) / @as(f64, std.time.ns_per_ms);
    }
}
