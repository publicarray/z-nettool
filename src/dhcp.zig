const std = @import("std");
const builtin = @import("builtin");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
) !void {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    const listen_addr = try std.net.Address.parseIp4("0.0.0.0", 68);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.BROADCAST,
        &std.mem.toBytes(@as(c_int, 1)),
    );

    var xid_buf: [4]u8 = undefined;
    std.crypto.random.bytes(&xid_buf);
    const xid = std.mem.readInt(u32, &xid_buf, .big);

    std.posix.bind(sock, &listen_addr.any, listen_addr.getOsSockLen()) catch |e| {
        if (e == error.AddressInUse and builtin.os.tag == .linux) {
            // send DISCOVER from an ephemeral socket (don’t bind 68), then sniff via pcap
            try sendDiscoverEphemeral(alloc, xid, mac);
            const pcap = @import("dhcp_pcap_linux.zig");
            try pcap.sniffOffersLinux(iface_name, xid, listen_seconds);
            return;
        }
        return e;
    };

    const pkt = try buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());

    try out.print("  Sent DISCOVER (xid=0x{x})\n", .{xid});
    try out.print("  Listening for {d}s...\n", .{listen_seconds});
    try out.flush();

    var timer = try std.time.Timer.start();
    var buf: [2048]u8 = undefined;

    while (timer.read() < (@as(u64, listen_seconds) * std.time.ns_per_s)) {
        var fds = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = try std.posix.poll(&fds, 250);
        if (rc == 0) continue;

        var from: std.posix.sockaddr = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const n = std.posix.recvfrom(sock, &buf, 0, &from, &from_len) catch continue;
        if (n <= 0) continue;

        // Zig 0.15: @intCast takes 1 arg (type inferred)
        const nn: usize = @intCast(n);
        if (parseOffer(buf[0..nn], xid)) |offer| {
            try out.print("\n  DHCP OFFER:\n", .{});
            try out.print("    Your IP:   {s}\n", .{offer.your_ip});
            if (offer.server_id.len != 0) try out.print("    Server ID: {s}\n", .{offer.server_id});
            if (offer.router.len != 0) try out.print("    Router:    {s}\n", .{offer.router});
            if (offer.dns.len != 0) try out.print("    DNS:       {s}\n", .{offer.dns});
            if (offer.lease.len != 0) try out.print("    Lease:     {s}\n", .{offer.lease});
            try out.flush();
        }
    }
}

fn sendDiscoverEphemeral(alloc: std.mem.Allocator, xid: u32, mac: [6]u8) !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.BROADCAST,
        &std.mem.toBytes(@as(c_int, 1)),
    );

    const pkt = try buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());
}

fn buildDiscover(alloc: std.mem.Allocator, xid: u32, mac: [6]u8) ![]u8 {
    var p = try std.ArrayList(u8).initCapacity(alloc, 300);
    errdefer p.deinit(alloc);

    var h: [236]u8 = [_]u8{0} ** 236;
    h[0] = 1; // BOOTREQUEST
    h[1] = 1; // Ethernet
    h[2] = 6; // hlen
    std.mem.writeInt(u32, h[4..8], xid, .big);
    std.mem.writeInt(u16, h[10..12], 0x8000, .big); // broadcast flag
    @memcpy(h[28..34], &mac); // chaddr

    try p.appendSlice(alloc, &h);
    try p.appendSlice(alloc, &.{ 0x63, 0x82, 0x53, 0x63 }); // magic cookie

    try p.appendSlice(alloc, &.{ 53, 1, 1 }); // DHCP Message Type: Discover
    try p.appendSlice(alloc, &.{ 55, 5, 1, 3, 6, 51, 54 }); // PRL
    try p.append(alloc, 255); // end

    return try p.toOwnedSlice(alloc);
}

const Offer = struct {
    your_ip: [16]u8 = [_]u8{0} ** 16,
    server_id: [16]u8 = [_]u8{0} ** 16,
    router: [16]u8 = [_]u8{0} ** 16,
    dns: [64]u8 = [_]u8{0} ** 64,
    lease: [32]u8 = [_]u8{0} ** 32,
};

fn parseOffer(pkt: []const u8, xid_expected: u32) ?Offer {
    if (pkt.len < 240) return null;
    if (pkt[0] != 2) return null;

    const xid = std.mem.readInt(u32, pkt[4..8], .big);
    if (xid != xid_expected) return null;

    const yiaddr = pkt[16..20];
    if (!std.mem.eql(u8, pkt[236..240], &.{ 0x63, 0x82, 0x53, 0x63 })) return null;

    var offer: Offer = .{};
    _ = std.fmt.bufPrint(&offer.your_ip, "{d}.{d}.{d}.{d}", .{ yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3] }) catch {};

    var i: usize = 240;
    var msg_type: u8 = 0;
    var lease_seconds: u32 = 0;

    var dns_tmp: [64]u8 = [_]u8{0} ** 64;
    var dns_len: usize = 0;

    while (i < pkt.len) {
        const code = pkt[i];
        i += 1;
        if (code == 255) break;
        if (code == 0) continue;
        if (i >= pkt.len) break;

        const l = pkt[i];
        i += 1;
        if (i + l > pkt.len) break;

        const data = pkt[i .. i + l];
        i += l;

        // Zig 0.15: use blocks for side effects (no “comma arms”)
        switch (code) {
            53 => {
                if (data.len == 1) msg_type = data[0];
            },
            54 => {
                if (data.len == 4)
                    _ = std.fmt.bufPrint(&offer.server_id, "{d}.{d}.{d}.{d}", .{ data[0], data[1], data[2], data[3] }) catch {};
            },
            3 => {
                if (data.len >= 4)
                    _ = std.fmt.bufPrint(&offer.router, "{d}.{d}.{d}.{d}", .{ data[0], data[1], data[2], data[3] }) catch {};
            },
            6 => {
                var j: usize = 0;
                while (j + 3 < data.len) : (j += 4) {
                    const part = std.fmt.bufPrint(dns_tmp[dns_len..], "{d}.{d}.{d}.{d} ", .{
                        data[j], data[j + 1], data[j + 2], data[j + 3],
                    }) catch break;
                    dns_len += part.len;
                    if (dns_len >= dns_tmp.len) break;
                }
                _ = std.fmt.bufPrint(&offer.dns, "{s}", .{dns_tmp[0..dns_len]}) catch {};
            },
            51 => {
                if (data.len == 4) lease_seconds = std.mem.readInt(u32, data[0..4], .big);
            },
            else => {},
        }
    }

    if (msg_type != 2) return null;

    if (lease_seconds != 0) {
        const hours: u32 = lease_seconds / 3600;
        const mins: u32 = (lease_seconds % 3600) / 60;
        _ = std.fmt.bufPrint(&offer.lease, "{d}h {d}m", .{ hours, mins }) catch {};
    }

    return offer;
}
