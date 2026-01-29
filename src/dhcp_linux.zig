const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");

pub fn discoverAndListen(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
    force_udp: bool,
) !void {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var xid_buf: [4]u8 = undefined;
    std.crypto.random.bytes(&xid_buf);
    const xid = std.mem.readInt(u32, &xid_buf, .big);

    if (!force_udp) {
        // Prefer pcap on Linux so we can see all offers (even if another DHCP client owns port 68).
        var send_ctx = SendCtx{
            .alloc = alloc,
            .iface_name = iface_name,
            .xid = xid,
            .mac = mac,
        };
        try out.print("  Sent DISCOVER (xid=0x{x})\n", .{xid});
        try out.print("  Listening for {d}s...\n", .{listen_seconds});
        try out.flush();

        const pcap = @import("dhcp_pcap_linux.zig");
        if (pcap.sniffOffersLinux(iface_name, xid, listen_seconds, &send_ctx, sendDiscoverCb)) |_| return else |e| {
            // Fall back to UDP if pcap isn't available (permissions, missing libpcap, etc.)
            try out.print("  [!] pcap sniff failed ({s}); falling back to UDP\n", .{@errorName(e)});
            try out.flush();
        }
    }

    const listen_addr = try std.net.Address.parseIp4("0.0.0.0", 68);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    const ifname_z = try std.heap.page_allocator.dupeZ(u8, iface_name);
    defer std.heap.page_allocator.free(ifname_z);
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, 25, ifname_z);

    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.BROADCAST,
        &std.mem.toBytes(@as(c_int, 1)),
    );

    std.posix.bind(sock, &listen_addr.any, listen_addr.getOsSockLen()) catch |e| {
        if (e == error.AddressInUse) {
            try out.print("  [!] port 68 in use and pcap unavailable.\n", .{});
            try out.flush();
        }
        return e;
    };

    const pkt = try dhcp_common.buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());

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

        const nn: usize = @intCast(n);
        if (dhcp_common.parseOfferFromBootp(buf[0..nn], xid)) |offer| {
            try dhcp_common.printOffer(out, offer, xid, dhcp_common.labels_udp);
            try out.flush();
        }
    }
}

const SendCtx = struct {
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    xid: u32,
    mac: [6]u8,
};

fn sendDiscoverCb(ctx: *anyopaque) !void {
    const c: *SendCtx = @ptrCast(@alignCast(ctx));
    try sendDiscoverEphemeral(c.alloc, c.iface_name, c.xid, c.mac);
}

fn sendDiscoverEphemeral(alloc: std.mem.Allocator, iface_name: []const u8, xid: u32, mac: [6]u8) !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    const ifname_z = try std.heap.page_allocator.dupeZ(u8, iface_name);
    defer std.heap.page_allocator.free(ifname_z);
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, 25, ifname_z);

    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.BROADCAST,
        &std.mem.toBytes(@as(c_int, 1)),
    );

    const pkt = try dhcp_common.buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());
}
