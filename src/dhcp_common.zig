const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("netinet/in.h");
    @cInclude("net/if.h");
    @cInclude("sys/socket.h");
});

pub const magic_cookie = [_]u8{ 0x63, 0x82, 0x53, 0x63 };

pub const Opt = struct {
    pub const msg_type: u8 = 53;
    pub const param_req: u8 = 55;
    pub const router: u8 = 3;
    pub const dns: u8 = 6;
    pub const lease: u8 = 51;
    pub const server_id: u8 = 54;
    pub const end: u8 = 255;
};

pub const Msg = struct {
    pub const discover: u8 = 1;
    pub const offer: u8 = 2;
    pub const ack: u8 = 5;
};

pub const Offer = struct {
    your_ip: [16]u8 = [_]u8{0} ** 16,
    server_id: [16]u8 = [_]u8{0} ** 16,
    router: [16]u8 = [_]u8{0} ** 16,
    dns: [64]u8 = [_]u8{0} ** 64,
    lease: [32]u8 = [_]u8{0} ** 32,
    xid: u32 = 0,
    xid_match: bool = true,
};

pub const OfferLabels = struct {
    ip: []const u8,
    server: []const u8,
    lease: []const u8,
    router: []const u8,
    dns: []const u8,
};

pub const UdpListenResult = struct {
    got_offer: bool = false,
    received_any: bool = false,
};

pub const labels_default = OfferLabels{
    .ip = "IP Offered",
    .server = "Server",
    .lease = "Lease Time",
    .router = "Router",
    .dns = "DNS",
};

pub fn configureDhcpSocket(sock: std.posix.socket_t) !void {
    const one = std.mem.toBytes(@as(c_int, 1));
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &one);
    if (builtin.os.tag == .macos) {
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, &one);
    }
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, &one);
}

pub fn buildDiscover(alloc: std.mem.Allocator, xid: u32, mac: [6]u8) ![]u8 {
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
    try p.appendSlice(alloc, magic_cookie[0..]);

    try p.appendSlice(alloc, &.{ Opt.msg_type, 1, Msg.discover });
    try p.appendSlice(alloc, &.{ Opt.param_req, 5, 1, 3, 6, 51, 54 });
    try p.append(alloc, Opt.end);

    return try p.toOwnedSlice(alloc);
}

pub fn sendAndListenUdp(
    alloc: std.mem.Allocator,
    iface_name: ?[]const u8,
    mac: [6]u8,
    listen_seconds: u32,
    print_sent: bool,
) !void {
    _ = try sendAndListenUdpWithResult(alloc, iface_name, mac, listen_seconds, print_sent);
}

pub fn sendAndListenUdpWithResult(
    alloc: std.mem.Allocator,
    iface_name: ?[]const u8,
    mac: [6]u8,
    listen_seconds: u32,
    print_sent: bool,
) !UdpListenResult {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var xid_buf: [4]u8 = undefined;
    std.crypto.random.bytes(&xid_buf);
    const xid = std.mem.readInt(u32, &xid_buf, .big);

    const listen_addr = try std.net.Address.parseIp4("0.0.0.0", 68);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    try configureDhcpSocket(sock);

    if (builtin.os.tag == .linux) {
        if (iface_name) |name| {
            const ifname_z = try std.heap.page_allocator.dupeZ(u8, name);
            defer std.heap.page_allocator.free(ifname_z);
            try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, 25, ifname_z);
        }
    }
    if (builtin.os.tag == .macos) {
        if (iface_name) |name| {
            const ifname_z = try std.heap.page_allocator.dupeZ(u8, name);
            defer std.heap.page_allocator.free(ifname_z);
            const ifindex = c.if_nametoindex(ifname_z);
            if (ifindex != 0) {
                try std.posix.setsockopt(
                    sock,
                    c.IPPROTO_IP,
                    c.IP_BOUND_IF,
                    &std.mem.toBytes(@as(c_uint, ifindex)),
                );
            }
        }
    }

    std.posix.bind(sock, &listen_addr.any, listen_addr.getOsSockLen()) catch |e| {
        if (e == error.AddressInUse and builtin.os.tag == .linux) {
            try out.print("  [!] port 68 in use and raw capture unavailable.\n", .{});
            try out.flush();
        }
        return e;
    };

    const pkt = try buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    var timer = try std.time.Timer.start();
    const send_after_ns: u64 = 100 * std.time.ns_per_ms;
    const total_ns: u64 = @as(u64, listen_seconds) * std.time.ns_per_s;
    var sent = false;
    var buf: [2048]u8 = undefined;
    var debug_non_offer_printed = false;
    var received_any = false;
    var got_offer = false;

    while (timer.read() < total_ns) {
        const now = timer.read();
        if (!sent and now >= send_after_ns) {
            _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());
            sent = true;
            if (print_sent) {
                try out.print("  Sent DISCOVER (xid=0x{x})\n", .{xid});
                try out.print("  Listening for {d}s...\n", .{listen_seconds});
                try out.flush();
            }
        }

        const wait_ns = if (sent or now >= send_after_ns) 250 * std.time.ns_per_ms else (send_after_ns - now);
        const wait_ms: i32 = @intCast(@min(wait_ns, total_ns - now) / std.time.ns_per_ms);

        var fds = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = try std.posix.poll(&fds, wait_ms);
        if (rc == 0) continue;

        var from: std.posix.sockaddr = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const n = std.posix.recvfrom(sock, &buf, 0, &from, &from_len) catch continue;
        if (n <= 0) continue;

        const nn: usize = @intCast(n);
        received_any = true;
        if (parseOfferFromBootp(buf[0..nn], xid)) |offer| {
            got_offer = true;
            try printOffer(out, offer, xid, labels_default);
            try out.flush();
        } else if (!debug_non_offer_printed) {
            debug_non_offer_printed = true;
            try out.print("  [debug] received {d} bytes but no DHCP offer parsed\n", .{nn});
            try out.flush();
        }
    }

    if (sent and !received_any) {
        try out.print("  [debug] no UDP packets received on port 68\n", .{});
        try out.flush();
    }

    return .{ .got_offer = got_offer, .received_any = received_any };
}

fn maxLabelLen(labels: OfferLabels) usize {
    var max_len: usize = labels.ip.len;
    if (labels.server.len > max_len) max_len = labels.server.len;
    if (labels.lease.len > max_len) max_len = labels.lease.len;
    if (labels.router.len > max_len) max_len = labels.router.len;
    if (labels.dns.len > max_len) max_len = labels.dns.len;
    if ("XID".len > max_len) max_len = "XID".len;
    return max_len;
}

fn writeSpaces(out: anytype, count: usize) !void {
    const spaces = "                                ";
    var remaining = count;
    while (remaining != 0) {
        const chunk = if (remaining > spaces.len) spaces.len else remaining;
        try out.writeAll(spaces[0..chunk]);
        remaining -= chunk;
    }
}

fn printField(out: anytype, label: []const u8, value: []const u8, max_label: usize) !void {
    try out.print("    {s}:", .{label});
    try writeSpaces(out, (max_label - label.len) + 2);
    try out.print("{s}\n", .{value});
}

pub fn printOffer(out: anytype, offer: Offer, xid_expected: u32, labels: OfferLabels) !void {
    try out.print("\n  DHCP OFFER:\n", .{});
    const max_label = maxLabelLen(labels);
    const ip = std.mem.trimRight(u8, &offer.your_ip, "\x00");
    const server = std.mem.trimRight(u8, &offer.server_id, "\x00");
    const lease = std.mem.trimRight(u8, &offer.lease, "\x00");
    const router = std.mem.trimRight(u8, &offer.router, "\x00");
    const dns = std.mem.trimRight(u8, &offer.dns, " \x00");

    try printField(out, labels.ip, if (ip.len != 0) ip else &offer.your_ip, max_label);
    if (server.len != 0) try printField(out, labels.server, server, max_label);
    if (lease.len != 0) try printField(out, labels.lease, lease, max_label);
    if (router.len != 0) try printField(out, labels.router, router, max_label);
    if (dns.len != 0) try printField(out, labels.dns, dns, max_label);
    if (!offer.xid_match) {
        var buf: [64]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "0x{x} (expected 0x{x})", .{ offer.xid, xid_expected }) catch return;
        try printField(out, "XID", s, max_label);
    }
}

pub fn parseOfferFromBootp(pkt: []const u8, xid_expected: u32) ?Offer {
    // pkt starts at BOOTP op
    if (pkt.len < 240) return null;
    if (pkt[0] != 2) return null; // BOOTREPLY

    const xid = std.mem.readInt(u32, pkt[4..8], .big);
    if (!std.mem.eql(u8, pkt[236..240], magic_cookie[0..])) return null;

    var offer: Offer = .{ .xid = xid, .xid_match = (xid == xid_expected) };
    const yiaddr = pkt[16..20];
    _ = std.fmt.bufPrint(&offer.your_ip, "{d}.{d}.{d}.{d}", .{ yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3] }) catch {};

    var i: usize = 240;
    var msg_type: u8 = 0;
    var lease_seconds: u32 = 0;

    var dns_tmp: [64]u8 = [_]u8{0} ** 64;
    var dns_len: usize = 0;

    while (i < pkt.len) {
        const code = pkt[i];
        i += 1;
        if (code == Opt.end) break;
        if (code == 0) continue;
        if (i >= pkt.len) break;

        const l = pkt[i];
        i += 1;
        if (i + l > pkt.len) break;

        const data = pkt[i .. i + l];
        i += l;

        switch (code) {
            Opt.msg_type => {
                if (data.len == 1) msg_type = data[0];
            },
            Opt.server_id => {
                if (data.len == 4)
                    _ = std.fmt.bufPrint(&offer.server_id, "{d}.{d}.{d}.{d}", .{ data[0], data[1], data[2], data[3] }) catch {};
            },
            Opt.router => {
                if (data.len >= 4)
                    _ = std.fmt.bufPrint(&offer.router, "{d}.{d}.{d}.{d}", .{ data[0], data[1], data[2], data[3] }) catch {};
            },
            Opt.dns => {
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
            Opt.lease => {
                if (data.len == 4) lease_seconds = std.mem.readInt(u32, data[0..4], .big);
            },
            else => {},
        }
    }

    // OFFER=2, ACK=5 (some servers may reply with ACK)
    if (!(msg_type == Msg.offer or msg_type == Msg.ack)) return null;

    if (lease_seconds != 0) {
        const hours: u32 = lease_seconds / 3600;
        const mins: u32 = (lease_seconds % 3600) / 60;
        _ = std.fmt.bufPrint(&offer.lease, "{d}h {d}m", .{ hours, mins }) catch {};
    }

    return offer;
}
