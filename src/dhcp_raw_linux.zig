const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");

const c = @cImport({
    @cInclude("net/if.h");
    @cInclude("linux/if_packet.h");
});

pub const Offer = dhcp_common.Offer;
pub const SendDiscoverFn = *const fn (ctx: *anyopaque) anyerror!void;

const ETH_P_ALL: u16 = 0x0003;

fn rd16be(b: []const u8) u16 {
    const p: *const [2]u8 = @ptrCast(b.ptr);
    return std.mem.readInt(u16, p, .big);
}

pub fn sniffOffersLinux(
    iface: []const u8,
    xid_expected: u32,
    seconds: u32,
    send_ctx: *anyopaque,
    send_discover: SendDiscoverFn,
) !void {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    const proto: u32 = @as(u32, std.mem.nativeToBig(u16, ETH_P_ALL));
    const sock = std.posix.socket(std.os.linux.AF.PACKET, std.posix.SOCK.RAW, proto) catch |e| {
        try out.print("  [!] raw socket create failed: {s}\n", .{@errorName(e)});
        try out.flush();
        return error.RawSocketOpenFailed;
    };
    defer std.posix.close(sock);

    const iface_z = try std.heap.page_allocator.dupeZ(u8, iface);
    defer std.heap.page_allocator.free(iface_z);
    const ifindex = c.if_nametoindex(iface_z);
    if (ifindex == 0) {
        try out.print("  [!] interface not found: {s}\n", .{iface});
        try out.flush();
        return error.InterfaceNotFound;
    }

    var addr: c.struct_sockaddr_ll = undefined;
    addr.sll_family = std.os.linux.AF.PACKET;
    addr.sll_protocol = std.mem.nativeToBig(u16, ETH_P_ALL);
    addr.sll_ifindex = @intCast(ifindex);
    addr.sll_hatype = 0;
    addr.sll_pkttype = 0;
    addr.sll_halen = 0;

    std.posix.bind(sock, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_ll)) catch |e| {
        try out.print("  [!] raw socket bind failed: {s}\n", .{@errorName(e)});
        try out.flush();
        return error.RawSocketBindFailed;
    };

    // Small delay to ensure capture is active before sending.
    std.Thread.sleep(50 * std.time.ns_per_ms);

    send_discover(send_ctx) catch |e| {
        try out.print("  [!] send DISCOVER failed: {s}\n", .{@errorName(e)});
        try out.flush();
    };

    var start = try std.time.Timer.start();
    var buf: [2048]u8 = undefined;

    while (start.read() < @as(u64, seconds) * std.time.ns_per_s) {
        var fds = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = std.posix.poll(&fds, 250) catch continue;
        if (rc == 0) continue;

        const len = std.posix.recvfrom(sock, buf[0..], 0, null, null) catch continue;
        if (len == 0) continue;

        const pkt = buf[0..len];
        if (tryParseDhcpOfferEther(pkt, xid_expected)) |offer| {
            try dhcp_common.printOffer(out, offer, xid_expected, dhcp_common.labels_default);
            try out.flush();
        }
    }
}

fn tryParseDhcpOfferEther(frame: []const u8, xid_expected: u32) ?Offer {
    if (frame.len < 14) return null;

    var off: usize = 12;
    var ethertype = rd16be(frame[off .. off + 2]);
    off = 14;

    while (ethertype == 0x8100 or ethertype == 0x88a8) {
        if (frame.len < off + 4) return null;
        ethertype = rd16be(frame[off + 2 .. off + 4]);
        off += 4;
    }

    if (ethertype != 0x0800) return null; // IPv4
    return parseOfferFromIp(frame[off..], xid_expected);
}

fn parseOfferFromIp(pkt: []const u8, xid_expected: u32) ?Offer {
    if (pkt.len < 20) return null;

    const ver_ihl = pkt[0];
    if ((ver_ihl >> 4) != 4) return null;
    const ihl = @as(usize, (ver_ihl & 0x0f)) * 4;
    if (pkt.len < ihl + 8) return null;

    const proto = pkt[9];
    if (proto != 17) return null; // UDP

    var off: usize = ihl;

    const src_port = rd16be(pkt[off .. off + 2]);
    const dst_port = rd16be(pkt[off + 2 .. off + 4]);
    if (!((src_port == 67 or src_port == 68) and (dst_port == 67 or dst_port == 68))) return null;

    off += 8;

    if (pkt.len < off + 240) return null;
    const dhcp = pkt[off..];

    return dhcp_common.parseOfferFromBootp(dhcp, xid_expected);
}
