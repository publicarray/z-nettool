const std = @import("std");

const c = @cImport({
    @cInclude("pcap/pcap.h");
});

pub const Offer = struct {
    your_ip: [16]u8 = [_]u8{0} ** 16,
    server_id: [16]u8 = [_]u8{0} ** 16,
    router: [16]u8 = [_]u8{0} ** 16,
    dns: [64]u8 = [_]u8{0} ** 64,
    lease: [32]u8 = [_]u8{0} ** 32,
};

fn rd16be(b: []const u8) u16 {
    // caller guarantees b.len >= 2
    const p: *const [2]u8 = @ptrCast(b.ptr);
    return std.mem.readInt(u16, p, .big);
}
fn rd32be(b: []const u8) u32 {
    const p: *const [4]u8 = @ptrCast(b.ptr);
    return std.mem.readInt(u32, p, .big);
}

pub fn sniffOffersLinux(
    iface: []const u8,
    xid_expected: u32,
    seconds: u32,
) !void {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    const iface_z = try std.heap.page_allocator.dupeZ(u8, iface);
    defer std.heap.page_allocator.free(iface_z);

    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const handle = c.pcap_open_live(iface_z.ptr, 1600, 1, 250, &errbuf);
    if (handle == null) {
        try out.print("  [!] pcap_open_live failed: {s}\n", .{std.mem.sliceTo(&errbuf, 0)});
        try out.flush();
        return error.PcapOpenFailed;
    }
    defer c.pcap_close(handle);

    // compile + apply filter
    var fp: c.bpf_program = undefined;
    const filter = "udp and (port 67 or port 68)";
    if (c.pcap_compile(handle, &fp, filter, 1, 0) != 0) {
        try out.print("  [!] pcap_compile failed\n", .{});
        try out.flush();
        return error.PcapCompileFailed;
    }
    defer c.pcap_freecode(&fp);

    if (c.pcap_setfilter(handle, &fp) != 0) {
        try out.print("  [!] pcap_setfilter failed\n", .{});
        try out.flush();
        return error.PcapSetFilterFailed;
    }

    // sniff loop
    var start = try std.time.Timer.start();
    while (start.read() < @as(u64, seconds) * std.time.ns_per_s) {
        var hdr_ptr: ?*c.pcap_pkthdr = null;
        var data_ptr: [*c]const u8 = null;

        const rc = c.pcap_next_ex(handle, &hdr_ptr, &data_ptr);
        if (rc == 0) continue; // timeout
        if (rc < 0) break; // error/break

        const hdr = hdr_ptr.?;
        const pkt = data_ptr[0..@intCast(hdr.caplen)];

        if (tryParseDhcpOffer(pkt, xid_expected)) |offer| {
            try out.print("\n  DHCP OFFER:\n", .{});
            try out.print("    IP Offered:  {s}\n", .{offer.your_ip});
            if (offer.server_id.len != 0) try out.print("    Server:      {s}\n", .{offer.server_id});
            if (offer.lease.len != 0) try out.print("    Lease Time:  {s}\n", .{offer.lease});
            if (offer.router.len != 0) try out.print("    Router:      {s}\n", .{offer.router});
            if (offer.dns.len != 0) try out.print("    DNS:         {s}\n", .{offer.dns});
            try out.flush();

            // If you want: stop after first offer
            // return;
        }
    }
}

fn tryParseDhcpOffer(frame: []const u8, xid_expected: u32) ?Offer {
    // Ethernet header (14) + optional VLAN tags
    if (frame.len < 14) return null;

    var off: usize = 12;
    var ethertype = rd16be(frame[off .. off + 2]);
    off = 14;

    // VLAN tags 0x8100 / 0x88a8
    while (ethertype == 0x8100 or ethertype == 0x88a8) {
        if (frame.len < off + 4) return null;
        ethertype = rd16be(frame[off .. off + 2]);
        off += 4;
    }

    if (ethertype != 0x0800) return null; // IPv4
    if (frame.len < off + 20) return null;

    const ver_ihl = frame[off];
    if ((ver_ihl >> 4) != 4) return null;
    const ihl = @as(usize, (ver_ihl & 0x0f)) * 4;
    if (frame.len < off + ihl + 8) return null;

    const proto = frame[off + 9];
    if (proto != 17) return null; // UDP

    off += ihl;

    const src_port = rd16be(frame[off .. off + 2]);
    const dst_port = rd16be(frame[off + 2 .. off + 4]);
    if (!((src_port == 67 or src_port == 68) and (dst_port == 67 or dst_port == 68))) return null;

    off += 8; // UDP header

    // DHCP/BOOTP payload starts here
    if (frame.len < off + 240) return null; // bootp(236)+cookie(4)
    const dhcp = frame[off..];

    return parseOfferFromBootp(dhcp, xid_expected);
}

fn parseOfferFromBootp(pkt: []const u8, xid_expected: u32) ?Offer {
    // pkt starts at BOOTP op
    if (pkt.len < 240) return null;
    if (pkt[0] != 2) return null; // BOOTREPLY

    const xid = rd32be(pkt[4..8]);
    if (xid != xid_expected) return null;

    if (!std.mem.eql(u8, pkt[236..240], &.{ 0x63, 0x82, 0x53, 0x63 })) return null;

    var offer: Offer = .{};
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
        if (code == 255) break;
        if (code == 0) continue;
        if (i >= pkt.len) break;

        const l = pkt[i];
        i += 1;
        if (i + l > pkt.len) break;

        const data = pkt[i .. i + l];
        i += l;

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

    // OFFER=2, ACK=5. Your sample prints OFFER; you can accept either.
    if (!(msg_type == 2 or msg_type == 5)) return null;

    if (lease_seconds != 0) {
        const hours: u32 = lease_seconds / 3600;
        const mins: u32 = (lease_seconds % 3600) / 60;
        _ = std.fmt.bufPrint(&offer.lease, "{d}h {d}m", .{ hours, mins }) catch {};
    }

    return offer;
}
