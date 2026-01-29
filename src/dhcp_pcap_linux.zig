const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");

const c = @cImport({
    @cInclude("pcap/pcap.h");
});

pub const Offer = dhcp_common.Offer;

pub const SendDiscoverFn = *const fn (ctx: *anyopaque) anyerror!void;

fn rd16be(b: []const u8) u16 {
    // caller guarantees b.len >= 2
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

    if (c.pcap_setnonblock(handle, 1, &errbuf) != 0) {
        try out.print("  [!] pcap_setnonblock failed: {s}\n", .{std.mem.sliceTo(&errbuf, 0)});
        try out.flush();
    }

    const linktype = c.pcap_datalink(handle);

    // Small delay to ensure capture is fully active before sending.
    std.Thread.sleep(50 * std.time.ns_per_ms);

    send_discover(send_ctx) catch |e| {
        try out.print("  [!] send DISCOVER failed: {s}\n", .{@errorName(e)});
        try out.flush();
    };

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

        if (tryParseDhcpOfferLink(pkt, linktype, xid_expected)) |offer| {
            try dhcp_common.printOffer(out, offer, xid_expected, dhcp_common.labels_default);
            try out.flush();

            // If you want: stop after first offer
            // return;
        }
    }
}

fn tryParseDhcpOfferLink(frame: []const u8, linktype: c_int, xid_expected: u32) ?Offer {
    if (linktype == c.DLT_EN10MB) return tryParseDhcpOfferEther(frame, xid_expected);
    if (linktype == c.DLT_LINUX_SLL) return tryParseDhcpOfferSll(frame, xid_expected, false);
    if (@hasDecl(c, "DLT_LINUX_SLL2")) {
        if (linktype == c.DLT_LINUX_SLL2) return tryParseDhcpOfferSll(frame, xid_expected, true);
    }
    return null;
}

fn tryParseDhcpOfferEther(frame: []const u8, xid_expected: u32) ?Offer {
    // Ethernet header (14) + optional VLAN tags
    if (frame.len < 14) return null;

    var off: usize = 12;
    var ethertype = rd16be(frame[off .. off + 2]);
    off = 14;

    // VLAN tags 0x8100 / 0x88a8
    while (ethertype == 0x8100 or ethertype == 0x88a8) {
        if (frame.len < off + 4) return null;
        ethertype = rd16be(frame[off + 2 .. off + 4]);
        off += 4;
    }

    return parseOfferFromProto(ethertype, frame[off..], xid_expected);
}

fn tryParseDhcpOfferSll(frame: []const u8, xid_expected: u32, sll2: bool) ?Offer {
    if (!sll2) {
        // Linux cooked v1 header: 16 bytes, protocol at offset 14
        if (frame.len < 16) return null;
        const proto = rd16be(frame[14..16]);
        return parseOfferFromProto(proto, frame[16..], xid_expected);
    }

    // Linux cooked v2 header: 20 bytes, protocol at offset 0
    if (frame.len < 20) return null;
    const proto = rd16be(frame[0..2]);
    return parseOfferFromProto(proto, frame[20..], xid_expected);
}

fn parseOfferFromProto(proto: u16, payload: []const u8, xid_expected: u32) ?Offer {
    var ethertype = proto;
    var p = payload;

    // VLAN tags 0x8100 / 0x88a8
    while (ethertype == 0x8100 or ethertype == 0x88a8) {
        if (p.len < 4) return null;
        ethertype = rd16be(p[2..4]);
        p = p[4..];
    }

    if (ethertype != 0x0800) return null; // IPv4
    return parseOfferFromIp(p, xid_expected);
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

    off += 8; // UDP header

    // DHCP/BOOTP payload starts here
    if (pkt.len < off + 240) return null; // bootp(236)+cookie(4)
    const dhcp = pkt[off..];

    return dhcp_common.parseOfferFromBootp(dhcp, xid_expected);
}
