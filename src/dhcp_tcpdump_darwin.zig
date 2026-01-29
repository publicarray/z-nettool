const std = @import("std");
const dhcp_common = @import("dhcp_common.zig");
const c = @cImport({
    @cInclude("net/if.h");
    @cInclude("netinet/in.h");
    @cInclude("sys/socket.h");
});

pub fn captureOfferViaTcpdump(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    listen_seconds: u32,
) !void {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var xid_buf: [4]u8 = undefined;
    std.crypto.random.bytes(&xid_buf);
    const xid = std.mem.readInt(u32, &xid_buf, .big);

    try out.print("  [debug] capturing DHCP OFFER via tcpdump for up to {d}s...\n", .{listen_seconds});
    try out.flush();

    var child = std.process.Child.init(&[_][]const u8{
        "tcpdump", "-n",  "-l",  "-U",   "-s", "0",   "-XX", "-c",   "1",  "-i", iface_name,
        "udp",     "and", "src", "port", "67", "and", "dst", "port", "68",
    }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.stdin_behavior = .Ignore;

    child.spawn() catch {
        try out.print("  [debug] tcpdump spawn failed (try sudo)\n", .{});
        try out.flush();
        return;
    };

    // Allow tcpdump to attach before sending.
    std.Thread.sleep(100 * std.time.ns_per_ms);

    sendDiscoverUdp(alloc, iface_name, mac, xid) catch |e| {
        try out.print("  [debug] failed to send DISCOVER for tcpdump capture ({s})\n", .{@errorName(e)});
        try out.flush();
    };

    var output = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer output.deinit(alloc);

    var timer = try std.time.Timer.start();
    const timeout_ns: u64 = @as(u64, listen_seconds) * std.time.ns_per_s;

    const stdout_file = child.stdout.?;
    const stdout_fd = stdout_file.handle;

    while (true) {
        const elapsed = timer.read();
        if (elapsed >= timeout_ns) break;

        const remaining_ns = timeout_ns - elapsed;
        const wait_ms: i32 = @intCast(@max(@as(u64, 1), remaining_ns / std.time.ns_per_ms));
        var fds = [_]std.posix.pollfd{.{ .fd = stdout_fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const rc = try std.posix.poll(&fds, wait_ms);
        if (rc == 0) continue;

        var buf: [1024]u8 = undefined;
        const n = stdout_file.read(&buf) catch break;
        if (n == 0) break; // EOF
        try output.appendSlice(alloc, buf[0..n]);
    }

    _ = child.kill() catch {};
    _ = child.wait() catch {};

    var stderr_buf: []u8 = &.{};
    if (child.stderr) |stderr_file| {
        stderr_buf = stderr_file.readToEndAlloc(alloc, 8 * 1024) catch &.{};
    }
    defer if (stderr_buf.len != 0) alloc.free(stderr_buf);

    if (output.items.len == 0) {
        if (stderr_buf.len != 0) {
            const msg = std.mem.trim(u8, stderr_buf, " \t\r\n");
            try out.print("  [debug] tcpdump failed: {s}\n", .{msg});
            try out.flush();
        }
        return;
    }

    if (parseOfferFromTcpdumpText(alloc, output.items, xid)) |offer| {
        try dhcp_common.printOffer(out, offer, xid, dhcp_common.labels_udp);
        try out.print("\n", .{});
        try out.flush();
    } else {
        try out.print("  [debug] tcpdump captured packet but no DHCP offer parsed\n", .{});
        try out.flush();
    }
}

fn parseOfferFromTcpdumpText(
    alloc: std.mem.Allocator,
    text: []const u8,
    xid_expected: u32,
) ?dhcp_common.Offer {
    var bytes = std.ArrayList(u8).initCapacity(alloc, 0) catch return null;
    defer bytes.deinit(alloc);

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        if (std.mem.indexOf(u8, line, "0x") != null and std.mem.indexOfScalar(u8, line, ':') != null) {
            const colon = std.mem.indexOfScalar(u8, line, ':').?;
            const rhs = line[colon + 1 ..];
            appendHexBytes(alloc, &bytes, rhs) catch return null;
        }
    }

    if (bytes.items.len == 0) return null;
    return parseOfferFromFrame(bytes.items, xid_expected);
}

fn appendHexBytes(alloc: std.mem.Allocator, dst: *std.ArrayList(u8), s: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, s, " \t");
    while (it.next()) |tok| {
        if (tok.len == 0 or (tok.len % 2) != 0) break;
        var all_hex = true;
        for (tok) |cch| {
            if (fromHex(cch) == null) {
                all_hex = false;
                break;
            }
        }
        if (!all_hex) break;
        var i: usize = 0;
        while (i < tok.len) : (i += 2) {
            const hi = fromHex(tok[i]) orelse return;
            const lo = fromHex(tok[i + 1]) orelse return;
            try dst.append(alloc, (hi << 4) | lo);
        }
    }
}

fn fromHex(cch: u8) ?u8 {
    return switch (cch) {
        '0'...'9' => cch - '0',
        'a'...'f' => 10 + (cch - 'a'),
        'A'...'F' => 10 + (cch - 'A'),
        else => null,
    };
}

fn parseOfferFromFrame(frame: []const u8, xid_expected: u32) ?dhcp_common.Offer {
    if (frame.len < 240) return null;
    const cookie = dhcp_common.magic_cookie[0..];
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, frame, pos, cookie)) |idx| {
        if (idx >= 236) {
            if (dhcp_common.parseOfferFromBootp(frame[idx - 236 ..], xid_expected)) |offer| {
                return offer;
            }
        }
        pos = idx + 1;
    }
    return null;
}

fn sendDiscoverUdp(
    alloc: std.mem.Allocator,
    iface_name: []const u8,
    mac: [6]u8,
    xid: u32,
) !void {
    const listen_addr = try std.net.Address.parseIp4("0.0.0.0", 68);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    try dhcp_common.configureDhcpSocket(sock);

    const ifname_z = try std.heap.page_allocator.dupeZ(u8, iface_name);
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

    try std.posix.bind(sock, &listen_addr.any, listen_addr.getOsSockLen());

    const pkt = try dhcp_common.buildDiscover(alloc, xid, mac);
    defer alloc.free(pkt);

    const bcast = try std.net.Address.parseIp4("255.255.255.255", 67);
    _ = try std.posix.sendto(sock, pkt, 0, &bcast.any, bcast.getOsSockLen());
}
