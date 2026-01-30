const std = @import("std");

const linux = std.os.linux;
const nl = @cImport({
    @cInclude("linux/nl80211.h");
});

const sockaddr_nl = extern struct {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
};

const nlmsghdr = extern struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

const genlmsghdr = extern struct {
    cmd: u8,
    version: u8,
    reserved: u16,
};

const nlattr = extern struct {
    nla_len: u16,
    nla_type: u16,
};

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NL80211_CMD_GET_STATION: u8 = nl.NL80211_CMD_GET_STATION;
const NL80211_CMD_GET_INTERFACE: u8 = nl.NL80211_CMD_GET_INTERFACE;
const NL80211_CMD_GET_SCAN: u8 = nl.NL80211_CMD_GET_SCAN;
const NL80211_ATTR_IFINDEX: u16 = nl.NL80211_ATTR_IFINDEX;
const NL80211_ATTR_STA_INFO: u16 = nl.NL80211_ATTR_STA_INFO;
const NL80211_ATTR_BSS: u16 = nl.NL80211_ATTR_BSS;
const NL80211_ATTR_MAC: u16 = nl.NL80211_ATTR_MAC;
const NL80211_ATTR_BSSID: u16 = nl.NL80211_ATTR_BSSID;

const NL80211_STA_INFO_TX_BITRATE: u16 = nl.NL80211_STA_INFO_TX_BITRATE;
const NL80211_STA_INFO_RX_BITRATE: u16 = nl.NL80211_STA_INFO_RX_BITRATE;

const NL80211_RATE_INFO_BITRATE: u16 = nl.NL80211_RATE_INFO_BITRATE; // 100 kbps (u16)
const NL80211_RATE_INFO_BITRATE32: u16 = nl.NL80211_RATE_INFO_BITRATE32; // 100 kbps (u32)

const NL80211_BSS_STATUS: u16 = nl.NL80211_BSS_STATUS;
const NL80211_BSS_BSSID: u16 = nl.NL80211_BSS_BSSID;
const NL80211_BSS_STATUS_ASSOCIATED: u32 = nl.NL80211_BSS_STATUS_ASSOCIATED;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = 0x3fff;

const GENL_VERSION: u8 = 1;

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

fn nlmsgAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn nlaAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn nlaType(raw: u16) u16 {
    return raw & NLA_TYPE_MASK;
}

fn ifIndexLinux(iface: []const u8) !u32 {
    if (iface.len >= std.posix.IFNAMESIZE) return error.NameTooLong;
    var ifr: std.posix.ifreq = undefined;
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    ifr.ifrn.name[iface.len] = 0;

    const sockfd = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(sockfd);
    try std.posix.ioctl_SIOCGIFINDEX(sockfd, &ifr);
    return @bitCast(ifr.ifru.ivalue);
}

pub fn phySpeedFromNl80211(alloc: std.mem.Allocator, iface: []const u8) !?[]u8 {
    const ifindex = ifIndexLinux(iface) catch return null;
    const debug = false;
    const pid: u32 = @intCast(std.os.linux.getpid());

    const fd = try std.posix.socket(linux.PF.NETLINK, std.posix.SOCK.RAW | std.posix.SOCK.CLOEXEC, linux.NETLINK.GENERIC);
    defer std.posix.close(fd);

    var local = sockaddr_nl{
        .nl_family = linux.PF.NETLINK,
        .nl_pad = 0,
        .nl_pid = pid,
        .nl_groups = 0,
    };
    try std.posix.bind(fd, @ptrCast(&local), @sizeOf(sockaddr_nl));

    var nl80211_id: u16 = 0;
    if (getNl80211FamilyIdFromProc(alloc)) |id| {
        nl80211_id = id;
    } else |_| {}
    if (nl80211_id == 0) {
        nl80211_id = getNl80211FamilyId(fd, pid) catch return null;
    }
    if (nl80211_id == 0) {
        if (phySpeedFromDebugfs(alloc, iface)) |s| return s;
        return null;
    }

    if (try getStationTxRateSimple(alloc, fd, nl80211_id, ifindex, pid, debug)) |rate| return rate;
    if (try getStationTxRateDump(alloc, fd, nl80211_id, ifindex, pid, debug)) |rate| return rate;

    const bssid_iface = getBssidFromInterface(fd, nl80211_id, ifindex, pid, debug) catch null;
    if (bssid_iface) |bssid| {
        if (try getStationTxRate(alloc, fd, nl80211_id, ifindex, bssid, pid, debug)) |rate| return rate;
    }

    const bssid = getAssociatedBssid(fd, nl80211_id, ifindex, pid, debug) catch return null;
    if (bssid == null) {
        if (phySpeedFromDebugfs(alloc, iface)) |s| return s;
        return null;
    }
    if (try getStationTxRate(alloc, fd, nl80211_id, ifindex, bssid.?, pid, debug)) |rate| return rate;
    return phySpeedFromDebugfs(alloc, iface);
}

fn getNl80211FamilyId(fd: std.posix.fd_t, pid: u32) !u16 {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const name = "nl80211";
    const name_len = name.len + 1;
    const nla_len: u16 = @intCast(@sizeOf(nlattr) + name_len);

    const msg_len: u32 = @intCast(@sizeOf(nlmsghdr) + @sizeOf(genlmsghdr) + nlaAlign(nla_len));
    const hdr = nlmsghdr{
        .nlmsg_len = msg_len,
        .nlmsg_type = GENL_ID_CTRL,
        .nlmsg_flags = linux.NLM_F_REQUEST,
        .nlmsg_seq = 1,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = CTRL_CMD_GETFAMILY, .version = GENL_VERSION, .reserved = 0 };
    const attr = nlattr{ .nla_len = nla_len, .nla_type = CTRL_ATTR_FAMILY_NAME };

    try w.writeAll(std.mem.asBytes(&hdr));
    try w.writeAll(std.mem.asBytes(&gen));
    try w.writeAll(std.mem.asBytes(&attr));
    try w.writeAll(name);
    try w.writeByte(0);

    const pad = nlaAlign(nla_len) - nla_len;
    if (pad > 0) try w.writeByteNTimes(0, pad);

    const msg = fbs.getWritten();
    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [4096]u8 = undefined;
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        if (parseFamilyId(recv_buf[0..@intCast(n)])) |id| {
            if (id != 0) return id;
        } else |_| {}
    }
    const dump_id = try getNl80211FamilyIdDump(fd, pid);
    return dump_id;
}

fn parseFamilyId(buf: []const u8) !u16 {
    var off: usize = 0;
    while (off + @sizeOf(nlmsghdr) <= buf.len) {
        var hdr: nlmsghdr = undefined;
        @memcpy(std.mem.asBytes(&hdr), buf[off .. off + @sizeOf(nlmsghdr)]);
        if (hdr.nlmsg_len < @sizeOf(nlmsghdr)) break;
        const end = off + hdr.nlmsg_len;
        if (end > buf.len) break;

        if (hdr.nlmsg_type == NLMSG_ERROR) {
            const payload = buf[off + @sizeOf(nlmsghdr) .. end];
            if (payload.len >= 4) {
                const err = std.mem.readInt(i32, @as(*const [4]u8, @ptrCast(payload[0..4])), .little);
                if (err == 0) {
                    off += nlmsgAlign(hdr.nlmsg_len);
                    continue;
                }
            }
            break;
        }

        const payload = buf[off + @sizeOf(nlmsghdr) .. end];
        if (payload.len < @sizeOf(genlmsghdr)) {
            off = nlmsgAlign(end);
            continue;
        }
        const attrs = payload[@sizeOf(genlmsghdr)..];
        var aoff: usize = 0;
        while (aoff + @sizeOf(nlattr) <= attrs.len) {
            var a: nlattr = undefined;
            @memcpy(std.mem.asBytes(&a), attrs[aoff .. aoff + @sizeOf(nlattr)]);
            if (a.nla_len < @sizeOf(nlattr)) break;
            const aend = aoff + a.nla_len;
            if (aend > attrs.len) break;

            const t = nlaType(a.nla_type);
            if (t == CTRL_ATTR_FAMILY_ID and a.nla_len >= @sizeOf(nlattr) + 2) {
                const val = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(attrs[aoff + @sizeOf(nlattr) .. aoff + @sizeOf(nlattr) + 2])), .little);
                return val;
            }

            aoff += nlaAlign(a.nla_len);
        }

        off += nlmsgAlign(hdr.nlmsg_len);
    }
    return 0;
}

fn getNl80211FamilyIdDump(fd: std.posix.fd_t, pid: u32) !u16 {
    var msg = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 128);
    defer msg.deinit(std.heap.page_allocator);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = GENL_ID_CTRL,
        .nlmsg_flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
        .nlmsg_seq = 7,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = CTRL_CMD_GETFAMILY, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&hdr));
    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&gen));
    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [8192]u8 = undefined;
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        if (parseFamilyIdDump(recv_buf[0..@intCast(n)])) |id| {
            if (id != 0) return id;
        } else |_| {}
    }
    return 0;
}

fn parseFamilyIdDump(buf: []const u8) !u16 {
    var off: usize = 0;
    while (off + @sizeOf(nlmsghdr) <= buf.len) {
        var hdr: nlmsghdr = undefined;
        @memcpy(std.mem.asBytes(&hdr), buf[off .. off + @sizeOf(nlmsghdr)]);
        if (hdr.nlmsg_len < @sizeOf(nlmsghdr)) break;
        const end = off + hdr.nlmsg_len;
        if (end > buf.len) break;

        if (hdr.nlmsg_type == NLMSG_DONE or hdr.nlmsg_type == NLMSG_ERROR) return 0;

        const payload = buf[off + @sizeOf(nlmsghdr) .. end];
        if (payload.len >= @sizeOf(genlmsghdr)) {
            const attrs = payload[@sizeOf(genlmsghdr)..];
            var aoff: usize = 0;
            var name_match = false;
            var fam_id: u16 = 0;
            while (aoff + @sizeOf(nlattr) <= attrs.len) {
                var a: nlattr = undefined;
                @memcpy(std.mem.asBytes(&a), attrs[aoff .. aoff + @sizeOf(nlattr)]);
                if (a.nla_len < @sizeOf(nlattr)) break;
                const aend = aoff + a.nla_len;
                if (aend > attrs.len) break;

                const t = nlaType(a.nla_type);
                if (t == CTRL_ATTR_FAMILY_NAME) {
                    const raw = attrs[aoff + @sizeOf(nlattr) .. aend];
                    const s = std.mem.trimRight(u8, raw, "\x00");
                    if (std.mem.eql(u8, s, "nl80211")) name_match = true;
                } else if (t == CTRL_ATTR_FAMILY_ID and a.nla_len >= @sizeOf(nlattr) + 2) {
                    fam_id = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(attrs[aoff + @sizeOf(nlattr) .. aoff + @sizeOf(nlattr) + 2])), .little);
                }

                aoff += nlaAlign(a.nla_len);
            }
            if (name_match and fam_id != 0) return fam_id;
        }

        off += nlmsgAlign(hdr.nlmsg_len);
    }
    return 0;
}

fn getNl80211FamilyIdFromProc(alloc: std.mem.Allocator) !u16 {
    var f = std.fs.openFileAbsolute("/proc/net/genl", .{}) catch return error.NoProcGenl;
    defer f.close();
    var buf: [4096]u8 = undefined;
    const n = f.read(&buf) catch return error.NoProcGenl;
    const data = buf[0..n];

    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        var fields = std.mem.splitAny(u8, line, " \t");
        var first_num: ?u16 = null;
        var saw_name = false;
        while (fields.next()) |tok| {
            if (tok.len == 0) continue;
            if (!saw_name and std.mem.eql(u8, tok, "nl80211")) saw_name = true;
            if (first_num == null) {
                const id = std.fmt.parseInt(u16, tok, 10) catch null;
                if (id != null) first_num = id;
            }
        }
        if (saw_name and first_num != null) {
            _ = alloc;
            return first_num.?;
        }
    }
    return error.NoProcGenl;
}

fn getStationTxRateDump(alloc: std.mem.Allocator, fd: std.posix.fd_t, family_id: u16, ifindex: u32, pid: u32, debug: bool) !?[]u8 {
    var msg = try std.ArrayList(u8).initCapacity(alloc, 128);
    defer msg.deinit(alloc);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = family_id,
        .nlmsg_flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
        .nlmsg_seq = 2,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = NL80211_CMD_GET_STATION, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(alloc, std.mem.asBytes(&hdr));
    try msg.appendSlice(alloc, std.mem.asBytes(&gen));
    try appendAttr(alloc, &msg, NL80211_ATTR_IFINDEX, std.mem.asBytes(&ifindex));

    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [8192]u8 = undefined;
    var best_bitrate_100kbps: ?u32 = null;

    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        const slice = recv_buf[0..@intCast(n)];
        var off: usize = 0;
        while (off + @sizeOf(nlmsghdr) <= slice.len) {
            var hdrp: nlmsghdr = undefined;
            @memcpy(std.mem.asBytes(&hdrp), slice[off .. off + @sizeOf(nlmsghdr)]);
            if (hdrp.nlmsg_len < @sizeOf(nlmsghdr)) break;
            const end = off + hdrp.nlmsg_len;
            if (end > slice.len) break;

            if (hdrp.nlmsg_type == NLMSG_DONE) {
                return bitrateToString(alloc, best_bitrate_100kbps);
            }
            if (hdrp.nlmsg_type == NLMSG_ERROR) {
                return bitrateToString(alloc, best_bitrate_100kbps);
            }

            const payload = slice[off + @sizeOf(nlmsghdr) .. end];
            if (payload.len >= @sizeOf(genlmsghdr)) {
                const attrs = payload[@sizeOf(genlmsghdr)..];
                if (parseStaInfoBitrate(attrs, debug)) |rate| {
                    best_bitrate_100kbps = rate;
                }
            }

            off += nlmsgAlign(hdrp.nlmsg_len);
        }
    }

    return bitrateToString(alloc, best_bitrate_100kbps);
}

fn getStationTxRateSimple(alloc: std.mem.Allocator, fd: std.posix.fd_t, family_id: u16, ifindex: u32, pid: u32, debug: bool) !?[]u8 {
    var msg = try std.ArrayList(u8).initCapacity(alloc, 128);
    defer msg.deinit(alloc);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = family_id,
        .nlmsg_flags = linux.NLM_F_REQUEST,
        .nlmsg_seq = 5,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = NL80211_CMD_GET_STATION, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(alloc, std.mem.asBytes(&hdr));
    try msg.appendSlice(alloc, std.mem.asBytes(&gen));
    try appendAttr(alloc, &msg, NL80211_ATTR_IFINDEX, std.mem.asBytes(&ifindex));

    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [8192]u8 = undefined;
    var best_bitrate_100kbps: ?u32 = null;

    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        const slice = recv_buf[0..@intCast(n)];
        var off: usize = 0;
        while (off + @sizeOf(nlmsghdr) <= slice.len) {
            var hdrp: nlmsghdr = undefined;
            @memcpy(std.mem.asBytes(&hdrp), slice[off .. off + @sizeOf(nlmsghdr)]);
            if (hdrp.nlmsg_len < @sizeOf(nlmsghdr)) break;
            const end = off + hdrp.nlmsg_len;
            if (end > slice.len) break;

            if (hdrp.nlmsg_type == NLMSG_DONE or hdrp.nlmsg_type == NLMSG_ERROR) {
                return bitrateToString(alloc, best_bitrate_100kbps);
            }

            const payload = slice[off + @sizeOf(nlmsghdr) .. end];
            if (payload.len >= @sizeOf(genlmsghdr)) {
                const attrs = payload[@sizeOf(genlmsghdr)..];
                if (parseStaInfoBitrate(attrs, debug)) |rate| {
                    best_bitrate_100kbps = rate;
                }
            }

            off += nlmsgAlign(hdrp.nlmsg_len);
        }
    }

    return bitrateToString(alloc, best_bitrate_100kbps);
}

fn getStationTxRate(alloc: std.mem.Allocator, fd: std.posix.fd_t, family_id: u16, ifindex: u32, bssid: [6]u8, pid: u32, debug: bool) !?[]u8 {
    var msg = try std.ArrayList(u8).initCapacity(alloc, 128);
    defer msg.deinit(alloc);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = family_id,
        .nlmsg_flags = linux.NLM_F_REQUEST,
        .nlmsg_seq = 4,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = NL80211_CMD_GET_STATION, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(alloc, std.mem.asBytes(&hdr));
    try msg.appendSlice(alloc, std.mem.asBytes(&gen));
    try appendAttr(alloc, &msg, NL80211_ATTR_IFINDEX, std.mem.asBytes(&ifindex));
    try appendAttr(alloc, &msg, NL80211_ATTR_MAC, &bssid);

    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [8192]u8 = undefined;
    var best_bitrate_100kbps: ?u32 = null;

    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        const slice = recv_buf[0..@intCast(n)];
        var off: usize = 0;
        while (off + @sizeOf(nlmsghdr) <= slice.len) {
            var hdrp: nlmsghdr = undefined;
            @memcpy(std.mem.asBytes(&hdrp), slice[off .. off + @sizeOf(nlmsghdr)]);
            if (hdrp.nlmsg_len < @sizeOf(nlmsghdr)) break;
            const end = off + hdrp.nlmsg_len;
            if (end > slice.len) break;

            if (hdrp.nlmsg_type == NLMSG_DONE or hdrp.nlmsg_type == NLMSG_ERROR) {
                return bitrateToString(alloc, best_bitrate_100kbps);
            }

            const payload = slice[off + @sizeOf(nlmsghdr) .. end];
            if (payload.len >= @sizeOf(genlmsghdr)) {
                const attrs = payload[@sizeOf(genlmsghdr)..];
                if (parseStaInfoBitrate(attrs, debug)) |rate| {
                    best_bitrate_100kbps = rate;
                }
            }

            off += nlmsgAlign(hdrp.nlmsg_len);
        }
    }

    return bitrateToString(alloc, best_bitrate_100kbps);
}

fn getBssidFromInterface(fd: std.posix.fd_t, family_id: u16, ifindex: u32, pid: u32, debug: bool) !?[6]u8 {
    var msg = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 128);
    defer msg.deinit(std.heap.page_allocator);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = family_id,
        .nlmsg_flags = linux.NLM_F_REQUEST,
        .nlmsg_seq = 6,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = NL80211_CMD_GET_INTERFACE, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&hdr));
    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&gen));
    try appendAttr(std.heap.page_allocator, &msg, NL80211_ATTR_IFINDEX, std.mem.asBytes(&ifindex));

    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [4096]u8 = undefined;
    const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch return null;
    if (n <= 0) return null;
    const slice = recv_buf[0..@intCast(n)];
    return parseBssidFromInterface(slice, debug);
}

fn parseBssidFromInterface(buf: []const u8, debug: bool) ?[6]u8 {
    var off: usize = 0;
    while (off + @sizeOf(nlmsghdr) <= buf.len) {
        const hdr = @as(*const nlmsghdr, @ptrCast(@alignCast(&buf[off]))).*;
        if (hdr.nlmsg_len < @sizeOf(nlmsghdr)) break;
        const end = off + hdr.nlmsg_len;
        if (end > buf.len) break;

        if (hdr.nlmsg_type == NLMSG_DONE or hdr.nlmsg_type == NLMSG_ERROR) return null;

        const payload = buf[off + @sizeOf(nlmsghdr) .. end];
        if (payload.len >= @sizeOf(genlmsghdr)) {
            const attrs = payload[@sizeOf(genlmsghdr)..];
            var aoff: usize = 0;
            while (aoff + @sizeOf(nlattr) <= attrs.len) {
                var a: nlattr = undefined;
                @memcpy(std.mem.asBytes(&a), attrs[aoff .. aoff + @sizeOf(nlattr)]);
                if (a.nla_len < @sizeOf(nlattr)) break;
                const aend = aoff + a.nla_len;
                if (aend > attrs.len) break;

                const t = nlaType(a.nla_type);
                if (debug) debugAttr("iface", t, a.nla_len);
                if (t == NL80211_ATTR_BSSID and a.nla_len >= @sizeOf(nlattr) + 6) {
                    var mac: [6]u8 = undefined;
                    @memcpy(&mac, attrs[aoff + @sizeOf(nlattr) .. aoff + @sizeOf(nlattr) + 6]);
                    return mac;
                }

                aoff += nlaAlign(a.nla_len);
            }
        }

        off += nlmsgAlign(hdr.nlmsg_len);
    }

    return null;
}

fn getAssociatedBssid(fd: std.posix.fd_t, family_id: u16, ifindex: u32, pid: u32, debug: bool) !?[6]u8 {
    var msg = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 128);
    defer msg.deinit(std.heap.page_allocator);

    const hdr = nlmsghdr{
        .nlmsg_len = 0,
        .nlmsg_type = family_id,
        .nlmsg_flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
        .nlmsg_seq = 3,
        .nlmsg_pid = pid,
    };
    const gen = genlmsghdr{ .cmd = NL80211_CMD_GET_SCAN, .version = GENL_VERSION, .reserved = 0 };

    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&hdr));
    try msg.appendSlice(std.heap.page_allocator, std.mem.asBytes(&gen));
    try appendAttr(std.heap.page_allocator, &msg, NL80211_ATTR_IFINDEX, std.mem.asBytes(&ifindex));

    const total_len = @as(u32, @intCast(msg.items.len));
    std.mem.writeInt(u32, msg.items[0..4], total_len, .little);

    var kernel = sockaddr_nl{ .nl_family = linux.PF.NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0 };
    _ = try std.posix.sendto(fd, msg.items, 0, @ptrCast(&kernel), @sizeOf(sockaddr_nl));

    var recv_buf: [8192]u8 = undefined;
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = std.posix.poll(&fds, 200) catch break;
        if (rc == 0) break;
        const n = std.posix.recvfrom(fd, &recv_buf, 0, null, null) catch break;
        if (n <= 0) break;
        const slice = recv_buf[0..@intCast(n)];
        var off: usize = 0;
        while (off + @sizeOf(nlmsghdr) <= slice.len) {
            var hdrp: nlmsghdr = undefined;
            @memcpy(std.mem.asBytes(&hdrp), slice[off .. off + @sizeOf(nlmsghdr)]);
            if (hdrp.nlmsg_len < @sizeOf(nlmsghdr)) break;
            const end = off + hdrp.nlmsg_len;
            if (end > slice.len) break;

            if (hdrp.nlmsg_type == NLMSG_DONE or hdrp.nlmsg_type == NLMSG_ERROR) return null;

            const payload = slice[off + @sizeOf(nlmsghdr) .. end];
            if (payload.len >= @sizeOf(genlmsghdr)) {
                const attrs = payload[@sizeOf(genlmsghdr)..];
                if (parseBssAssociated(attrs, debug)) |bssid| return bssid;
            }

            off += nlmsgAlign(hdrp.nlmsg_len);
        }
    }

    return null;
}

fn parseBssAssociated(attrs: []const u8, debug: bool) ?[6]u8 {
    var aoff: usize = 0;
    while (aoff + @sizeOf(nlattr) <= attrs.len) {
        var a: nlattr = undefined;
        @memcpy(std.mem.asBytes(&a), attrs[aoff .. aoff + @sizeOf(nlattr)]);
        if (a.nla_len < @sizeOf(nlattr)) break;
        const aend = aoff + a.nla_len;
        if (aend > attrs.len) break;

        const t = nlaType(a.nla_type);
        if (debug) debugAttr("scan", t, a.nla_len);
        if (t == NL80211_ATTR_BSS) {
            const nested = attrs[aoff + @sizeOf(nlattr) .. aend];
            if (parseBssNestedAssociated(nested, debug)) |bssid| return bssid;
        }

        aoff += nlaAlign(a.nla_len);
    }
    return null;
}

fn parseBssNestedAssociated(nested: []const u8, debug: bool) ?[6]u8 {
    var status: ?u32 = null;
    var bssid: ?[6]u8 = null;

    var off: usize = 0;
    while (off + @sizeOf(nlattr) <= nested.len) {
        var a: nlattr = undefined;
        @memcpy(std.mem.asBytes(&a), nested[off .. off + @sizeOf(nlattr)]);
        if (a.nla_len < @sizeOf(nlattr)) break;
        const aend = off + a.nla_len;
        if (aend > nested.len) break;

        const t = nlaType(a.nla_type);
        if (debug) debugAttr("bss", t, a.nla_len);
        if (t == NL80211_BSS_STATUS and a.nla_len >= @sizeOf(nlattr) + 4) {
            status = std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(nested[off + @sizeOf(nlattr) .. off + @sizeOf(nlattr) + 4])), .little);
        } else if (t == NL80211_BSS_BSSID and a.nla_len >= @sizeOf(nlattr) + 6) {
            var mac: [6]u8 = undefined;
            @memcpy(&mac, nested[off + @sizeOf(nlattr) .. off + @sizeOf(nlattr) + 6]);
            bssid = mac;
        }

        off += nlaAlign(a.nla_len);
    }

    if (status != null and bssid != null and status.? == NL80211_BSS_STATUS_ASSOCIATED) {
        return bssid.?;
    }
    return null;
}

fn appendAttr(alloc: std.mem.Allocator, list: *std.ArrayList(u8), attr_type: u16, payload: []const u8) !void {
    const len: u16 = @intCast(@sizeOf(nlattr) + payload.len);
    const attr = nlattr{ .nla_len = len, .nla_type = attr_type };
    try list.appendSlice(alloc, std.mem.asBytes(&attr));
    try list.appendSlice(alloc, payload);
    const pad = nlaAlign(len) - len;
    if (pad > 0) try list.appendNTimes(alloc, 0, pad);
}

fn parseStaInfoBitrate(attrs: []const u8, debug: bool) ?u32 {
    var aoff: usize = 0;
    while (aoff + @sizeOf(nlattr) <= attrs.len) {
        var a: nlattr = undefined;
        @memcpy(std.mem.asBytes(&a), attrs[aoff .. aoff + @sizeOf(nlattr)]);
        if (a.nla_len < @sizeOf(nlattr)) break;
        const aend = aoff + a.nla_len;
        if (aend > attrs.len) break;

        const t = nlaType(a.nla_type);
        if (debug) debugAttr("sta", t, a.nla_len);
        if (t == NL80211_ATTR_STA_INFO) {
            const nested = attrs[aoff + @sizeOf(nlattr) .. aend];
            if (parseStaInfoNested(nested, debug)) |rate| return rate;
        }

        aoff += nlaAlign(a.nla_len);
    }
    return null;
}

fn parseStaInfoNested(nested: []const u8, debug: bool) ?u32 {
    var off: usize = 0;
    while (off + @sizeOf(nlattr) <= nested.len) {
        var a: nlattr = undefined;
        @memcpy(std.mem.asBytes(&a), nested[off .. off + @sizeOf(nlattr)]);
        if (a.nla_len < @sizeOf(nlattr)) break;
        const aend = off + a.nla_len;
        if (aend > nested.len) break;

        const t = nlaType(a.nla_type);
        if (debug) debugAttr("sta-n", t, a.nla_len);
        if (t == NL80211_STA_INFO_TX_BITRATE or t == NL80211_STA_INFO_RX_BITRATE) {
            const rate_nested = nested[off + @sizeOf(nlattr) .. aend];
            if (parseRateInfo(rate_nested, debug)) |rate| return rate;
        }

        off += nlaAlign(a.nla_len);
    }
    return null;
}

fn parseRateInfo(nested: []const u8, debug: bool) ?u32 {
    var off: usize = 0;
    while (off + @sizeOf(nlattr) <= nested.len) {
        var a: nlattr = undefined;
        @memcpy(std.mem.asBytes(&a), nested[off .. off + @sizeOf(nlattr)]);
        if (a.nla_len < @sizeOf(nlattr)) break;
        const aend = off + a.nla_len;
        if (aend > nested.len) break;

        const t = nlaType(a.nla_type);
        if (debug) debugAttr("rate", t, a.nla_len);
        if (t == NL80211_RATE_INFO_BITRATE and a.nla_len >= @sizeOf(nlattr) + 2) {
            return std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(nested[off + @sizeOf(nlattr) .. off + @sizeOf(nlattr) + 2])), .little);
        }
        if (t == NL80211_RATE_INFO_BITRATE32 and a.nla_len >= @sizeOf(nlattr) + 4) {
            return std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(nested[off + @sizeOf(nlattr) .. off + @sizeOf(nlattr) + 4])), .little);
        }

        off += nlaAlign(a.nla_len);
    }
    return null;
}

fn bitrateToString(alloc: std.mem.Allocator, rate_100kbps: ?u32) !?[]u8 {
    if (rate_100kbps == null) return null;
    const r = @as(f64, @floatFromInt(rate_100kbps.?)) / 10.0; // 100kbps -> Mbps
    if (r >= 1000.0) {
        const gbps = r / 1000.0;
        return try std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{gbps});
    }
    if (@mod(r, 1.0) == 0.0) {
        return try std.fmt.allocPrint(alloc, "{d} Mbps", .{@as(u32, @intFromFloat(r))});
    }
    return try std.fmt.allocPrint(alloc, "{d:.1} Mbps", .{r});
}

fn debugAttr(tag: []const u8, attr_type: u16, len: u16) void {
    std.debug.print("[wifi:{s}] attr {d} len {d}\n", .{ tag, attr_type, len });
}

fn phySpeedFromDebugfs(alloc: std.mem.Allocator, iface: []const u8) ?[]u8 {
    var dir = std.fs.openDirAbsolute("/sys/kernel/debug/ieee80211", .{ .iterate = true }) catch return null;
    defer dir.close();

    var it = dir.iterate();
    while (it.next() catch null) |e| {
        if (e.kind != .directory) continue;
        if (!std.mem.startsWith(u8, e.name, "phy")) continue;

        var path_buf: [512]u8 = undefined;
        const stations_dir = std.fmt.bufPrint(&path_buf, "/sys/kernel/debug/ieee80211/{s}/netdev:{s}/stations", .{ e.name, iface }) catch continue;
        // First check for rate files at netdev level (some drivers expose here).
        const netdev_base = std.fmt.bufPrint(&path_buf, "/sys/kernel/debug/ieee80211/{s}/netdev:{s}", .{ e.name, iface }) catch continue;
        if (readDebugRate(alloc, netdev_base, "last_tx_rate")) |v| return v;
        if (readDebugRate(alloc, netdev_base, "last_rx_rate")) |v| return v;
        if (readDebugRate(alloc, netdev_base, "tx_bitrate")) |v| return v;
        if (readDebugRate(alloc, netdev_base, "rx_bitrate")) |v| return v;
        if (readDebugRate(alloc, netdev_base, "tx_rate")) |v| return v;
        if (readDebugRate(alloc, netdev_base, "rx_rate")) |v| return v;

        var sdir = std.fs.openDirAbsolute(stations_dir, .{ .iterate = true }) catch continue;
        defer sdir.close();

        var sit = sdir.iterate();
        while (sit.next() catch null) |se| {
            if (se.kind != .directory) continue;
            const base = std.fmt.allocPrint(alloc, "{s}/{s}", .{ stations_dir, se.name }) catch continue;
            defer alloc.free(base);

            if (readDebugRate(alloc, base, "last_tx_rate")) |v| return v;
            if (readDebugRate(alloc, base, "last_rx_rate")) |v| return v;
            if (readDebugRate(alloc, base, "tx_bitrate")) |v| return v;
            if (readDebugRate(alloc, base, "rx_bitrate")) |v| return v;
            if (readDebugRate(alloc, base, "tx_rate")) |v| return v;
            if (readDebugRate(alloc, base, "rx_rate")) |v| return v;
        }
    }
    return null;
}

fn readDebugRate(alloc: std.mem.Allocator, base: []const u8, leaf: []const u8) ?[]u8 {
    var path_buf: [512]u8 = undefined;
    const p = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ base, leaf }) catch return null;
    var f = std.fs.openFileAbsolute(p, .{}) catch return null;
    defer f.close();
    var buf: [4096]u8 = undefined;
    const n = f.read(&buf) catch return null;
    const data = buf[0..n];

    const s = std.mem.trim(u8, data, " \t\r\n");
    if (s.len == 0) return null;

    var i: usize = 0;
    while (i < s.len and ((s[i] >= '0' and s[i] <= '9') or s[i] == '.')) : (i += 1) {}
    if (i == 0) return null;

    const val = std.fmt.parseFloat(f64, s[0..i]) catch return null;
    const unit = s[i..];
    if (std.mem.indexOf(u8, unit, "Mbit") != null or std.mem.indexOf(u8, unit, "Mb/s") != null) {
        if (@mod(val, 1.0) == 0.0) {
            return std.fmt.allocPrint(alloc, "{d} Mbps", .{@as(u32, @intFromFloat(val))}) catch null;
        }
        return std.fmt.allocPrint(alloc, "{d:.1} Mbps", .{val}) catch null;
    }
    if (std.mem.indexOf(u8, unit, "Gbit") != null or std.mem.indexOf(u8, unit, "Gb/s") != null) {
        return std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{val}) catch null;
    }

    // Assume Mbps if unit missing
    if (@mod(val, 1.0) == 0.0) {
        return std.fmt.allocPrint(alloc, "{d} Mbps", .{@as(u32, @intFromFloat(val))}) catch null;
    }
    return std.fmt.allocPrint(alloc, "{d:.1} Mbps", .{val}) catch null;
}
