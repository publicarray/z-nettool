const std = @import("std");
const common = @import("netinfo_common.zig");
const d = @import("darwin_if.zig");

pub fn getNetInfoCommon(alloc: std.mem.Allocator, iface: []const u8) !common.NetInfo {
    const ip = try ipAddrsFromIfAddrs(alloc, iface);
    var ip4 = ip.ip4;
    var ip6 = ip.ip6;
    if (ip4.len == 0) {
        alloc.free(ip4);
        ip4 = try alloc.dupe(u8, "[unknown]");
    }
    if (ip6.len == 0) {
        alloc.free(ip6);
        ip6 = try alloc.dupe(u8, "");
    }

    const link = try linkPartsFromIfAddrs(alloc, iface);
    return .{
        .ip_cidr = ip4,
        .ip6_cidr = ip6,
        .link_state = link.state,
        .link_kind = link.kind,
        .link_speed = link.speed,
        .link_duplex = link.duplex,
    };
}

const IpAddrs = struct {
    ip4: []u8,
    ip6: []u8,
};

fn ipAddrsFromIfAddrs(alloc: std.mem.Allocator, iface: []const u8) !IpAddrs {
    var ifap: ?*d.ifaddrs = null;
    if (d.getifaddrs(&ifap) != 0) {
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };
    }
    defer d.freeifaddrs(ifap);

    var ip4: ?[]u8 = null;
    var ip6: ?[]u8 = null;

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_name == null) continue;

        const name = std.mem.span(@as([*:0]const u8, @ptrCast(ifa.ifa_name)));
        if (!std.mem.eql(u8, name, iface)) continue;

        const addr = ifa.ifa_addr orelse continue;
        const family = addr.*.sa_family;
        if (family == d.AF_INET) {
            if (ip4 != null) continue;
            const sa = @as(*const d.sockaddr_in, @ptrCast(@alignCast(addr)));
            const mask = ifa.ifa_netmask orelse continue;
            const mask4 = @as(*const d.sockaddr_in, @ptrCast(@alignCast(mask)));

            var buf: [d.INET_ADDRSTRLEN]u8 = undefined;
            const ip_ptr = d.inet_ntop(d.AF_INET, &sa.sin_addr, &buf, buf.len) orelse continue;
            const ip_str = std.mem.span(@as([*:0]const u8, @ptrCast(ip_ptr)));

            const prefix = prefixLenFromMask4(mask4);
            ip4 = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ ip_str, prefix });
        } else if (family == d.AF_INET6) {
            if (ip6 != null) continue;
            const sa6 = @as(*const d.sockaddr_in6, @ptrCast(@alignCast(addr)));
            const mask = ifa.ifa_netmask orelse continue;
            const mask6 = @as(*const d.sockaddr_in6, @ptrCast(@alignCast(mask)));

            const b = std.mem.asBytes(&sa6.sin6_addr);
            if (b.len >= 2 and b[0] == 0xfe and (b[1] & 0xc0) == 0x80) continue; // skip link-local

            var buf: [d.INET6_ADDRSTRLEN]u8 = undefined;
            const ip_ptr = d.inet_ntop(d.AF_INET6, &sa6.sin6_addr, &buf, buf.len) orelse continue;
            const ip_str = std.mem.span(@as([*:0]const u8, @ptrCast(ip_ptr)));

            const prefix = prefixLenFromMask6(mask6);
            ip6 = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ ip_str, prefix });
        }
    }

    return .{
        .ip4 = ip4 orelse try alloc.dupe(u8, ""),
        .ip6 = ip6 orelse try alloc.dupe(u8, ""),
    };
}

fn prefixLenFromMask4(mask: *const d.sockaddr_in) u8 {
    const m: u32 = @bitCast(mask.sin_addr.s_addr);
    return @intCast(@popCount(m));
}

fn prefixLenFromMask6(mask: *const d.sockaddr_in6) u8 {
    var count: u32 = 0;
    for (std.mem.asBytes(&mask.sin6_addr)) |b| count += @popCount(b);
    return @intCast(count);
}

const LinkParts = struct {
    state: []u8,
    kind: []u8,
    speed: []u8,
    duplex: []u8,
};

fn linkPartsFromIfAddrs(alloc: std.mem.Allocator, iface: []const u8) !LinkParts {
    var ifap: ?*d.ifaddrs = null;
    if (d.getifaddrs(&ifap) != 0) {
        return LinkParts{
            .state = try alloc.dupe(u8, "unknown"),
            .kind = try alloc.dupe(u8, "unknown"),
            .speed = try alloc.dupe(u8, "unknown speed"),
            .duplex = try alloc.dupe(u8, "unknown"),
        };
    }
    defer d.freeifaddrs(ifap);

    var state: ?[]u8 = null;
    var kind: ?[]u8 = null;

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_name == null) continue;

        const name = std.mem.span(@as([*:0]const u8, @ptrCast(ifa.ifa_name)));
        if (!std.mem.eql(u8, name, iface)) continue;

        if (state == null) {
            const flags: u32 = @intCast(ifa.ifa_flags);
            const up = (flags & d.IFF_UP) != 0;
            const running = (flags & d.IFF_RUNNING) != 0;
            if (up and running) {
                state = try alloc.dupe(u8, "up");
            } else if (up) {
                state = try alloc.dupe(u8, "down");
            } else {
                state = try alloc.dupe(u8, "down");
            }
        }

        if (kind == null) {
            const addr = ifa.ifa_addr orelse continue;
            if (addr.*.sa_family == d.AF_LINK) {
                const sdl = @as(*const d.sockaddr_dl, @ptrCast(@alignCast(addr)));
                if (sdl.sdl_type == d.IFT_ETHER) {
                    kind = try alloc.dupe(u8, "ethernet");
                }
            }
        }

        if (state != null and kind != null) break;
    }

    var out_state = state orelse try alloc.dupe(u8, "unknown");
    const out_kind = kind orelse try alloc.dupe(u8, "unknown");
    var out_speed = try alloc.dupe(u8, "unknown speed");
    var out_duplex = try alloc.dupe(u8, "unknown");

    if (readIfconfigInfo(alloc, iface)) |info| {
        if (info.state) |s| {
            alloc.free(out_state);
            out_state = s;
        }
        if (info.speed) |s| {
            alloc.free(out_speed);
            out_speed = s;
        }
        if (info.duplex) |dup| {
            alloc.free(out_duplex);
            out_duplex = dup;
        }
    } else |_| {}

    return .{
        .state = out_state,
        .kind = out_kind,
        .speed = out_speed,
        .duplex = out_duplex,
    };
}

const IfconfigInfo = struct {
    state: ?[]u8 = null,
    speed: ?[]u8 = null,
    duplex: ?[]u8 = null,

    pub fn deinit(self: *IfconfigInfo, alloc: std.mem.Allocator) void {
        if (self.state) |s| alloc.free(s);
        if (self.speed) |s| alloc.free(s);
        if (self.duplex) |s| alloc.free(s);
        self.* = .{};
    }
};

fn readIfconfigInfo(alloc: std.mem.Allocator, iface: []const u8) !IfconfigInfo {
    var info: IfconfigInfo = .{};
    errdefer info.deinit(alloc);

    var child = std.process.Child.init(&.{ "ifconfig", iface }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const out = try child.stdout.?.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(out);
    _ = try child.wait();

    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "status:")) {
            const s = std.mem.trim(u8, line["status:".len..], " \t");
            if (info.state) |old| alloc.free(old);
            if (std.ascii.eqlIgnoreCase(s, "active")) {
                info.state = try alloc.dupe(u8, "up");
            } else if (std.ascii.eqlIgnoreCase(s, "inactive")) {
                info.state = try alloc.dupe(u8, "down");
            } else {
                info.state = try alloc.dupe(u8, s);
            }
            continue;
        }

        if (std.mem.startsWith(u8, line, "media:")) {
            parseMediaLine(alloc, line, &info);
            continue;
        }
    }

    return info;
}

fn parseMediaLine(alloc: std.mem.Allocator, line: []const u8, info: *IfconfigInfo) void {
    const open = std.mem.indexOfScalar(u8, line, '(') orelse return;
    const close = std.mem.indexOfScalarPos(u8, line, open + 1, ')') orelse line.len;
    if (open + 1 >= close) return;

    const inner = line[open + 1 .. close];
    const end = std.mem.indexOfAny(u8, inner, " <") orelse inner.len;
    if (end == 0) return;

    const token = inner[0..end];
    if (parseSpeedToken(alloc, token)) |s| {
        if (info.speed) |old| alloc.free(old);
        info.speed = s;
    }

    if (std.mem.indexOf(u8, inner, "full-duplex") != null) {
        if (info.duplex) |old| alloc.free(old);
        info.duplex = alloc.dupe(u8, "full") catch return;
    } else if (std.mem.indexOf(u8, inner, "half-duplex") != null) {
        if (info.duplex) |old| alloc.free(old);
        info.duplex = alloc.dupe(u8, "half") catch return;
    }
}

fn parseSpeedToken(alloc: std.mem.Allocator, token: []const u8) ?[]u8 {
    var i: usize = 0;
    while (i < token.len) : (i += 1) {
        const cch = token[i];
        if (!((cch >= '0' and cch <= '9') or cch == '.')) break;
    }
    if (i == 0) return null;

    const num_str = token[0..i];
    const val = std.fmt.parseFloat(f64, num_str) catch return null;

    const has_g = (i < token.len and (token[i] == 'G' or token[i] == 'g')) or
        (std.mem.indexOf(u8, token, "Gbase") != null) or
        (std.mem.indexOf(u8, token, "Gbps") != null);

    if (has_g) {
        return std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{val}) catch null;
    }

    if (val >= 1000.0) {
        const gbps = val / 1000.0;
        return std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{gbps}) catch null;
    }

    if (@mod(val, 1.0) == 0.0) {
        return std.fmt.allocPrint(alloc, "{d} Mbps", .{@as(u32, @intFromFloat(val))}) catch null;
    }

    return std.fmt.allocPrint(alloc, "{d:.1} Mbps", .{val}) catch null;
}
