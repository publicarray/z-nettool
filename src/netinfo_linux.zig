const std = @import("std");
const linux = std.os.linux;
const common = @import("netinfo_common.zig");
const wifi = @import("netinfo_linux_wifi.zig");
const c = @cImport({
    @cInclude("ifaddrs.h");
    @cInclude("net/if.h");
    @cInclude("arpa/inet.h");
    @cInclude("netinet/in.h");
});

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

    const link = try linkPartsFromSysfs(alloc, iface);
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
    var ifap: ?*c.ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) {
        return .{ .ip4 = try alloc.dupe(u8, ""), .ip6 = try alloc.dupe(u8, "") };
    }
    defer c.freeifaddrs(ifap);

    var ip4: ?[]u8 = null;
    var ip6: ?[]u8 = null;

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_name == null) continue;

        const name = std.mem.span(@as([*:0]const u8, @ptrCast(ifa.ifa_name)));
        if (!std.mem.eql(u8, name, iface)) continue;

        const family = ifa.ifa_addr.*.sa_family;
        if (family == c.AF_INET) {
            if (ip4 != null) continue;
            const sa = @as(*const c.sockaddr_in, @ptrCast(@alignCast(ifa.ifa_addr)));
            const mask = ifa.ifa_netmask orelse continue;
            const mask4 = @as(*const c.sockaddr_in, @ptrCast(@alignCast(mask)));

            var buf: [c.INET_ADDRSTRLEN]u8 = undefined;
            const ip_ptr = c.inet_ntop(c.AF_INET, &sa.sin_addr, &buf, buf.len) orelse continue;
            const ip_str = std.mem.span(@as([*:0]const u8, @ptrCast(ip_ptr)));

            const prefix = prefixLenFromMask4(mask4);
            ip4 = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ ip_str, prefix });
        } else if (family == c.AF_INET6) {
            if (ip6 != null) continue;
            const sa6 = @as(*const c.sockaddr_in6, @ptrCast(@alignCast(ifa.ifa_addr)));
            const mask = ifa.ifa_netmask orelse continue;
            const mask6 = @as(*const c.sockaddr_in6, @ptrCast(@alignCast(mask)));

            // Avoid relying on platform-specific struct_in6_addr fields.
            const b = std.mem.asBytes(&sa6.sin6_addr);
            if (b.len >= 2 and b[0] == 0xfe and (b[1] & 0xc0) == 0x80) continue; // skip link-local

            var buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
            const ip_ptr = c.inet_ntop(c.AF_INET6, &sa6.sin6_addr, &buf, buf.len) orelse continue;
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

fn prefixLenFromMask4(mask: *const c.sockaddr_in) u8 {
    const m: u32 = @bitCast(mask.sin_addr.s_addr);
    return @intCast(@popCount(m));
}

fn prefixLenFromMask6(mask: *const c.sockaddr_in6) u8 {
    var count: u32 = 0;
    // Avoid relying on platform-specific struct_in6_addr fields.
    for (std.mem.asBytes(&mask.sin6_addr)) |b| count += @popCount(b);
    return @intCast(count);
}

fn readSysfsTrim(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.openFileAbsolute(path, .{});
    defer f.close();
    var buf: [128]u8 = undefined;
    const rc = linux.read(@intCast(f.handle), &buf, buf.len);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.SysfsReadFailed;
    const n: usize = @intCast(signed);
    return try alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \t\r\n"));
}

const LinkParts = struct {
    state: []u8,
    kind: []u8,
    speed: []u8,
    duplex: []u8,
};

fn linkPartsFromSysfs(alloc: std.mem.Allocator, iface: []const u8) !LinkParts {
    var p1: [256]u8 = undefined;
    var p2: [256]u8 = undefined;
    var p3: [256]u8 = undefined;

    const oper = try std.fmt.bufPrint(&p1, "/sys/class/net/{s}/operstate", .{iface});
    const speedp = try std.fmt.bufPrint(&p2, "/sys/class/net/{s}/speed", .{iface});
    const duplp = try std.fmt.bufPrint(&p3, "/sys/class/net/{s}/duplex", .{iface});

    const oper_s = readSysfsTrim(alloc, oper) catch return LinkParts{
        .state = try alloc.dupe(u8, "unknown"),
        .kind = try alloc.dupe(u8, "unknown"),
        .speed = try alloc.dupe(u8, "unknown speed"),
        .duplex = try alloc.dupe(u8, "unknown"),
    };

    const duplex_s = readSysfsTrim(alloc, duplp) catch try alloc.dupe(u8, "unknown");

    // speed may not exist (wifi often doesn't expose)
    const speed_s = readSysfsTrim(alloc, speedp) catch try alloc.dupe(u8, "unknown");

    var kind_s: []u8 = undefined;
    var speed_out: []u8 = undefined;
    var duplex_out: []u8 = duplex_s;

    const sp = std.fmt.parseInt(u32, speed_s, 10) catch null;
    if (sp) |mbps| {
        kind_s = try alloc.dupe(u8, "ethernet");
        if (mbps >= 1000) {
            const gbps = @as(f64, @floatFromInt(mbps)) / 1000.0;
            speed_out = try std.fmt.allocPrint(alloc, "{d:.2} Gbps", .{gbps});
        } else {
            speed_out = try std.fmt.allocPrint(alloc, "{d} Mbps", .{mbps});
        }
    } else {
        if (isWirelessIface(iface)) {
            if (try wifi.phySpeedFromNl80211(alloc, iface)) |s| {
                kind_s = try alloc.dupe(u8, "wifi");
                speed_out = s;
            } else {
                kind_s = try alloc.dupe(u8, "wifi");
                speed_out = try alloc.dupe(u8, "unknown speed");
            }
            if (!std.mem.eql(u8, duplex_out, "half")) {
                alloc.free(duplex_out);
                duplex_out = try alloc.dupe(u8, "half");
            }
        } else {
            kind_s = try alloc.dupe(u8, "unknown");
            speed_out = try alloc.dupe(u8, "unknown speed");
        }
    }

    const state_s = try alloc.dupe(u8, oper_s);

    alloc.free(oper_s);
    alloc.free(speed_s);

    return .{
        .state = state_s,
        .kind = kind_s,
        .speed = speed_out,
        .duplex = duplex_out,
    };
}

fn isWirelessIface(iface: []const u8) bool {
    var buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "/sys/class/net/{s}/wireless", .{iface}) catch return false;
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}
