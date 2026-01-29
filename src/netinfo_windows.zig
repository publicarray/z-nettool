const std = @import("std");
const w = std.os.windows;

// kernel32 dynamic loader
extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?w.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: w.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

const AF_UNSPEC: u32 = 0;
const AF_INET: u16 = 2;

const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;

const IfType_EthernetCSMA: u32 = 6; // IF_TYPE_ETHERNET_CSMACD

// --- Win structs (enough for what we need) ---

const SOCKADDR = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

const SOCKADDR_IN = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32, // network order
    sin_zero: [8]u8,
};

const SOCKET_ADDRESS = extern struct {
    lpSockaddr: ?*SOCKADDR,
    iSockaddrLength: i32,
};

const IP_ADAPTER_UNICAST_ADDRESS_LH = extern struct {
    Length: u32,
    Flags: u32,
    Next: ?*IP_ADAPTER_UNICAST_ADDRESS_LH,
    Address: SOCKET_ADDRESS,

    // fields to reach OnLinkPrefixLength (modern Windows)
    PrefixOrigin: u32,
    SuffixOrigin: u32,
    DadState: u32,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    LeaseLifetime: u32,
    OnLinkPrefixLength: u8,

    // struct continues; not needed
};

const IP_ADAPTER_ADDRESSES_LH = extern struct {
    Length: u32,
    IfIndex: u32,
    Next: ?*IP_ADAPTER_ADDRESSES_LH,
    AdapterName: ?[*:0]u8,

    FirstUnicastAddress: ?*IP_ADAPTER_UNICAST_ADDRESS_LH,
    FirstAnycastAddress: ?*anyopaque,
    FirstMulticastAddress: ?*anyopaque,
    FirstDnsServerAddress: ?*anyopaque,

    DnsSuffix: ?[*:0]u16,
    Description: ?[*:0]u16,
    FriendlyName: ?[*:0]u16,

    PhysicalAddress: [8]u8,
    PhysicalAddressLength: u32,

    Flags: u32,
    Mtu: u32,
    IfType: u32,
    OperStatus: u32,
    Ipv6IfIndex: u32,
    ZoneIndices: [16]u32,
    FirstPrefix: ?*anyopaque,

    TransmitLinkSpeed: u64, // bits/sec
    ReceiveLinkSpeed: u64, // bits/sec

    // struct continues; not needed
};

const GetAdaptersAddressesFn = *const fn (
    Family: u32,
    Flags: u32,
    Reserved: ?*anyopaque,
    AdapterAddresses: ?*IP_ADAPTER_ADDRESSES_LH,
    SizePointer: *u32,
) callconv(.winapi) u32;

fn loadGetAdaptersAddresses() !GetAdaptersAddressesFn {
    const mod = LoadLibraryW(&[_:0]u16{ 'i', 'p', 'h', 'l', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l' }) orelse return error.DllLoadFailed;

    const sym = GetProcAddress(mod, &[_:0]u8{ 'G', 'e', 't', 'A', 'd', 'a', 'p', 't', 'e', 'r', 's', 'A', 'd', 'd', 'r', 'e', 's', 's', 'e', 's' }) orelse return error.SymbolNotFound;

    return @ptrCast(sym);
}

fn utf16zEqualsAsciiIgnoreCase(wname_z: [*:0]const u16, ascii: []const u8) bool {
    // compare FriendlyName (UTF-16) to ASCII iface name (what you display)
    var i: usize = 0;
    while (true) : (i += 1) {
        const wc = wname_z[i];
        if (wc == 0) return i == ascii.len;
        if (i >= ascii.len) return false;
        const a = ascii[i];
        if (wc > 0x7f) return false; // we only expect ASCII-friendly names here
        const wc8: u8 = @intCast(wc);
        if (std.ascii.toLower(wc8) != std.ascii.toLower(a)) return false;
    }
}

fn ip4ToString(buf: *[32]u8, addr_be: u32, prefix: u8) ![]const u8 {
    // addr_be is network order; convert to host then print bytes
    const addr = std.mem.bigToNative(u32, addr_be);
    const b0: u8 = @intCast((addr >> 24) & 0xff);
    const b1: u8 = @intCast((addr >> 16) & 0xff);
    const b2: u8 = @intCast((addr >> 8) & 0xff);
    const b3: u8 = @intCast(addr & 0xff);
    return try std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}/{d}", .{ b0, b1, b2, b3, prefix });
}

fn fmtBitsPerSec(buf: *[64]u8, bps: u64) ![]const u8 {
    // show Mbps/Gbps
    const mbps = @as(f64, @floatFromInt(bps)) / 1_000_000.0;
    if (mbps >= 1000.0) {
        const gbps = mbps / 1000.0;
        return try std.fmt.bufPrint(buf, "{d:.2} Gbps", .{gbps});
    }
    return try std.fmt.bufPrint(buf, "{d:.0} Mbps", .{mbps});
}

fn psEscapeSingleQuotes(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try std.ArrayList(u8).initCapacity(alloc, s.len);
    errdefer out.deinit(alloc);
    for (s) |c| {
        if (c == '\'') {
            try out.append(alloc, '\'');
            try out.append(alloc, '\'');
        } else {
            try out.append(alloc, c);
        }
    }
    return try out.toOwnedSlice(alloc);
}

fn getDuplex(alloc: std.mem.Allocator, iface_name: []const u8) !?[]u8 {
    const esc = try psEscapeSingleQuotes(alloc, iface_name);
    defer alloc.free(esc);

    const ps = try std.fmt.allocPrint(
        alloc,
        "$d = (Get-NetAdapter -Name '{s}' -ErrorAction SilentlyContinue).MediaDuplexState; if ($d -ne $null) {{ $d }}",
        .{esc},
    );
    defer alloc.free(ps);

    var child = std.process.Child.init(&.{ "powershell", "-NoProfile", "-Command", ps }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 4 * 1024);
    defer alloc.free(out_bytes);
    _ = try child.wait();

    const s = std.mem.trim(u8, out_bytes, " \t\r\n");
    if (s.len == 0) return null;

    if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "half")) {
        return try alloc.dupe(u8, "half");
    }
    if (std.mem.eql(u8, s, "2") or std.ascii.eqlIgnoreCase(s, "full")) {
        return try alloc.dupe(u8, "full");
    }
    if (std.mem.eql(u8, s, "0") or std.ascii.eqlIgnoreCase(s, "unknown")) {
        return try alloc.dupe(u8, "unknown");
    }

    return try alloc.dupe(u8, s);
}

pub const NetInfo = struct {
    ip_cidr: []u8,
    link: []u8,
};

pub fn getIpAndLink(alloc: std.mem.Allocator, iface_name: []const u8) !NetInfo {
    const gaa = try loadGetAdaptersAddresses();
    const flags: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

    var buf_len: u32 = 0;
    const rc0 = gaa(AF_UNSPEC, flags, null, null, &buf_len);
    if (rc0 != ERROR_BUFFER_OVERFLOW or buf_len == 0) return error.GetAdaptersFailed;

    const buf = try alloc.alignedAlloc(u8, .@"8", buf_len);
    errdefer alloc.free(buf);

    const addrs: *IP_ADAPTER_ADDRESSES_LH = @ptrCast(@alignCast(buf.ptr));
    const rc = gaa(AF_UNSPEC, flags, null, addrs, &buf_len);
    if (rc != ERROR_SUCCESS) return error.GetAdaptersFailed;

    var cur: ?*IP_ADAPTER_ADDRESSES_LH = addrs;
    while (cur) |a| : (cur = a.Next) {
        if (a.FriendlyName == null) continue;
        if (!utf16zEqualsAsciiIgnoreCase(a.FriendlyName.?, iface_name)) continue;

        // IP (IPv4): first unicast IPv4 we find
        var ip_buf: [32]u8 = undefined;
        var ip_str: []const u8 = "[unknown]";

        const duplex_opt = getDuplex(alloc, iface_name) catch null;
        defer if (duplex_opt) |d| alloc.free(d);

        var u: ?*IP_ADAPTER_UNICAST_ADDRESS_LH = a.FirstUnicastAddress;
        while (u) |ua| : (u = ua.Next) {
            const sa = ua.Address.lpSockaddr orelse continue;
            if (sa.sa_family != AF_INET) continue;

            const sin: *const SOCKADDR_IN = @ptrCast(@alignCast(sa));
            ip_str = try ip4ToString(&ip_buf, sin.sin_addr, ua.OnLinkPrefixLength);
            break;
        }

        // Link
        // OperStatus: 1=Up (IfOperStatusUp)
        const up = (a.OperStatus == 1);
        var link_buf: [128]u8 = undefined;

        if (a.IfType == IfType_EthernetCSMA) {
            var sp_buf: [64]u8 = undefined;
            // Some drivers report 0; pick max of tx/rx
            const speed = if (a.TransmitLinkSpeed > a.ReceiveLinkSpeed) a.TransmitLinkSpeed else a.ReceiveLinkSpeed;
            const sp = if (speed > 0) try fmtBitsPerSec(&sp_buf, speed) else "unknown speed";
            const link_s = if (duplex_opt) |d|
                try std.fmt.bufPrint(&link_buf, "{s} [ethernet {s} {s}]", .{ if (up) "up" else "down", sp, d })
            else
                try std.fmt.bufPrint(&link_buf, "{s} [ethernet {s}]", .{ if (up) "up" else "down", sp });
            alloc.free(buf);
            return .{
                .ip_cidr = try alloc.dupe(u8, ip_str),
                .link = try alloc.dupe(u8, link_s),
            };
        } else {
            const link_s = if (duplex_opt) |d|
                try std.fmt.bufPrint(&link_buf, "{s} [unknown {s}]", .{ if (up) "up" else "down", d })
            else
                try std.fmt.bufPrint(&link_buf, "{s} [unknown]", .{if (up) "up" else "down"});
            alloc.free(buf);
            return .{
                .ip_cidr = try alloc.dupe(u8, ip_str),
                .link = try alloc.dupe(u8, link_s),
            };
        }
    }

    alloc.free(buf);
    return error.InterfaceNotFound;
}
