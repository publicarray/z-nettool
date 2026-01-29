const std = @import("std");
const builtin = @import("builtin");

const dhcp = @import("dhcp.zig");
const iface = @import("iface.zig");
const lldp = @import("lldp.zig");
const netinfo = @import("netinfo.zig");
const term_colour = @import("term_colour.zig");
const network_tests = @import("network_tests.zig");
const lldp_common = @import("lldp_common.zig");
const netinfo_common = @import("netinfo_common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const lldpPacketCaptureTimeout = 30;
    const dhcpListenTimeout = 30;

    // Zig 0.15+ stdout/stderr: you must provide a buffer and flush. :contentReference[oaicite:1]{index=1}
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var err_buf: [2048]u8 = undefined;
    var err_writer = std.fs.File.stderr().writer(&err_buf);
    const err = &err_writer.interface;

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    const forced_iface = parseIfaceArg(args);
    const force_dhcp_udp = hasFlag(args, "--dhcp-udp");

    var selected_iface = iface.chooseInterface(alloc, forced_iface) catch |e| {
        if (e == error.UnsupportedOS) {
            try err.print("Unsupported OS.\n", .{});
            try err.flush();
            return;
        }
        return e;
    };

    defer selected_iface.deinit(alloc);

    try out.print("Interface:  {s}\n", .{selected_iface.name});
    try out.print("MAC:        {s}\n", .{fmtMac(&selected_iface.mac)});

    if (builtin.os.tag == .windows) {
        try printWindowsPrereqWarnings(out, alloc);

        var info = try netinfo.getNetInfoCommon(alloc, selected_iface.name);
        defer info.deinit(alloc);
        try printNetInfo(out, info);
    } else if (builtin.os.tag == .linux) {
        try printLinuxPrereqWarnings(out, alloc);

        var info = try netinfo.getNetInfoCommon(alloc, selected_iface.name);
        defer info.deinit(alloc);
        try printNetInfo(out, info);
    } else if (builtin.os.tag == .macos) {
        try printDarwinPrereqWarnings(out, alloc);

        var info = try netinfo.getNetInfoCommon(alloc, selected_iface.name);
        defer info.deinit(alloc);
        try printNetInfo(out, info);
    } else {
        try out.print("IP:         [unknown]\n", .{});
        try out.print("Link:       [unknown]\n\n", .{});
    }
    try out.flush();

    if (builtin.os.tag == .windows) {
        try out.print("\nSwitch / VLAN Info (LLDP)\n", .{});
        const neigh = lldp.collectAndParseCommon(alloc, selected_iface.name, lldpPacketCaptureTimeout) catch |e| {
            try out.print("  LLDP: capture failed ({s}). Are you running as Admin?\n", .{@errorName(e)});
            try out.flush();
            return;
        };
        defer {
            for (neigh) |*n| n.deinit(alloc);
            alloc.free(neigh);
        }

        try printLldpReport(out, neigh);
    } else if (builtin.os.tag == .linux) {
        try out.print("\nSwitch / VLAN Info (LLDP)\n", .{});
        const neigh = lldp.collectAndParseCommon(alloc, selected_iface.name, lldpPacketCaptureTimeout) catch |e| {
            if (e == error.LldpctlFailed) {
                try out.print("  LLDP: lldpctl failed. Is lldpd running?\n", .{});
                try out.print("  Hint: sudo systemctl start lldpd\n", .{});
                try out.flush();
                return;
            }
            return e;
        };
        defer {
            for (neigh) |*n| n.deinit(alloc);
            alloc.free(neigh);
        }

        try printLldpReport(out, neigh);
    } else if (builtin.os.tag == .macos) {
        try out.print("\nSwitch / VLAN Info (LLDP)\n", .{});
        const neigh = lldp.collectAndParseCommon(alloc, selected_iface.name, lldpPacketCaptureTimeout) catch |e| {
            if (e == error.LldpctlFailed) {
                try out.print("  LLDP: lldpctl failed. Is lldpd installed/running?\n", .{});
                try out.print("  Hint: brew install lldpd && sudo lldpd\n", .{});
                try out.flush();
                return;
            }
            return e;
        };
        defer {
            for (neigh) |*n| n.deinit(alloc);
            alloc.free(neigh);
        }

        try printLldpReport(out, neigh);
    }

    try out.print("Connectivity Tests\n", .{});

    const warn_ping_ms: f64 = 80.0;
    const fail_ping_ms: f64 = 250.0;

    // Ping 8.8.8.8
    try out.print("  Ping 8.8.8.8:   ", .{});
    if (try network_tests.pingMs(alloc, "8.8.8.8")) |ms| {
        const s: term_colour.Status = if (ms >= fail_ping_ms) .fail else if (ms >= warn_ping_ms) .warn else .ok;
        try term_colour.printValue(out, s, "{d:.1} ms\n", .{ms});
    } else {
        try term_colour.printValue(out, .fail, "[failed]\n", .{});
    }

    // Ping 1.1.1.1
    try out.print("  Ping 1.1.1.1:   ", .{});
    if (try network_tests.pingMs(alloc, "1.1.1.1")) |ms| {
        const s: term_colour.Status = if (ms >= fail_ping_ms) .fail else if (ms >= warn_ping_ms) .warn else .ok;
        try term_colour.printValue(out, s, "{d:.1} ms\n", .{ms});
    } else {
        try term_colour.printValue(out, .fail, "[failed]\n", .{});
    }

    // DNS
    try out.print("  DNS Lookup:     ", .{});
    if (try network_tests.dnsLookupA(alloc, "google.com")) |ipstr| {
        defer alloc.free(ipstr);
        try term_colour.printValue(out, .ok, "google.com {s}\n", .{ipstr});
    } else {
        try term_colour.printValue(out, .fail, "[failed]\n", .{});
    }

    // HTTPS
    try out.print("  HTTPS Test:     ", .{});
    if (try network_tests.httpsStatus(alloc, "https://www.google.com")) |code| {
        const s: term_colour.Status = if (code >= 200 and code < 400) .ok else .fail;
        try term_colour.printValue(out, s, "{d}\n", .{code});
    } else {
        try term_colour.printValue(out, .fail, "[failed]\n", .{});
    }

    try out.print("\nDHCP Lease / Server Detection\n", .{});
    try out.flush();

    try out.print("DHCP: sending DISCOVER and listening for OFFER...\n", .{});
    try out.flush();

    try dhcp.discoverAndListen(alloc, selected_iface.name, selected_iface.mac, dhcpListenTimeout, force_dhcp_udp);

    try out.flush();
    try waitForEnterOnWindowsIfNotTty();
}

fn printLldpReport(out: anytype, neigh: []lldp_common.Neighbor) !void {
    if (neigh.len == 0) {
        try out.print("  No LLDP neighbors detected.\n", .{});
        return;
    }

    for (neigh) |n| {
        try out.print("  System:      {s}\n", .{n.system_name});
        try out.print("  SystemDescr: {s}\n", .{n.system_desc});
        try out.print("  PortID:      {s}\n", .{n.port_id});
        try out.print("  PortDescr:   {s}\n", .{n.port_desc});
        try out.print("  VLANs:       {s}\n", .{n.vlans_csv});
        try out.print("  Chassis:     {s}\n\n", .{n.chassis_id});
    }
}

fn printNetInfo(out: anytype, info: netinfo_common.NetInfo) !void {
    try out.print("IP:         {s}\n", .{info.ip_cidr});
    if (info.ip6_cidr.len != 0) {
        try out.print("IPv6:       {s}\n", .{info.ip6_cidr});
    }
    try out.print("Link:       ", .{});
    if (linkStateStatus(info.link_state)) |s| {
        try term_colour.printValue(out, s, "{s}", .{info.link_state});
    } else {
        try out.print("{s}", .{info.link_state});
    }
    try out.print(" [{s} ", .{info.link_kind});
    if (speedStatus(info.link_speed)) |s| {
        try term_colour.printValue(out, s, "{s}", .{info.link_speed});
    } else {
        try out.print("{s}", .{info.link_speed});
    }
    try out.print(" {s}]\n\n", .{info.link_duplex});
}

fn linkStateStatus(state: []const u8) ?term_colour.Status {
    const s = std.mem.trim(u8, state, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(s, "up")) return .ok;
    if (std.ascii.eqlIgnoreCase(s, "down")) return .fail;
    return .warn;
}

fn speedStatus(speed: []const u8) ?term_colour.Status {
    const mbps = parseSpeedMbps(speed) orelse return null;
    if (mbps < 1000.0) {
        return .warn;
    }
    if (mbps < 2000.0) {
        return .ok;
    }
    return .fast;
}

fn parseSpeedMbps(speed: []const u8) ?f64 {
    const s = std.mem.trim(u8, speed, " \t\r\n");
    if (std.ascii.endsWithIgnoreCase(s, "Mbps")) {
        const num = std.mem.trim(u8, s[0 .. s.len - 4], " \t");
        return std.fmt.parseFloat(f64, num) catch null;
    }
    if (std.ascii.endsWithIgnoreCase(s, "Gbps")) {
        const num = std.mem.trim(u8, s[0 .. s.len - 4], " \t");
        const gbps = std.fmt.parseFloat(f64, num) catch null;
        return (gbps orelse return null) * 1000.0;
    }
    return null;
}

fn printLinuxPrereqWarnings(out: anytype, alloc: std.mem.Allocator) !void {
    var any = false;

    if (!hasExecutableInPath(alloc, "lldpctl")) {
        try out.print("Warning: lldpctl not found (install lldpd/lldpctl).\n", .{});
        any = true;
    }
    if (!hasAnyFile(&.{
        "/usr/lib/libpcap.so",
        "/usr/lib64/libpcap.so",
        "/usr/lib/x86_64-linux-gnu/libpcap.so",
    })) {
        try out.print("Warning: libpcap not found (install libpcap).\n", .{});
        any = true;
    }
    if (std.posix.geteuid() != 0) {
        try out.print("Warning: ICMP ping requires CAP_NET_RAW or root; ping tests may fail.\n", .{});
        any = true;
    }

    if (any) try out.print("\n", .{});
}

fn printDarwinPrereqWarnings(out: anytype, alloc: std.mem.Allocator) !void {
    var any = false;

    if (!hasExecutableInPath(alloc, "lldpctl")) {
        try out.print("Warning: lldpctl not found (install lldpd).\n", .{});
        any = true;
    }

    if (any) try out.print("\n", .{});
}

fn hasExecutableInPath(alloc: std.mem.Allocator, name: []const u8) bool {
    const path_env = std.process.getEnvVarOwned(alloc, "PATH") catch return false;
    defer alloc.free(path_env);

    const delim = std.fs.path.delimiter;
    var it = std.mem.splitScalar(u8, path_env, delim);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const full = std.fs.path.join(alloc, &.{ dir, name }) catch continue;
        defer alloc.free(full);
        const f = std.fs.openFileAbsolute(full, .{}) catch continue;
        f.close();
        return true;
    }
    return false;
}

fn hasAnyFile(paths: []const []const u8) bool {
    for (paths) |p| {
        const f = std.fs.openFileAbsolute(p, .{}) catch continue;
        f.close();
        return true;
    }
    return false;
}

fn printWindowsPrereqWarnings(out: anytype, alloc: std.mem.Allocator) !void {
    if (!hasExecutableInPath(alloc, "pktmon.exe")) {
        try out.print("Warning: pktmon.exe not found (LLDP capture will fail).\n\n", .{});
    }
}

fn parseIfaceArg(args: []const [:0]u8) ?[]const u8 {
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 1) {
        const a = std.mem.sliceTo(args[i], 0);
        if (std.mem.eql(u8, a, "-i")) return std.mem.sliceTo(args[i + 1], 0);
    }
    return null;
}

fn hasFlag(args: []const [:0]u8, flag: []const u8) bool {
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = std.mem.sliceTo(args[i], 0);
        if (std.mem.eql(u8, a, flag)) return true;
    }
    return false;
}

fn fmtMac(mac: *const [6]u8) [17:0]u8 {
    var buf: [17:0]u8 = undefined;
    _ = std.fmt.bufPrintZ(&buf, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch {};
    return buf;
}

fn waitForEnterOnWindowsIfNotTty() !void {
    if (builtin.os.tag != .windows) return;

    var out_buf: [512]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    try out.print("\nPress Enter to exit...", .{});
    try out.flush();

    var in_buf: [256]u8 = undefined;
    var in_reader = std.fs.File.stdin().reader(&in_buf);
    const input = &in_reader.interface;

    // Read until newline or EOF
    while (true) {
        const b = input.takeByte() catch break;
        if (b == '\n') break;
    }
}
