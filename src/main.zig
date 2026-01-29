const std = @import("std");
const builtin = @import("builtin");

const dhcp = @import("dhcp.zig");
const term_colour = @import("term_colour.zig");
const network_tests = @import("network_tests.zig");

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

    var iface = if (builtin.os.tag == .windows)
        try (@import("iface_windows.zig").chooseInterface(alloc, forced_iface))
    else if (builtin.os.tag == .linux)
        try (@import("iface_linux.zig").chooseInterface(alloc, forced_iface))
    else {
        try err.print("Unsupported OS.\n", .{});
        try err.flush();
        return;
    };

    defer iface.deinit(alloc);

    try out.print("Interface:  {s}\n", .{iface.name});
    try out.print("MAC:        {s}\n", .{fmtMac(&iface.mac)});

    if (builtin.os.tag == .windows) {
        const ni = try @import("netinfo_windows.zig").getIpAndLink(alloc, iface.name);
        defer {
            alloc.free(ni.ip_cidr);
            alloc.free(ni.link);
        }
        try out.print("IP:         {s}\n", .{ni.ip_cidr});
        try out.print("Link:       {s}\n", .{ni.link});
    } else if (builtin.os.tag == .linux) {
        const ni = @import("netinfo_linux.zig");
        var info = try ni.getNetInfo(alloc, iface.name);
        defer info.deinit(alloc);

        try out.print("IP:         {s}\n", .{if (info.ip_cidr.len != 0) info.ip_cidr else "[unknown]"});
        try out.print("Link:       {s}\n\n", .{info.link});
    } else {
        try out.print("IP:         [unknown]\n", .{});
        try out.print("Link:       [unknown]\n\n", .{});
    }
    try out.flush();

    if (builtin.os.tag == .windows) {
        try out.print("\nSwitch / VLAN Info (LLDP)\n", .{});
        const neigh = @import("lldp_windows.zig").collectAndParse(alloc, lldpPacketCaptureTimeout) catch |e| {
            try out.print("  LLDP: capture failed ({s}). Are you running as Admin?\n", .{@errorName(e)});
            return;
        };
        defer {
            for (neigh) |*n| n.deinit(alloc);
            alloc.free(neigh);
        }

        if (neigh.len == 0) {
            try out.print("  No LLDP neighbors detected.\n", .{});
        } else {
            // Simple output (you can table-format later)
            for (neigh) |n| {
                try out.print("  System: {s}\n", .{n.system_name});
                try out.print("  Port:   {s}\n", .{n.port_desc});
                if (n.vlan) |v| try out.print("  VLAN:   {d}\n", .{v});
                try out.print("  Chassis:{s}\n\n", .{n.chassis_id});
            }
        }
    } else if (builtin.os.tag == .linux) {
        try out.print("\nSwitch / VLAN Info (LLDP)\n", .{});
        const allocator = std.heap.page_allocator;
        const lldp = @import("lldp_linux.zig");

        var info = try lldp.parseLLDP(allocator, iface.name);
        defer info.deinit(allocator);

        try out.print("  System: {s}\n", .{info.sys_name orelse "(none)"});
        try out.print("  PortID: {s}\n", .{info.port_id orelse "(none)"});
        try out.print("  PortDescr: {s}\n", .{info.port_descr orelse "(none)"});

        if (info.vlans.items.len == 0) {
            try out.print("  VLANs: (none)\n", .{});
        } else {
            try out.print("  VLANs:\n", .{});
            for (info.vlans.items) |v| try out.print("  - {s}\n", .{v});
        }
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

    try dhcp.discoverAndListen(alloc, iface.name, iface.mac, dhcpListenTimeout);

    try out.flush();
    try waitForEnterOnWindowsIfNotTty();
}

fn parseIfaceArg(args: []const [:0]u8) ?[]const u8 {
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 1) {
        const a = std.mem.sliceTo(args[i], 0);
        if (std.mem.eql(u8, a, "-i")) return std.mem.sliceTo(args[i + 1], 0);
    }
    return null;
}

fn fmtMac(mac: *const [6]u8) [17:0]u8 {
    var buf: [17:0]u8 = undefined;
    _ = std.fmt.bufPrintZ(&buf, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch {};
    return buf;
}

pub const Interface = struct {
    name: []u8, // owned
    mac: [6]u8,

    pub fn deinit(self: *Interface, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        self.* = undefined;
    }
};

fn waitForEnterOnWindowsIfNotTty() !void {
    if (builtin.os.tag != .windows) return;

    // If running in a real terminal, don't pause.
    // if (std.posix.isatty(std.fs.File.stdout().handle)) return;

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
