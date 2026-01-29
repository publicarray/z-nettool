const std = @import("std");
const builtin = @import("builtin");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    // platform args
    const argv = if (builtin.os.tag == .windows)
        &.{ "ping", "-n", "1", "-w", "2000", host }
    else
        &.{ "ping", "-c", "1", "-W", "2", host };

    var child = std.process.Child.init(argv, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(out_bytes);
    _ = try child.wait();

    if (builtin.os.tag == .windows) {
        // Look for "Average = 44ms"
        if (std.mem.indexOf(u8, out_bytes, "Average =")) |idx| {
            const tail = out_bytes[idx + "Average =".len ..];
            // parse number until 'm'
            var j: usize = 0;
            while (j < tail.len and (tail[j] == ' ')) : (j += 1) {}
            var k = j;
            while (k < tail.len and std.ascii.isDigit(tail[k])) : (k += 1) {}
            if (k > j) {
                const v = std.fmt.parseInt(u32, tail[j..k], 10) catch return null;
                return @as(f64, @floatFromInt(v));
            }
        }
        return null;
    } else {
        // Look for "time=44.0 ms"
        if (std.mem.indexOf(u8, out_bytes, "time=")) |idx| {
            const tail = out_bytes[idx + "time=".len ..];
            var k: usize = 0;
            while (k < tail.len and (std.ascii.isDigit(tail[k]) or tail[k] == '.')) : (k += 1) {}
            if (k > 0) return std.fmt.parseFloat(f64, tail[0..k]) catch null;
        }
        return null;
    }
}

pub fn dnsLookupA(alloc: std.mem.Allocator, name: []const u8) !?[]u8 {
    var list = try std.net.getAddressList(alloc, name, 0);
    defer list.deinit();

    for (list.addrs) |a| {
        if (a.any.family == std.posix.AF.INET) {
            const ip = a.in.sa.addr; // u32 IPv4 (network byte order)
            const b0: u8 = @intCast((ip >> 0) & 0xff);
            const b1: u8 = @intCast((ip >> 8) & 0xff);
            const b2: u8 = @intCast((ip >> 16) & 0xff);
            const b3: u8 = @intCast((ip >> 24) & 0xff);
            return try std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 });
        }
    }
    return null;
}

pub fn httpsStatus(alloc: std.mem.Allocator, url: []const u8) !?u16 {
    if (builtin.os.tag == .windows) {
        // PowerShell: return status code
        // (Invoke-WebRequest throws on some TLS failures; we treat that as null)
        const ps = try std.fmt.allocPrint(
            alloc,
            "try {{ (Invoke-WebRequest -UseBasicParsing -Uri '{s}' -TimeoutSec 5).StatusCode }} catch {{ '' }}",
            .{url},
        );
        defer alloc.free(ps);

        var child = std.process.Child.init(&.{ "powershell", "-NoProfile", "-Command", ps }, alloc);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();
        const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 16 * 1024);
        defer alloc.free(out_bytes);
        _ = try child.wait();

        const s = std.mem.trim(u8, out_bytes, " \t\r\n");
        if (s.len == 0) return null;
        return std.fmt.parseInt(u16, s, 10) catch null;
    } else {
        // curl: print only HTTP code
        // -sS silent, -o discard body, -m max time, -w output code
        var child = std.process.Child.init(&.{ "curl", "-sS", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", url }, alloc);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();
        const out_bytes = try child.stdout.?.readToEndAlloc(alloc, 16 * 1024);
        defer alloc.free(out_bytes);
        _ = try child.wait();

        const s = std.mem.trim(u8, out_bytes, " \t\r\n");
        if (s.len == 0) return null;
        const code = std.fmt.parseInt(u16, s, 10) catch return null;
        if (code == 0) return null;
        return code;
    }
}
