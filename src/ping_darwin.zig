const std = @import("std");

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    var child = std.process.Child.init(&.{ "ping", "-c", "1", "-n", "-q", host }, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.stdin_behavior = .Ignore;
    child.spawn() catch return null;

    const out = child.stdout.?.readToEndAlloc(alloc, 64 * 1024) catch {
        _ = child.wait() catch {};
        return null;
    };
    defer alloc.free(out);

    const term = child.wait() catch return null;
    switch (term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }

    return parsePingAvgMs(out);
}

fn parsePingAvgMs(out: []const u8) ?f64 {
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, "round-trip") and !std.mem.startsWith(u8, line, "rtt")) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        var stats = std.mem.trim(u8, line[eq + 1 ..], " \t");

        const ms_idx = std.mem.indexOf(u8, stats, " ms") orelse stats.len;
        stats = std.mem.trim(u8, stats[0..ms_idx], " \t");

        var it = std.mem.splitScalar(u8, stats, '/');
        _ = it.next(); // min
        if (it.next()) |avg| {
            return std.fmt.parseFloat(f64, std.mem.trim(u8, avg, " \t")) catch null;
        }
    }
    return null;
}
