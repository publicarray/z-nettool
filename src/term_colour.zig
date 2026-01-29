pub const Status = enum { ok, warn, fail };

const Ansi = struct {
    pub const reset = "\x1b[0m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
};

fn useColour() bool {
    // Keep simple for now; works on modern Windows + POSIX
    return true;
}

fn colour(status: Status) []const u8 {
    return switch (status) {
        .ok => Ansi.green,
        .warn => Ansi.yellow,
        .fail => Ansi.red,
    };
}

pub fn printValue(
    out: anytype,
    status: Status,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    if (useColour()) {
        try out.print("{s}", .{colour(status)});
        try out.print(fmt, args);
        try out.print("{s}", .{Ansi.reset});
    } else {
        try out.print(fmt, args);
    }
}
