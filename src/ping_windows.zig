const std = @import("std");
const windows = std.os.windows;
const ping_common = @import("ping_common.zig");

const IcmpApi = struct {
    pub const IP_OPTION_INFORMATION = extern struct {
        Ttl: u8,
        Tos: u8,
        Flags: u8,
        OptionsSize: u8,
        OptionsData: ?*u8,
    };

    pub const ICMP_ECHO_REPLY = extern struct {
        Address: u32,
        Status: u32,
        RoundTripTime: u32,
        DataSize: u16,
        Reserved: u16,
        Data: ?*anyopaque,
        Options: IP_OPTION_INFORMATION,
    };

    pub extern "iphlpapi" fn IcmpCreateFile() callconv(.winapi) windows.HANDLE;
    pub extern "iphlpapi" fn IcmpCloseHandle(handle: windows.HANDLE) callconv(.winapi) windows.BOOL;
    pub extern "iphlpapi" fn IcmpSendEcho(
        handle: windows.HANDLE,
        dest: u32,
        request_data: ?*const anyopaque,
        request_size: u16,
        request_options: ?*const IP_OPTION_INFORMATION,
        reply_buffer: ?*anyopaque,
        reply_size: u32,
        timeout: u32,
    ) callconv(.winapi) u32;
};

pub fn pingMs(alloc: std.mem.Allocator, host: []const u8) !?f64 {
    const addr = (try ping_common.resolveIpv4(alloc, host)) orelse return null;
    const dest: u32 = addr.in.sa.addr;

    const handle = IcmpApi.IcmpCreateFile();
    if (handle == windows.INVALID_HANDLE_VALUE) return null;
    defer _ = IcmpApi.IcmpCloseHandle(handle);

    var payload: [32]u8 = undefined;
    @memset(&payload, 0x42);

    var opts: IcmpApi.IP_OPTION_INFORMATION = .{
        .Ttl = 64,
        .Tos = 0,
        .Flags = 0,
        .OptionsSize = 0,
        .OptionsData = null,
    };

    var reply_buf: [@sizeOf(IcmpApi.ICMP_ECHO_REPLY) + payload.len]u8 align(@alignOf(IcmpApi.ICMP_ECHO_REPLY)) = undefined;
    const replies = IcmpApi.IcmpSendEcho(
        handle,
        dest,
        payload[0..].ptr,
        @intCast(payload.len),
        &opts,
        &reply_buf,
        @intCast(reply_buf.len),
        2000,
    );
    if (replies == 0) return null;

    const reply: *IcmpApi.ICMP_ECHO_REPLY = @ptrCast(@alignCast(&reply_buf));
    if (reply.Status != 0) return null;
    return @as(f64, @floatFromInt(reply.RoundTripTime));
}
