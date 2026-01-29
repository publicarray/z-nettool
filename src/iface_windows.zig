const std = @import("std");
const w = std.os.windows;

const Interface = @import("main.zig").Interface;

// ---------------- Win32 imports ----------------

extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?w.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: w.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;


// ---------------- Constants ----------------

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

const AF_UNSPEC: u32 = 0;
const AF_INET: u32 = 2;

const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;

// ---------------- Minimal structs ----------------

// Prefix only — safe for reading these fields
const IP_ADAPTER_ADDRESSES_PREFIX = extern struct {
    Length: u32,
    IfIndex: u32,
    Next: ?*IP_ADAPTER_ADDRESSES_PREFIX,
    AdapterName: ?[*:0]u8,

    FirstUnicastAddress: ?*anyopaque,
    FirstAnycastAddress: ?*anyopaque,
    FirstMulticastAddress: ?*anyopaque,
    FirstDnsServerAddress: ?*anyopaque,

    DnsSuffix: ?[*:0]u16,
    Description: ?[*:0]u16,
    FriendlyName: ?[*:0]u16,

    PhysicalAddress: [8]u8,
    PhysicalAddressLength: u32,
};

const IP_ADAPTER_INFO = extern struct {
    Next: ?*IP_ADAPTER_INFO,
    ComboIndex: u32,
    AdapterName: [260]u8,
    Description: [132]u8,
    AddressLength: u32,
    Address: [8]u8,
};

const GetAdaptersAddressesFn = *const fn (
    Family: u32,
    Flags: u32,
    Reserved: ?*anyopaque,
    AdapterAddresses: ?*IP_ADAPTER_ADDRESSES_PREFIX,
    SizePointer: *u32,
) callconv(.winapi) u32;

const GetAdaptersInfoFn = *const fn (
    AdapterInfo: ?*IP_ADAPTER_INFO,
    SizePointer: *u32,
) callconv(.winapi) u32;

// ---------------- Helpers ----------------

fn loadGetAdaptersAddresses() !GetAdaptersAddressesFn {
    const mod = LoadLibraryW(&[_:0]u16{ 'i','p','h','l','p','a','p','i','.','d','l','l' })
        orelse return error.DllLoadFailed;

    const sym = GetProcAddress(mod, &[_:0]u8{
        'G','e','t','A','d','a','p','t','e','r','s','A','d','d','r','e','s','s','e','s'
    }) orelse return error.SymbolNotFound;

    return @ptrCast(sym);
}

fn loadGetAdaptersInfo() !GetAdaptersInfoFn {
    const mod = LoadLibraryW(&[_:0]u16{ 'i','p','h','l','p','a','p','i','.','d','l','l' })
        orelse return error.DllLoadFailed;

    const sym = GetProcAddress(mod, &[_:0]u8{
        'G','e','t','A','d','a','p','t','e','r','s','I','n','f','o'
    }) orelse return error.SymbolNotFound;

    return @ptrCast(sym);
}

fn utf16leZToUtf8Alloc(alloc: std.mem.Allocator, wstr_z: [*:0]const u16) ![]u8 {
    const s16 = std.mem.sliceTo(wstr_z, 0);

    var it = std.unicode.Utf16LeIterator.init(s16);
    var count: usize = 0;

    while (true) {
        const cp = it.nextCodepoint() catch break;
        if (cp == null) break;
        var tmp: [4]u8 = undefined;
        count += std.unicode.utf8Encode(cp.?, &tmp) catch break;
    }

    const out = try alloc.alloc(u8, count);
    errdefer alloc.free(out);

    it = std.unicode.Utf16LeIterator.init(s16);
    var i: usize = 0;
    while (true) {
        const cp = it.nextCodepoint() catch break;
        if (cp == null) break;
        var tmp: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(cp.?, &tmp) catch break;
        @memcpy(out[i..i+len], tmp[0..len]);
        i += len;
    }

    return out;
}

// ---------------- Adapter logic ----------------

const Adapter = struct {
    name: []u8,
    mac: [6]u8,
};

pub fn chooseInterface(alloc: std.mem.Allocator, forced: ?[]const u8) !Interface {
    const adapters = try getAdapters(alloc);
    defer {
        for (adapters) |a| alloc.free(a.name);
        alloc.free(adapters);
    }

    if (adapters.len == 0) return error.NoInterfaces;

    if (forced) |name| {
        for (adapters) |a| {
            if (std.ascii.eqlIgnoreCase(a.name, name)) {
                return .{ .name = try alloc.dupe(u8, a.name), .mac = a.mac };
            }
        }
        return error.InterfaceNotFound;
    }

    std.debug.print("Select interface:\n", .{});
    for (adapters, 0..) |a, i| {
        std.debug.print("  {d}) {s}\n", .{ i + 1, a.name });
    }

    const idx = try readChoice(adapters.len);
    const sel = adapters[idx - 1];
    return .{ .name = try alloc.dupe(u8, sel.name), .mac = sel.mac };
}

fn getAdapters(alloc: std.mem.Allocator) ![]Adapter {
    return getAdaptersViaAddresses(alloc)
        catch getAdaptersViaAdaptersInfo(alloc);
}

fn getAdaptersViaAddresses(alloc: std.mem.Allocator) ![]Adapter {
    const gaa = try loadGetAdaptersAddresses();
    const flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    var buf_len: u32 = 0;
    const rc0 = gaa(AF_UNSPEC, flags, null, null, &buf_len);

    // std.debug.print(
    //     "GetAdaptersAddresses(size) rc={d} buf_len={d}\n",
    //     .{ rc0, buf_len },
    // );

    if (rc0 != ERROR_BUFFER_OVERFLOW or buf_len == 0)
        return error.GetAdaptersFailed;

    const buf = try alloc.alignedAlloc(u8, .@"8", buf_len);
    errdefer alloc.free(buf);

    const addrs: *IP_ADAPTER_ADDRESSES_PREFIX =
        @ptrCast(@alignCast(buf.ptr));

    const rc = gaa(AF_UNSPEC, flags, null, addrs, &buf_len);
    if (rc != ERROR_SUCCESS)
        return error.GetAdaptersFailed;

    var list = try std.ArrayList(Adapter).initCapacity(alloc, 0);
    errdefer {
        for (list.items) |a| alloc.free(a.name);
        list.deinit(alloc);
    }

    var cur: ?*IP_ADAPTER_ADDRESSES_PREFIX = addrs;
    while (cur) |a| : (cur = a.Next) {
        if (a.PhysicalAddressLength < 6) continue;
        if (a.FriendlyName == null) continue;

        const name = try utf16leZToUtf8Alloc(alloc, a.FriendlyName.?);
        var mac: [6]u8 = undefined;
        @memcpy(mac[0..6], a.PhysicalAddress[0..6]);

        try list.append(alloc, .{ .name = name, .mac = mac });
    }

    alloc.free(buf);
    return try list.toOwnedSlice(alloc);
}

fn getAdaptersViaAdaptersInfo(alloc: std.mem.Allocator) ![]Adapter {
    const gai = try loadGetAdaptersInfo();

    var buf_len: u32 = 0;
    const rc0 = gai(null, &buf_len);

    // std.debug.print(
    //     "GetAdaptersInfo(size) rc={d} buf_len={d}\n",
    //     .{ rc0, buf_len },
    // );

    if (rc0 != ERROR_BUFFER_OVERFLOW or buf_len == 0)
        return error.GetAdaptersFailed;

    const buf = try alloc.alignedAlloc(u8, .@"8", buf_len);
    errdefer alloc.free(buf);

    const info: *IP_ADAPTER_INFO =
        @ptrCast(@alignCast(buf.ptr));

    const rc = gai(info, &buf_len);
    if (rc != ERROR_SUCCESS)
        return error.GetAdaptersFailed;

    var list = try std.ArrayList(Adapter).initCapacity(alloc, 0);
    errdefer {
        for (list.items) |a| alloc.free(a.name);
        list.deinit(alloc);
    }

    var cur: ?*IP_ADAPTER_INFO = info;
    while (cur) |a| : (cur = a.Next) {
        if (a.AddressLength < 6) continue;

        const desc = std.mem.sliceTo(&a.Description, 0);
        const name = try alloc.dupe(u8, desc);

        var mac: [6]u8 = undefined;
        @memcpy(mac[0..6], a.Address[0..6]);

        try list.append(alloc, .{ .name = name, .mac = mac });
    }

    alloc.free(buf);
    return try list.toOwnedSlice(alloc);
}

fn readChoice(max: usize) !usize {
    var in_buf: [1024]u8 = undefined;
    var in_reader = std.fs.File.stdin().reader(&in_buf);
    const input = &in_reader.interface;

    var out_buf: [1024]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    var line: [64]u8 = undefined;

    while (true) {
        try out.print("Enter number (1..{d}): ", .{max});
        try out.flush();

        var len: usize = 0;
        while (true) {
            const b = input.takeByte() catch return error.EndOfStream;
            if (b == '\n') break;
            if (b == '\r') continue;
            if (len < line.len) {
                line[len] = b;
                len += 1;
            }
        }

        const s = std.mem.trim(u8, line[0..len], " \t\r\n");
        const v = std.fmt.parseInt(usize, s, 10) catch continue;
        if (v >= 1 and v <= max) return v;
    }
}
