const std = @import("std");

pub const AF_INET: u8 = 2;
pub const AF_LINK: u8 = 18;
pub const AF_INET6: u8 = 30;

pub const IFF_UP: u32 = 0x1;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_LOOPBACK: u32 = 0x8;

pub const IFT_ETHER: u8 = 0x6;

pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;

pub const socklen_t = u32;

pub const sockaddr = extern struct {
    sa_len: u8,
    sa_family: u8,
    sa_data: [14]u8,
};

pub const in_addr = extern struct {
    s_addr: u32,
};

pub const sockaddr_in = extern struct {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: in_addr,
    sin_zero: [8]u8,
};

pub const in6_addr = extern struct {
    addr: [16]u8,
};

pub const sockaddr_in6 = extern struct {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: in6_addr,
    sin6_scope_id: u32,
};

pub const sockaddr_dl = extern struct {
    sdl_len: u8,
    sdl_family: u8,
    sdl_index: u16,
    sdl_type: u8,
    sdl_nlen: u8,
    sdl_alen: u8,
    sdl_slen: u8,
    sdl_data: [12]u8,
};

pub const ifaddrs = extern struct {
    ifa_next: ?*ifaddrs,
    ifa_name: ?[*:0]u8,
    ifa_flags: u32,
    ifa_addr: ?*sockaddr,
    ifa_netmask: ?*sockaddr,
    ifa_dstaddr: ?*sockaddr,
    ifa_data: ?*anyopaque,
};

pub extern "c" fn getifaddrs(ifap: *?*ifaddrs) c_int;
pub extern "c" fn freeifaddrs(ifap: ?*ifaddrs) void;
pub extern "c" fn inet_ntop(af: c_int, src: *const anyopaque, dst: [*]u8, size: socklen_t) ?[*:0]u8;
