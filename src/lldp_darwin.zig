const std = @import("std");
const common = @import("lldp_common.zig");
const lldp_tcpdump = @import("lldp_tcpdump_darwin.zig");
const lldp_ctl = @import("lldp_lldpctl_darwin.zig");

pub fn collectAndParseCommon(alloc: std.mem.Allocator, iface: []const u8, listen_seconds: u32) ![]common.Neighbor {
    return lldp_tcpdump.collectAndParseCommon(alloc, iface, listen_seconds);
}

pub fn collectAndParseCommonCtl(alloc: std.mem.Allocator, iface: []const u8) ![]common.Neighbor {
    return lldp_ctl.collectAndParseCommonCtl(alloc, iface);
}
