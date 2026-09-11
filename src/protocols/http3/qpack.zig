//! QPACK - QUIC header compression (RFC 9204).
//!
//! Static table (99 entries), dynamic table with eviction, field-section
//! representations (indexed, name references, literals, post-base), the
//! field-section prefix (Required Insert Count / Delta Base, including
//! blocked sections), encoder-stream instructions (Set Capacity, Insert
//! with Name Reference, Insert with Literal Name, Duplicate) and
//! decoder-stream instructions (Section Acknowledgment, Stream
//! Cancellation, Insert Count Increment).
//!
//! Dynamic-table wire layouts implement RFC 9204 Sections 4.3-4.5
//! (opcodes, T-bit polarity, relative indexes, RIC/Base math).
//! Encoder policy is insert-on-first-use with literal fallback when the
//! table is full or barred; eviction of entries referenced by
//! unacknowledged sections is fenced by `evictBarrier`, which the
//! connection layer advances from decoder-stream acknowledgments.
//!
//! References:
//!   - RFC 9204 — QPACK: Field Compression for HTTP/3
//!   - RFC 9204 Section 2.3.2 — Static Table
//!   - RFC 9204 Section 3.1 — Encoder Instructions
//!   - RFC 9204 Section 3.2.6 — Decoder Instructions

const std = @import("std");
const Allocator = std.mem.Allocator;
const varint = @import("../quic/varint.zig");
const huff = @import("../common/huffman.zig");

pub const Error = error{
    InvalidIndex,
    InvalidInstruction,
    TableCapacityExceeded,
    /// A field section references dynamic entries the decoder has not
    /// received yet (Required Insert Count beyond our insert count).
    /// Not a protocol violation: buffer the section bytes and retry
    /// after feeding more encoder-stream data.
    Blocked,
    /// More bytes are needed to finish the current integer or string.
    /// Instruction-stream readers treat trailing Truncated as "wait
    /// for more bytes"; anywhere else it is malformed input.
    Truncated,
    OutOfMemory,
    BufferTooSmall,
};

pub const ENTRY_OVERHEAD: usize = 32;

/// Resource caps: names are short, values can be large (cookies),
/// large (cookies), sections are bounded by maxFieldSectionSize.
pub const MAX_NAME_LEN: usize = 256;
pub const MAX_VALUE_LEN: usize = 65536;

fn take(data: []const u8, offset: *usize, length: u64) Error![]const u8 {
    const n = std.math.cast(usize, length) orelse return Error.InvalidInstruction;
    if (offset.* > data.len or n > data.len - offset.*) return Error.Truncated;
    const result = data[offset.*..][0..n];
    offset.* += n;
    return result;
}

fn readString(allocator: Allocator, data: []const u8, offset: *usize, max_len: usize) Error![]u8 {
    if (offset.* >= data.len) return Error.Truncated;
    const huffman_encoded = data[offset.*] & 0x80 != 0;
    const length = try decodeInt(data, offset, 7);
    if (length > max_len) return Error.InvalidInstruction;
    const encoded = try take(data, offset, length);
    return decodeStringBytes(allocator, encoded, huffman_encoded, max_len);
}

/// Decodes already-framed string bytes (length known, header parsed).
fn decodeStringBytes(allocator: Allocator, encoded: []const u8, huffman: bool, max_len: usize) Error![]u8 {
    if (!huffman) return allocator.dupe(u8, encoded) catch return Error.OutOfMemory;
    const doubled = std.math.mul(usize, encoded.len, 2) catch return Error.OutOfMemory;
    const capacity = std.math.add(usize, doubled, 1) catch return Error.OutOfMemory;
    const decoded = allocator.alloc(u8, capacity) catch return Error.OutOfMemory;
    errdefer allocator.free(decoded);
    const n = huff.decode(decoded, encoded) catch return Error.InvalidInstruction;
    if (n > max_len) return Error.InvalidInstruction;
    return allocator.realloc(decoded, n) catch return Error.OutOfMemory;
}

pub const StaticEntry = struct { name: []const u8, value: []const u8 };

/// QPACK static table (RFC 9204 Appendix A) - first entries shown; full list encoded.
pub const STATIC_TABLE_SIZE = 99;

fn se(name: []const u8, value: []const u8) StaticEntry {
    return .{ .name = name, .value = value };
}

pub const staticTable = [_]StaticEntry{
    se(":authority", ""), // 0
    se(":path", "/"), // 1
    se("age", "0"), // 2
    se("content-disposition", ""), // 3
    se("content-length", "0"), // 4
    se("cookie", ""), // 5
    se("date", ""), // 6
    se("etag", ""), // 7
    se("if-modified-since", ""), // 8
    se("if-none-match", ""), // 9
    se("last-modified", ""), // 10
    se("link", ""), // 11
    se("location", ""), // 12
    se("referer", ""), // 13
    se("set-cookie", ""), // 14
    se(":method", "CONNECT"), // 15
    se(":method", "DELETE"), // 16
    se(":method", "GET"), // 17
    se(":method", "HEAD"), // 18
    se(":method", "OPTIONS"), // 19
    se(":method", "POST"), // 20
    se(":method", "PUT"), // 21
    se(":scheme", "http"), // 22
    se(":scheme", "https"), // 23
    se(":status", "103"), // 24
    se(":status", "200"), // 25
    se(":status", "304"), // 26
    se(":status", "404"), // 27
    se(":status", "503"), // 28
    se("accept", "*/*"), // 29
    se("accept", "application/dns-message"), // 30
    se("accept-encoding", "gzip, deflate, br"), // 31
    se("accept-ranges", "bytes"), // 32
    se("access-control-allow-headers", "cache-control"), // 33
    se("access-control-allow-headers", "content-type"), // 34
    se("access-control-allow-origin", "*"), // 35
    se("cache-control", "max-age=0"), // 36
    se("cache-control", "max-age=2592000"), // 37
    se("cache-control", "max-age=604800"), // 38
    se("cache-control", "no-cache"), // 39
    se("cache-control", "no-store"), // 40
    se("cache-control", "public, max-age=31536000"), // 41
    se("content-encoding", "br"), // 42
    se("content-encoding", "gzip"), // 43
    se("content-type", "application/dns-message"), // 44
    se("content-type", "application/javascript"), // 45
    se("content-type", "application/json"), // 46
    se("content-type", "application/x-www-form-urlencoded"), // 47
    se("content-type", "image/gif"), // 48
    se("content-type", "image/jpeg"), // 49
    se("content-type", "image/png"), // 50
    se("content-type", "text/css"), // 51
    se("content-type", "text/html; charset=utf-8"), // 52
    se("content-type", "text/plain"), // 53
    se("content-type", "text/plain;charset=utf-8"), // 54
    se("range", "bytes=0-"), // 55
    se("strict-transport-security", "max-age=31536000"), // 56
    se("strict-transport-security", "max-age=31536000; includesubdomains"), // 57
    se("strict-transport-security", "max-age=31536000; includesubdomains; preload"), // 58
    se("vary", "accept-encoding"), // 59
    se("vary", "origin"), // 60
    se("x-content-type-options", "nosniff"), // 61
    se("x-xss-protection", "1; mode=block"), // 62
    se(":status", "100"), // 63
    se(":status", "204"), // 64
    se(":status", "206"), // 65
    se(":status", "302"), // 66
    se(":status", "400"), // 67
    se(":status", "403"), // 68
    se(":status", "421"), // 69
    se(":status", "425"), // 70
    se(":status", "500"), // 71
    se("accept-language", ""), // 72
    se("access-control-allow-credentials", "FALSE"), // 73
    se("access-control-allow-credentials", "TRUE"), // 74
    se("access-control-allow-headers", "*"), // 75
    se("access-control-allow-methods", "get"), // 76
    se("access-control-allow-methods", "get, post, options"), // 77
    se("access-control-allow-methods", "options"), // 78
    se("access-control-expose-headers", "content-length"), // 79
    se("access-control-request-headers", "content-type"), // 80
    se("access-control-request-method", "get"), // 81
    se("access-control-request-method", "post"), // 82
    se("alt-svc", "clear"), // 83
    se("authorization", ""), // 84
    se("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"), // 85
    se("early-data", "1"), // 86
    se("expect-ct", ""), // 87
    se("forwarded", ""), // 88
    se("if-range", ""), // 89
    se("origin", ""), // 90
    se("purpose", "prefetch"), // 91
    se("server", ""), // 92
    se("timing-allow-origin", "*"), // 93
    se("upgrade-insecure-requests", "1"), // 94
    se("user-agent", ""), // 95
    se("x-forwarded-for", ""), // 96
    se("x-frame-options", "deny"), // 97
    se("x-frame-options", "sameorigin"), // 98
};

// Integer primitives shared with HPACK-style prefixes

pub fn encodeInt(buf: []u8, prefixBits: u4, value: u64) Error!usize {
    if (buf.len < 1) return Error.BufferTooSmall;
    const max_prefix: u64 = (@as(u64, 1) << prefixBits) - 1;
    buf[0] = 0;

    if (value < max_prefix) {
        buf[0] |= @intCast(value);
        return 1;
    }
    buf[0] |= @intCast(max_prefix);
    var remaining = value - max_prefix;
    var pos: usize = 1;
    while (remaining >= 128) {
        if (pos >= buf.len) return Error.BufferTooSmall;
        buf[pos] = @intCast((remaining % 128) + 128);
        remaining /= 128;
        pos += 1;
    }
    if (pos >= buf.len) return Error.BufferTooSmall;
    buf[pos] = @intCast(remaining);
    return pos + 1;
}

pub fn decodeInt(data: []const u8, offset: *usize, prefixBits: u4) Error!u64 {
    if (offset.* >= data.len) return Error.Truncated;
    const max_prefix: u64 = (@as(u64, 1) << prefixBits) - 1;
    var value: u64 = data[offset.*] & @as(u8, @intCast(max_prefix));
    offset.* += 1;
    if (value < max_prefix) return value;

    var shift: u6 = 0;
    var terminated = false;
    while (offset.* < data.len) {
        const b = data[offset.*];
        offset.* += 1;
        if (shift >= 63 and (b & 0x7F) > 1) return Error.InvalidInstruction;
        const contribution = @as(u64, b & 0x7F) << shift;
        value = std.math.add(u64, value, contribution) catch return Error.InvalidInstruction;
        if (b & 0x80 == 0) {
            terminated = true;
            break;
        }
        shift += 7;
        if (shift > 63) return Error.InvalidInstruction;
    }
    if (!terminated) return Error.Truncated;
    return value;
}

// Dynamic table entry (RFC 9204 Section 2.3.2).

pub const DynEntry = struct {
    name: []const u8,
    value: []const u8,
    /// Total size = name.len + value.len + ENTRY_OVERHEAD (32).
    totalSize: usize,
};

pub const DynTable = struct {
    entries: std.ArrayList(DynEntry),
    maxSize: usize,
    currentSize: usize = 0,
    /// Absolute index of the oldest retained dynamic entry.
    baseIndex: u64 = STATIC_TABLE_SIZE,
    /// Absolute index assigned to the next insertion.
    nextIndex: u64 = STATIC_TABLE_SIZE,

    pub fn init(_: Allocator, maxSize: usize) DynTable {
        return .{
            .entries = std.ArrayList(DynEntry).empty,
            .maxSize = maxSize,
        };
    }

    pub fn deinit(self: *DynTable, allocator: Allocator) void {
        for (self.entries.items) |e| {
            allocator.free(e.name);
            allocator.free(e.value);
        }
        self.entries.deinit(allocator);
    }

    /// Inserts a new entry, evicting oldest entries to stay within maxSize.
    pub fn insert(self: *DynTable, allocator: Allocator, name: []const u8, value: []const u8) !u64 {
        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);
        const owned_value = try allocator.dupe(u8, value);
        errdefer allocator.free(owned_value);

        const total = std.math.add(usize, std.math.add(usize, name.len, value.len) catch return Error.OutOfMemory, ENTRY_OVERHEAD) catch return Error.OutOfMemory;
        if (total > self.maxSize) return Error.TableCapacityExceeded;
        const index = self.nextIndex;

        // Evict from oldest (index = STATIC_TABLE_SIZE) until room.
        while (self.currentSize + total > self.maxSize and self.entries.items.len > 0) {
            const old = self.entries.orderedRemove(0);
            self.currentSize -%= old.totalSize;
            self.baseIndex = std.math.add(u64, self.baseIndex, 1) catch return Error.OutOfMemory;
            allocator.free(old.name);
            allocator.free(old.value);
        }

        try self.entries.append(allocator, .{
            .name = owned_name,
            .value = owned_value,
            .totalSize = total,
        });
        self.currentSize += total;
        self.nextIndex = std.math.add(u64, self.nextIndex, 1) catch return Error.OutOfMemory;
        return @intCast(index);
    }

    /// Lowers (or raises) the capacity, evicting oldest entries to fit.
    /// Used for encoder-stream Set Capacity instructions.
    pub fn setMaxSize(self: *DynTable, allocator: Allocator, max_size: usize) void {
        self.maxSize = max_size;
        while (self.currentSize > self.maxSize and self.entries.items.len > 0) {
            const old = self.entries.orderedRemove(0);
            self.currentSize -%= old.totalSize;
            self.baseIndex +%= 1;
            allocator.free(old.name);
            allocator.free(old.value);
        }
    }

    /// Resolves a QPACK absolute index to a name+value pair.
    pub fn resolve(self: *const DynTable, absoluteIndex: u64) ?struct { name: []const u8, value: []const u8 } {
        if (absoluteIndex < STATIC_TABLE_SIZE) {
            const e = staticTable[@intCast(absoluteIndex)];
            return .{ .name = e.name, .value = e.value };
        }
        if (absoluteIndex < self.baseIndex) return null;
        const dyn_idx = absoluteIndex - self.baseIndex;
        if (dyn_idx >= self.entries.items.len) return null;
        const e = self.entries.items[@intCast(dyn_idx)];
        return .{ .name = e.name, .value = e.value };
    }
};

// Encoder

pub const Encoder = struct {
    allocator: Allocator,
    dyn: ?DynTable = null,
    /// Peer's QPACK_MAX_TABLE_CAPACITY (our table limit). Also sizes the
    /// Required Insert Count modulo in section prefixes.
    peerMaxCapacity: usize = 0,
    /// Peer's QPACK_BLOCKED_STREAMS hint, retained for policy tuning.
    peerMaxBlocked: u64 = 0,
    /// Absolute indexes below this are pinned against eviction: they may
    /// still be referenced by unacknowledged sections. The connection
    /// layer advances this from decoder-stream Section Acknowledgments.
    /// Defaults to pinning everything (literal fallback when full).
    evictBarrier: u64 = STATIC_TABLE_SIZE,
    /// Encoder-stream bytes not yet flushed (inserts, capacity changes).
    /// Drain with `takeEncoderBytes` and send on the encoder stream.
    pending: std.ArrayList(u8) = .empty,
    /// Buffered decoder-stream bytes with a consume cursor; a trailing
    /// split instruction waits for more bytes instead of erroring.
    decBuf: std.ArrayList(u8) = .empty,
    decOff: usize = 0,
    /// Highest insert count the peer confirmed via Insert Count Increment.
    peerKnownInserts: u64 = STATIC_TABLE_SIZE,
    /// Set while encoding a section whenever a dynamic reference is
    /// emitted. Builders read it via `sectionRic` to size the prefix.
    sectionUsedDynamic: bool = false,

    pub fn init(allocator: Allocator) Encoder {
        return .{ .allocator = allocator };
    }

    /// Releases the optional dynamic table and all strings owned by it.
    pub fn deinit(self: *Encoder) void {
        if (self.dyn) |*d| d.deinit(self.allocator);
        self.dyn = null;
        self.pending.deinit(self.allocator);
        self.decBuf.deinit(self.allocator);
        self.decOff = 0;
    }

    /// Sizes the dynamic table to the peer's advertised capacity and
    /// queues a Set Capacity instruction for the encoder stream.
    pub fn setMaxTableCapacity(self: *Encoder, capacity: usize) void {
        if (self.dyn) |*d| d.deinit(self.allocator);
        self.dyn = null;
        self.peerMaxCapacity = capacity;
        if (capacity != 0) {
            self.dyn = DynTable.init(self.allocator, capacity);
        }
        var ib: [16]u8 = undefined;
        const n = encodeInt(&ib, 5, capacity) catch return;
        ib[0] |= 0x20;
        self.pending.appendSlice(self.allocator, ib[0..n]) catch {};
    }

    pub fn setMaxBlockedStreams(self: *Encoder, n: u64) void {
        self.peerMaxBlocked = n;
    }

    pub fn setEvictBarrier(self: *Encoder, abs_index: u64) void {
        self.evictBarrier = abs_index;
    }

    /// Next absolute dynamic index that will be assigned.
    pub fn insertCount(self: *const Encoder) u64 {
        if (self.dyn) |*d| return d.nextIndex;
        return STATIC_TABLE_SIZE;
    }

    /// Takes pending encoder-stream bytes; caller sends them on the
    /// encoder unidirectional stream, then frees the slice (always
    /// owned, even when empty).
    pub fn takeEncoderBytes(self: *Encoder) ![]u8 {
        if (self.pending.items.len == 0) return try self.allocator.dupe(u8, &.{});
        return try self.pending.toOwnedSlice(self.allocator);
    }

    fn emitString(self: *Encoder, out: *std.ArrayList(u8), str: []const u8, n: u3) !void {
        if (str.len == 0) {
            var tmp: [10]u8 = undefined;
            const nn = try encodeInt(&tmp, n, 0);
            try out.appendSlice(self.allocator, tmp[0..nn]);
            return;
        }
        const max = huff.maxEncodedLen(str.len);
        const buf = try self.allocator.alloc(u8, max);
        defer self.allocator.free(buf);
        if (huff.encode(buf, str)) |hlen| {
            if (hlen < str.len) {
                var tmp: [10]u8 = undefined;
                const nn = try encodeInt(&tmp, n, hlen);
                tmp[0] |= 0x80;
                try out.appendSlice(self.allocator, tmp[0..nn]);
                try out.appendSlice(self.allocator, buf[0..hlen]);
                return;
            }
        } else |_| {}
        var tmp: [10]u8 = undefined;
        const nn = try encodeInt(&tmp, n, str.len);
        try out.appendSlice(self.allocator, tmp[0..nn]);
        try out.appendSlice(self.allocator, str);
    }

    /// Encodes a header field, inserting into the dynamic table on first
    /// use when one is active (falling back to a literal when the table
    /// is full or every entry is pinned by `evictBarrier`).
    /// Sensitive names (authorization, cookie, set-cookie) are flagged
    /// never-index so intermediaries do not retain them.
    pub fn encodeField(
        self: *Encoder,
        out: *std.ArrayList(u8),
        name: []const u8,
        value: []const u8,
    ) !void {
        // Exact static match first.
        if (self.encodeStaticMatch(out, name, value)) return;

        // Exact dynamic match (newest first).
        if (self.dyn) |*dt| {
            var i: usize = dt.entries.items.len;
            while (i > 0) {
                i -= 1;
                const e = dt.entries.items[i];
                if (std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.value, value)) {
                    try self.encodeIndexedDynamic(out, dt.baseIndex + i, dt.nextIndex);
                    return;
                }
            }
        }

        // Static name-only match: literal with static name reference.
        for (staticTable, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                var ib: [10]u8 = undefined;
                const n = try encodeInt(&ib, 4, i);
                ib[0] |= 0x50 | (neverIndexBit(name) << 5);
                try out.appendSlice(self.allocator, ib[0..n]);
                try self.emitString(out, value, 7);
                return;
            }
        }

        // Dynamic name-only match (newest first).
        if (self.dyn) |*dt| {
            var i: usize = dt.entries.items.len;
            while (i > 0) {
                i -= 1;
                const e = dt.entries.items[i];
                if (std.mem.eql(u8, e.name, name)) {
                    const rel = dt.nextIndex - (dt.baseIndex + i) - 1;
                    var ib: [10]u8 = undefined;
                    const n = try encodeInt(&ib, 4, rel);
                    ib[0] |= 0x40 | (neverIndexBit(name) << 5);
                    try out.appendSlice(self.allocator, ib[0..n]);
                    try self.emitString(out, value, 7);
                    self.sectionUsedDynamic = true;
                    return;
                }
            }
        }

        // No match: insert on first use, else literal without name ref.
        if (self.dyn != null) {
            if (try self.insertDynamic(name, value)) |abs| {
                try self.encodeIndexedDynamic(out, abs, self.insertCount());
                return;
            }
        }
        try self.encodeLiteral(out, name, value);
    }

    fn neverIndexBit(name: []const u8) u8 {
        if (std.mem.eql(u8, name, "authorization") or
            std.mem.eql(u8, name, "cookie") or
            std.mem.eql(u8, name, "set-cookie")) return 1;
        return 0;
    }

    /// Emits a literal without name reference: 001 | N | H | len(3+).
    fn encodeLiteral(self: *Encoder, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
        const max = huff.maxEncodedLen(name.len);
        const buf = try self.allocator.alloc(u8, max);
        defer self.allocator.free(buf);
        const hlen = huff.encode(buf, name) catch null;
        const use_huff = if (hlen) |hl| hl < name.len else false;
        const nlen = if (use_huff) hlen.? else name.len;
        var ib: [10]u8 = undefined;
        const n = try encodeInt(&ib, 3, nlen);
        ib[0] |= 0x20 | (neverIndexBit(name) << 4);
        if (use_huff) ib[0] |= 0x08;
        try out.appendSlice(self.allocator, ib[0..n]);
        if (use_huff) {
            try out.appendSlice(self.allocator, buf[0..hlen.?]);
        } else {
            try out.appendSlice(self.allocator, name);
        }
        try self.emitString(out, value, 7);
    }

    /// Inserts (name, value), emitting the encoder-stream instruction to
    /// `pending`. Returns the absolute index, or null when the table is
    /// full and every entry is pinned (caller falls back to a literal).
    /// Eviction only removes entries below `evictBarrier`.
    fn insertDynamic(self: *Encoder, name: []const u8, value: []const u8) !?u64 {
        const dt = if (self.dyn) |*d| d else return null;
        const total = std.math.add(
            usize,
            std.math.add(usize, name.len, value.len) catch return null,
            ENTRY_OVERHEAD,
        ) catch return null;
        if (total > dt.maxSize) return null;
        while (dt.currentSize + total > dt.maxSize and dt.entries.items.len > 0) {
            const oldest_abs = dt.baseIndex;
            if (oldest_abs >= self.evictBarrier) return null;
            const old = dt.entries.orderedRemove(0);
            dt.currentSize -%= old.totalSize;
            dt.baseIndex +%= 1;
            self.allocator.free(old.name);
            self.allocator.free(old.value);
        }
        if (dt.currentSize + total > dt.maxSize) return null;
        const abs = try dt.insert(self.allocator, name, value);
        // Encoder-stream Insert With Literal Name: 01 | H | len(5+).
        const max = huff.maxEncodedLen(name.len);
        const buf = try self.allocator.alloc(u8, max);
        defer self.allocator.free(buf);
        const hlen = huff.encode(buf, name) catch null;
        const use_huff = if (hlen) |hl| hl < name.len else false;
        const nlen = if (use_huff) hlen.? else name.len;
        var ib: [16]u8 = undefined;
        const n = try encodeInt(&ib, 5, nlen);
        ib[0] |= 0x40;
        if (use_huff) ib[0] |= 0x20;
        try self.pending.appendSlice(self.allocator, ib[0..n]);
        if (use_huff) {
            try self.pending.appendSlice(self.allocator, buf[0..hlen.?]);
        } else {
            try self.pending.appendSlice(self.allocator, name);
        }
        try self.emitString(&self.pending, value, 7);
        self.sectionUsedDynamic = true;
        return abs;
    }

    /// Emits the field-section prefix for a section whose largest
    /// referenced absolute index is below `ric`, with `base` as Base
    /// (we always set Base == RIC: no post-base references emitted).
    pub fn encodePrefix(self: *Encoder, out: *std.ArrayList(u8), ric: u64, base: u64) !void {
        std.debug.assert(base <= ric);
        const max_entries = @max(1, self.peerMaxCapacity / ENTRY_OVERHEAD);
        var enc_ric: u64 = 0;
        if (ric != 0) {
            const full = std.math.mul(u64, max_entries, 2) catch std.math.maxInt(u64);
            enc_ric = (ric % @max(1, full)) + 1;
        }
        var tmp: [16]u8 = undefined;
        const n = try encodeInt(&tmp, 8, enc_ric);
        try out.appendSlice(self.allocator, tmp[0..n]);
        const delta = ric - base;
        const m = try encodeInt(&tmp, 7, delta);
        // S=0 (Base >= ... encoded as RIC + delta); top bit stays clear.
        try out.appendSlice(self.allocator, tmp[0..m]);
    }

    /// Starts a section: clears the dynamic-reference flag. After
    /// encoding the section's fields, `sectionRic` gives the prefix RIC.
    pub fn beginSection(self: *Encoder) void {
        self.sectionUsedDynamic = false;
    }

    /// Required Insert Count for the section currently being encoded:
    /// the insert count when dynamic references were used, else 0.
    pub fn sectionRic(self: *const Encoder) u64 {
        if (!self.sectionUsedDynamic) return 0;
        return self.insertCount();
    }

    /// Attempts to encode using a static table indexed match.
    fn encodeStaticMatch(self: *Encoder, out: *std.ArrayList(u8), name: []const u8, value: []const u8) bool {
        for (staticTable, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                self.encodeIndexedStatic(out, @intCast(i)) catch return false;
                return true;
            }
        }
        return false;
    }

    /// Encodes a static-table indexed field (T=1, 6-bit prefix).
    pub fn encodeIndexedStatic(self: *Encoder, out: *std.ArrayList(u8), index: u64) !void {
        var ib: [10]u8 = undefined;
        const n = try encodeInt(&ib, 6, index);
        ib[0] |= 0xC0; // S=1 + 6-bit prefix tag
        try out.appendSlice(self.allocator, ib[0..n]);
    }

    /// Encodes a dynamic-table indexed field (T=1, 6-bit prefix) as a
    /// relative index against `base` (normally the section Base).
    pub fn encodeIndexedDynamic(self: *Encoder, out: *std.ArrayList(u8), absoluteIndex: u64, base: u64) !void {
        if (absoluteIndex < STATIC_TABLE_SIZE) {
            return try self.encodeIndexedStatic(out, absoluteIndex);
        }
        std.debug.assert(base > absoluteIndex);
        const rel = base - absoluteIndex - 1;
        var ib: [10]u8 = undefined;
        const n = try encodeInt(&ib, 6, rel);
        ib[0] |= 0x80; // 1 | T=0 (dynamic)
        try out.appendSlice(self.allocator, ib[0..n]);
        self.sectionUsedDynamic = true;
    }

    /// Processes decoder-stream bytes from the peer: Section
    /// Acknowledgment (0x80+, 7-bit), Stream Cancellation (0x40, 6-bit),
    /// Insert Count Increment (0x00, 6-bit). Pass `fin=true` when these
    /// are the stream's final bytes: a trailing split instruction is
    /// then corruption (InvalidInstruction), otherwise it is buffered
    /// until more bytes arrive.
    pub fn readDecoderStream(self: *Encoder, data: []const u8, fin: bool) !void {
        try self.decBuf.appendSlice(self.allocator, data);
        var off: usize = self.decOff;
        const buf = self.decBuf.items;
        while (off < buf.len) {
            const start = off;
            _ = self.decodeDecoderOp(buf, &off) catch |e| {
                // Truncated on a live stream means a split instruction:
                // rewind and wait for more bytes. At FIN (or for any
                // other error) it is corruption.
                if (e == error.Truncated and !fin) {
                    off = start;
                    break;
                }
                return Error.InvalidInstruction;
            };
        }
        self.decOff = off;
        self.compactDecBuf();
    }

    fn decodeDecoderOp(self: *Encoder, buf: []const u8, off: *usize) Error!u64 {
        const first = buf[off.*];
        if (first & 0x80 != 0) {
            return try decodeInt(buf, off, 7); // Section Ack: stream id
        } else if (first & 0xC0 == 0x40) {
            return try decodeInt(buf, off, 6); // Stream Cancellation
        }
        const n = try decodeInt(buf, off, 6); // Insert Count Increment
        self.peerKnownInserts = std.math.add(u64, self.peerKnownInserts, n) catch
            return Error.InvalidInstruction;
        return n;
    }

    fn compactDecBuf(self: *Encoder) void {
        if (self.decOff == 0) return;
        if (self.decOff >= self.decBuf.items.len) {
            self.decBuf.clearRetainingCapacity();
            self.decOff = 0;
            return;
        }
        std.mem.copyForwards(u8, self.decBuf.items[0..], self.decBuf.items[self.decOff..]);
        self.decBuf.items.len -= self.decOff;
        self.decOff = 0;
    }
};

// Decoder

pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    allocated: bool = false,
};

pub const Decoder = struct {
    allocator: Allocator,
    dyn: ?DynTable = null,
    /// Capacity we advertised via SETTINGS. Encoder-stream Set Capacity
    /// above this is a stream error.
    advertisedMax: usize = 0,
    /// Local MAX_FIELD_SECTION_SIZE enforcement on section bytes.
    maxFieldSectionSize: u64 = 16384,
    /// Buffered encoder-stream bytes with a consume cursor; a trailing
    /// split instruction waits for more bytes instead of erroring.
    /// Bounded by MAX_ENCODER_BUF.
    encBuf: std.ArrayList(u8) = .empty,
    encOff: usize = 0,
    /// Inserts consumed and reported via Insert Count Increment.
    ackedInserts: u64 = STATIC_TABLE_SIZE,

    /// Cap on buffered encoder-stream bytes: a peer dripping partial
    /// bytes forever is a stream error, not unbounded memory.
    pub const MAX_ENCODER_BUF: usize = 128 * 1024;

    pub fn init(allocator: Allocator) Decoder {
        return .{ .allocator = allocator };
    }

    /// Releases the optional dynamic table and all strings owned by it.
    pub fn deinit(self: *Decoder) void {
        if (self.dyn) |*d| d.deinit(self.allocator);
        self.dyn = null;
        self.encBuf.deinit(self.allocator);
        self.encOff = 0;
    }

    pub fn setMaxTableCapacity(self: *Decoder, capacity: usize) void {
        if (self.dyn) |*d| d.deinit(self.allocator);
        self.dyn = null;
        self.advertisedMax = capacity;
        self.ackedInserts = STATIC_TABLE_SIZE;
        self.encBuf.clearRetainingCapacity();
        self.encOff = 0;
        if (capacity != 0) {
            self.dyn = DynTable.init(self.allocator, capacity);
        }
    }

    pub fn setMaxFieldSectionSize(self: *Decoder, n: u64) void {
        self.maxFieldSectionSize = n;
    }

    /// Absolute index that the next encoder-stream insert will take.
    pub fn insertCount(self: *const Decoder) u64 {
        if (self.dyn) |*d| return d.nextIndex;
        return STATIC_TABLE_SIZE;
    }

    /// Feeds encoder-stream bytes, applying complete instructions to the
    /// dynamic table. Pass `fin=true` when these are the stream's final
    /// bytes: a trailing split instruction is then a stream error
    /// (InvalidInstruction), otherwise it is buffered. Anything else
    /// malformed is InvalidInstruction (connection error
    /// QPACK_ENCODER_STREAM_ERROR).
    pub fn readEncoderStream(self: *Decoder, data: []const u8, fin: bool) !void {
        if (self.encBuf.items.len - self.encOff + data.len > MAX_ENCODER_BUF) {
            return Error.InvalidInstruction;
        }
        try self.encBuf.appendSlice(self.allocator, data);
        var off: usize = self.encOff;
        const buf = self.encBuf.items;
        while (off < buf.len) {
            const start = off;
            self.decodeEncoderOp(buf, &off) catch |e| {
                // Truncated on a live stream means a split instruction:
                // rewind and wait for more bytes. At FIN (or for any
                // other error) it is corruption.
                if (e == error.Truncated and !fin) {
                    off = start;
                    break;
                }
                return Error.InvalidInstruction;
            };
        }
        self.encOff = off;
        self.compactEncBuf();
    }

    fn compactEncBuf(self: *Decoder) void {
        if (self.encOff == 0) return;
        if (self.encOff >= self.encBuf.items.len) {
            self.encBuf.clearRetainingCapacity();
            self.encOff = 0;
            return;
        }
        std.mem.copyForwards(u8, self.encBuf.items[0..], self.encBuf.items[self.encOff..]);
        self.encBuf.items.len -= self.encOff;
        self.encOff = 0;
    }

    fn decodeEncoderOp(self: *Decoder, buf: []const u8, off: *usize) Error!void {
        const first = buf[off.*];
        if (first & 0x80 != 0) {
            // Insert With Name Reference: 1 | T | idx(6+).
            // T polarity is inverted vs field sections: T=1 static.
            const is_static = first & 0x40 != 0;
            const idx = try decodeInt(buf, off, 6);
            var name: []const u8 = undefined;
            if (is_static) {
                if (idx >= STATIC_TABLE_SIZE) return Error.InvalidInstruction;
                name = staticTable[@intCast(idx)].name;
            } else {
                const abs = try self.encoderRelToAbs(idx);
                const res = self.lookupDynamic(abs) catch return Error.InvalidInstruction;
                name = res.name;
            }
            const value = try readString(self.allocator, buf, off, MAX_VALUE_LEN);
            errdefer self.allocator.free(value);
            try self.insertDecoded(name, value);
            return;
        }
        if (first & 0xC0 == 0x40) {
            // Insert With Literal Name: 01 | H | len(5+). Both 0x40
            // (raw) and 0x60 (Huffman) forms insert.
            const huff_name = first & 0x20 != 0;
            const nlen = try decodeInt(buf, off, 5);
            if (nlen > MAX_NAME_LEN) return Error.InvalidInstruction;
            const nbytes = try take(buf, off, nlen);
            const name = try decodeStringBytes(self.allocator, nbytes, huff_name, MAX_NAME_LEN);
            errdefer self.allocator.free(name);
            const value = try readString(self.allocator, buf, off, MAX_VALUE_LEN);
            errdefer self.allocator.free(value);
            try self.insertDecoded(name, value);
            self.allocator.free(name);
            self.allocator.free(value);
            return;
        }
        if (first & 0xE0 == 0x20) {
            // Set Dynamic Table Capacity: 001 | cap(5+).
            const cap = try decodeInt(buf, off, 5);
            const cap_usize = std.math.cast(usize, cap) orelse return Error.InvalidInstruction;
            if (cap_usize > self.advertisedMax) return Error.InvalidInstruction;
            if (self.dyn) |*d| {
                d.setMaxSize(self.allocator, cap_usize);
            } else if (cap_usize != 0) {
                return Error.InvalidInstruction;
            }
            return;
        }
        // Duplicate: 000 | rel(5+), relative to our insert count.
        const rel = try decodeInt(buf, off, 5);
        const abs = try self.encoderRelToAbs(rel);
        const res = self.lookupDynamic(abs) catch return Error.InvalidInstruction;
        const name = try self.allocator.dupe(u8, res.name);
        errdefer self.allocator.free(name);
        const value = try self.allocator.dupe(u8, res.value);
        errdefer self.allocator.free(value);
        try self.insertDecoded(name, value);
        self.allocator.free(name);
        self.allocator.free(value);
    }

    fn encoderRelToAbs(self: *const Decoder, rel: u64) Error!u64 {
        const have = self.insertCount() - STATIC_TABLE_SIZE;
        if (rel >= have) return Error.InvalidInstruction;
        return STATIC_TABLE_SIZE + (have - rel - 1);
    }

    fn insertDecoded(self: *Decoder, name: []const u8, value: []const u8) Error!void {
        const dt = if (self.dyn) |*d| d else return Error.InvalidInstruction;
        _ = dt.insert(self.allocator, name, value) catch |e| switch (e) {
            error.TableCapacityExceeded => return Error.InvalidInstruction,
            error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.InvalidInstruction,
        };
    }

    /// A resolved table entry (borrowed; owned by the static table or
    /// our dynamic table, never freed by the caller).
    pub const DynRef = struct { name: []const u8, value: []const u8 };

    fn lookupDynamic(self: *const Decoder, abs: u64) Error!DynRef {
        // Dynamic references name the dynamic table only; an absolute
        // index in the static range here is a malformed reference, not
        // a static lookup (fail closed).
        if (abs < STATIC_TABLE_SIZE) return Error.InvalidIndex;
        const dt = if (self.dyn) |*d| d else return Error.InvalidIndex;
        const r = dt.resolve(abs) orelse return Error.InvalidIndex;
        return .{ .name = r.name, .value = r.value };
    }

    fn lookup(self: *const Decoder, abs: u64) Error!DynRef {
        if (abs < STATIC_TABLE_SIZE) {
            const e = staticTable[@intCast(abs)];
            return .{ .name = e.name, .value = e.value };
        }
        return self.lookupDynamic(abs);
    }

    /// Base-relative reference (field sections): abs = Base - rel - 1,
    /// additionally requiring abs < ric (the section may not name
    /// entries inserted after its Required Insert Count).
    fn baseRelative(_: *const Decoder, base: u64, ric: u64, rel: u64) Error!u64 {
        if (rel >= base) return Error.InvalidIndex;
        const abs = base - rel - 1;
        if (abs >= ric) return Error.InvalidInstruction;
        return abs;
    }

    fn reconstructRic(self: *const Decoder, enc_ric: u64) Error!u64 {
        if (enc_ric == 0) return 0;
        if (self.advertisedMax == 0) return Error.InvalidInstruction;
        const max_ents = @max(1, self.advertisedMax / ENTRY_OVERHEAD);
        const full = std.math.mul(u64, max_ents, 2) catch return Error.InvalidInstruction;
        if (enc_ric > full) return Error.InvalidInstruction;
        const max = std.math.add(u64, self.insertCount(), max_ents) catch return Error.InvalidInstruction;
        const max_wrapped = max / full * full;
        var ric = std.math.add(u64, max_wrapped, enc_ric - 1) catch return Error.InvalidInstruction;
        if (ric > max) {
            if (ric <= full) return Error.InvalidInstruction;
            ric -= full;
        }
        if (ric == 0) return Error.InvalidInstruction;
        return ric;
    }

    /// Decodes an encoded field section into field lines (no prefix).
    /// Base and RIC both equal our insert count: only references
    /// resolvable right now decode; anything naming a future insert is
    /// an index error. Prefer `decodeSectionCounted` on the wire path.
    pub fn decodeSection(self: *Decoder, data: []const u8) Error![]FieldLine {
        const ic = self.insertCount();
        return self.decodeSectionInner(data, ic, ic);
    }

    /// Decodes a complete QPACK encoded field section, including its
    /// prefix, emitting a Section Acknowledgment for `stream_id` into
    /// `ack_out` (when non-null) if dynamic entries were referenced.
    /// Returns `error.Blocked` when Required Insert Count runs ahead of
    /// our encoder-stream state: keep the section bytes and retry after
    /// feeding more encoder data. Never buffers internally.
    pub fn decodeSectionCounted(
        self: *Decoder,
        data: []const u8,
        streamId: u64,
        ackOut: ?*std.ArrayList(u8),
    ) Error![]FieldLine {
        if (data.len > std.math.add(u64, self.maxFieldSectionSize, 16) catch std.math.maxInt(u64)) {
            return Error.InvalidInstruction;
        }
        var offset: usize = 0;
        const enc_ric = try decodeInt(data, &offset, 8);
        const ric = try self.reconstructRic(enc_ric);
        if (offset >= data.len) return Error.InvalidInstruction;
        const sign = data[offset] & 0x80 != 0;
        const delta = try decodeInt(data, &offset, 7);
        var base: u64 = undefined;
        if (sign) {
            if (ric <= delta) return Error.InvalidInstruction;
            base = ric - delta - 1;
        } else {
            base = std.math.add(u64, ric, delta) catch return Error.InvalidInstruction;
        }
        if (ric != 0 and self.dyn == null) return Error.InvalidInstruction;
        if (ric > self.insertCount()) return Error.Blocked;
        const fields = try self.decodeSectionInner(data[offset..], base, ric);
        errdefer self.freeFields(fields);
        if (ric != 0) {
            if (ackOut) |out| {
                var ib: [16]u8 = undefined;
                const n = try encodeInt(&ib, 7, streamId);
                ib[0] |= 0x80;
                try out.appendSlice(self.allocator, ib[0..n]);
            }
        }
        return fields;
    }

    /// Legacy entry point: prefix-less sections decode against the
    /// current table. Kept for tests and static-only callers.
    pub fn decodeSectionWithPrefix(self: *Decoder, data: []const u8) Error![]FieldLine {
        return self.decodeSectionCounted(data, 0, null);
    }

    fn decodeSectionInner(self: *Decoder, data: []const u8, base: u64, ric: u64) Error![]FieldLine {
        var results = std.ArrayList(FieldLine).empty;
        errdefer results.deinit(self.allocator);
        var offset: usize = 0;

        while (offset < data.len) {
            const first = data[offset];

            if (first & 0x80 != 0) {
                // Indexed: 1 | T | idx(6+). T=1 names the static table
                // absolutely; T=0 is a dynamic Base-relative index.
                const dyn_ref = first & 0x40 == 0;
                const rel = try decodeInt(data, &offset, 6);
                const abs = if (dyn_ref) try self.baseRelative(base, ric, rel) else rel;
                const res = if (dyn_ref) try self.lookupDynamic(abs) else try self.lookup(abs);
                try results.append(self.allocator, .{ .name = res.name, .value = res.value, .allocated = false });
            } else if (first & 0xC0 == 0x40) {
                // Literal with name reference: 01 | N | T | idx(4+).
                const dyn_ref = first & 0x10 == 0;
                const rel = try decodeInt(data, &offset, 4);
                const abs = if (dyn_ref) try self.baseRelative(base, ric, rel) else rel;
                const res = if (dyn_ref) try self.lookupDynamic(abs) else try self.lookup(abs);
                const name = try self.allocator.dupe(u8, res.name);
                const value = readString(self.allocator, data, &offset, MAX_VALUE_LEN) catch |e| {
                    self.allocator.free(name);
                    return e;
                };
                appendOwnedField(&results, self.allocator, name, value) catch |e| {
                    self.allocator.free(name);
                    self.allocator.free(value);
                    return e;
                };
            } else if (first & 0xF0 == 0x20 or first & 0xF0 == 0x30) {
                // Literal without name reference: 001 | N | H | len(3+).
                // (A dynamic-table size update can only appear on the
                // encoder stream; here these bytes are always a literal.)
                const huff_name = first & 0x08 != 0;
                const nlen = try decodeInt(data, &offset, 3);
                if (nlen > MAX_NAME_LEN) return Error.InvalidInstruction;
                const nbytes = try take(data, &offset, nlen);
                const name = try decodeStringBytes(self.allocator, nbytes, huff_name, MAX_NAME_LEN);
                const value = readString(self.allocator, data, &offset, MAX_VALUE_LEN) catch |e| {
                    self.allocator.free(name);
                    return e;
                };
                appendOwnedField(&results, self.allocator, name, value) catch |e| {
                    self.allocator.free(name);
                    self.allocator.free(value);
                    return e;
                };
            } else if (first & 0xF0 == 0x10) {
                // Indexed with post-base index: 0001 | rel(4+).
                const rel = try decodeInt(data, &offset, 4);
                const abs = std.math.add(u64, base, rel) catch return Error.InvalidInstruction;
                if (abs >= ric) return Error.InvalidInstruction;
                const res = try self.lookupDynamic(abs);
                try results.append(self.allocator, .{ .name = res.name, .value = res.value, .allocated = false });
            } else {
                // Literal with post-base name reference: 000 | N | rel(3+).
                const rel = try decodeInt(data, &offset, 3);
                const abs = std.math.add(u64, base, rel) catch return Error.InvalidInstruction;
                if (abs >= ric) return Error.InvalidInstruction;
                const res = try self.lookupDynamic(abs);
                const name = try self.allocator.dupe(u8, res.name);
                const value = readString(self.allocator, data, &offset, MAX_VALUE_LEN) catch |e| {
                    self.allocator.free(name);
                    return e;
                };
                appendOwnedField(&results, self.allocator, name, value) catch |e| {
                    self.allocator.free(name);
                    self.allocator.free(value);
                    return e;
                };
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Emits an Insert Count Increment for inserts consumed since the
    /// last call (decoder-stream traffic for the peer's encoder).
    /// No-op when nothing new arrived.
    pub fn insertCountIncrement(self: *Decoder, out: *std.ArrayList(u8)) !void {
        const n = self.insertCount() - self.ackedInserts;
        if (n == 0) return;
        var ib: [16]u8 = undefined;
        const m = try encodeInt(&ib, 6, n);
        try out.appendSlice(self.allocator, ib[0..m]);
        self.ackedInserts = self.insertCount();
    }

    /// Emits a Stream Cancellation for an abandoned section (decoder
    /// stream), e.g. after RESET_STREAM on a blocked request stream.
    pub fn cancelSection(self: *Decoder, out: *std.ArrayList(u8), streamId: u64) !void {
        var ib: [16]u8 = undefined;
        const m = try encodeInt(&ib, 6, streamId);
        ib[0] |= 0x40;
        try out.appendSlice(self.allocator, ib[0..m]);
    }

    pub fn freeFields(self: *Decoder, fields: []FieldLine) void {
        for (fields) |f| {
            if (f.allocated) {
                self.allocator.free(f.name);
                self.allocator.free(f.value);
            }
        }
        self.allocator.free(fields);
    }
};

fn appendOwnedField(
    results: *std.ArrayList(FieldLine),
    allocator: Allocator,
    name: []u8,
    value: []u8,
) !void {
    try results.append(allocator, .{ .name = name, .value = value, .allocated = true });
}

// Tests

test "qpack integer roundtrip" {
    var buf: [16]u8 = undefined;
    const vals = [_]u64{ 0, 62, 63, 127, 128, 255 };
    for (vals) |v| {
        const n = try encodeInt(&buf, 6, v);
        var off: usize = 0;
        const d = try decodeInt(buf[0..n], &off, 6);
        try std.testing.expectEqual(v, d);
    }
}

test "static table known entries" {
    try std.testing.expectEqualStrings(":method", staticTable[17].name);
    try std.testing.expectEqualStrings("GET", staticTable[17].value);
    try std.testing.expectEqualStrings(":status", staticTable[25].name);
    try std.testing.expectEqualStrings("200", staticTable[25].value);
}

test "encoder indexed static then decoder reads it" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);

    try enc.encodeIndexedStatic(&block, 17); // :method GET
    try enc.encodeIndexedStatic(&block, 25); // :status 200

    var dec = Decoder.init(a);
    const fields = try dec.decodeSection(block.items);
    defer dec.freeFields(fields);

    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("GET", fields[0].value);
}

test "qpack static name reference decodes without consuming a name" {
    const a = std.testing.allocator;
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);

    var len_buf: [10]u8 = undefined;
    const indexBytes = try encodeInt(&len_buf, 4, 17);
    len_buf[0] |= 0x50; // 01, N=0, S=1
    try block.appendSlice(a, len_buf[0..indexBytes]);
    const n = try encodeInt(&len_buf, 7, 4);
    try block.appendSlice(a, len_buf[0..n]);
    try block.appendSlice(a, "POST");

    var dec = Decoder.init(a);
    const fields = try dec.decodeSection(block.items);
    defer dec.freeFields(fields);
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("POST", fields[0].value);
}

test "qpack complete field section consumes zero dynamic prefix" {
    const a = std.testing.allocator;
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);
    try block.appendSlice(a, "\x00\x00"); // Required Insert Count=0, Delta Base=0

    var enc = Encoder.init(a);
    try enc.encodeIndexedStatic(&block, 17);

    var dec = Decoder.init(a);
    const fields = try dec.decodeSectionWithPrefix(block.items);
    defer dec.freeFields(fields);
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
}

test "qpack dynamic name references fail closed" {
    const a = std.testing.allocator;
    var dec = Decoder.init(a);
    // 0x41: literal with dynamic-table name reference, rel index 1.
    // No dynamic table exists, so the reference cannot resolve.
    try std.testing.expectError(Error.InvalidIndex, dec.decodeSection("\x41"));
}

test "qpack dynamic indexes remain monotonic across eviction" {
    const a = std.testing.allocator;
    var table = DynTable.init(a, 40);
    defer table.deinit(a);

    const first = try table.insert(a, "a", "1");
    const second = try table.insert(a, "b", "2");
    try std.testing.expectEqual(@as(u64, STATIC_TABLE_SIZE), first);
    try std.testing.expectEqual(first + 1, second);
    try std.testing.expect(table.resolve(first) == null);
    const current = table.resolve(second) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("b", current.name);
}

test "qpack rejects entries larger than dynamic capacity" {
    const a = std.testing.allocator;
    var table = DynTable.init(a, 40);
    defer table.deinit(a);
    try std.testing.expectError(Error.TableCapacityExceeded, table.insert(a, "oversized-name", "oversized-value"));
    try std.testing.expectEqual(@as(usize, 0), table.entries.items.len);
    try std.testing.expectEqual(@as(usize, 0), table.currentSize);
}

test "qpack huffman literal decodes through shared codec" {
    const a = std.testing.allocator;
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);
    // Literal without name reference: 001 | N | H | len(3+).
    var encoded: [64]u8 = undefined;
    const nameLen = try huff.encode(encoded[0..], ":path");
    var len_buf: [10]u8 = undefined;
    var n = try encodeInt(&len_buf, 3, nameLen);
    len_buf[0] |= 0x20 | 0x08; // literal, raw name, Huffman-encoded
    try block.appendSlice(a, len_buf[0..n]);
    try block.appendSlice(a, encoded[0..nameLen]);

    const valueLen = try huff.encode(encoded[0..], "/");
    n = try encodeInt(&len_buf, 7, valueLen);
    len_buf[0] |= 0x80;
    try block.appendSlice(a, len_buf[0..n]);
    try block.appendSlice(a, encoded[0..valueLen]);

    var dec = Decoder.init(a);
    const fields = try dec.decodeSection(block.items);
    defer dec.freeFields(fields);
    try std.testing.expectEqualStrings(":path", fields[0].name);
    try std.testing.expectEqualStrings("/", fields[0].value);
}

test "qpack dynamic roundtrip through encoder and decoder streams" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);

    // Encode one field: unseen name+value inserts into the table.
    var field = std.ArrayList(u8).empty;
    defer field.deinit(a);
    enc.beginSection();
    try enc.encodeField(&field, "x-custom", "v1");
    const ric = enc.sectionRic();
    try std.testing.expect(ric > STATIC_TABLE_SIZE);

    var section = std.ArrayList(u8).empty;
    defer section.deinit(a);
    try enc.encodePrefix(&section, ric, ric);
    try section.appendSlice(a, field.items);

    // Flush encoder-stream instructions (Set Capacity + Insert).
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);
    try std.testing.expect(enc_bytes.len > 0);

    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    try dec.readEncoderStream(enc_bytes, true);

    var ack = std.ArrayList(u8).empty;
    defer ack.deinit(a);
    const fields = try dec.decodeSectionCounted(section.items, 0, &ack);
    defer dec.freeFields(fields);
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("x-custom", fields[0].name);
    try std.testing.expectEqualStrings("v1", fields[0].value);
    // Dynamic section decoded: a Section Acknowledgment was staged
    // (single byte for small stream IDs: 0x80 | id(7+)).
    try std.testing.expectEqual(@as(usize, 1), ack.items.len);
    try std.testing.expectEqual(@as(u8, 0x80), ack.items[0]);

    // The consumed inserts are reportable via Insert Count Increment.
    var inc = std.ArrayList(u8).empty;
    defer inc.deinit(a);
    try dec.insertCountIncrement(&inc);
    try std.testing.expect(inc.items.len > 0);
}

test "qpack blocked section retries after encoder data arrives" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);
    enc.beginSection();
    var field = std.ArrayList(u8).empty;
    defer field.deinit(a);
    try enc.encodeField(&field, "x-blocked", "yes");
    const ric = enc.sectionRic();
    var section = std.ArrayList(u8).empty;
    defer section.deinit(a);
    try enc.encodePrefix(&section, ric, ric);
    try section.appendSlice(a, field.items);
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);

    // Fresh decoder knows nothing: same section must Block, not fail.
    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    try std.testing.expectError(Error.Blocked, dec.decodeSectionCounted(section.items, 4, null));

    // Feed the encoder stream, then the identical bytes decode.
    try dec.readEncoderStream(enc_bytes, true);
    const fields = try dec.decodeSectionCounted(section.items, 4, null);
    defer dec.freeFields(fields);
    try std.testing.expectEqualStrings("x-blocked", fields[0].name);
    try std.testing.expectEqualStrings("yes", fields[0].value);
}

test "qpack post-base references resolve" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);
    // Two inserts: abs 99 (x-a) and 100 (x-b); insertCount 101.
    _ = try enc.insertDynamic("x-a", "1");
    _ = try enc.insertDynamic("x-b", "2");
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);

    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    try dec.readEncoderStream(enc_bytes, true);

    // Section with Base=100 (< RIC=101): post-base rel 0 -> abs 100.
    // RIC 101 with maxEntries 128 encodes as 101 % 256 + 1 = 102.
    var section = std.ArrayList(u8).empty;
    defer section.deinit(a);
    try section.appendSlice(a, &.{ 102, 0x80 }); // RIC=101, S=1, delta=0
    try section.append(a, 0x10); // indexed post-base, rel 0
    const fields = try dec.decodeSectionCounted(section.items, 0, null);
    defer dec.freeFields(fields);
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("x-b", fields[0].name);

    // Post-base name reference: 000 | N | rel(3+), then a value.
    var section2 = std.ArrayList(u8).empty;
    defer section2.deinit(a);
    try section2.appendSlice(a, &.{ 102, 0x80, 0x00 });
    var tmp: [10]u8 = undefined;
    const n = try encodeInt(&tmp, 7, 3);
    try section2.appendSlice(a, tmp[0..n]);
    try section2.appendSlice(a, "two");
    const fields2 = try dec.decodeSectionCounted(section2.items, 0, null);
    defer dec.freeFields(fields2);
    try std.testing.expectEqualStrings("x-b", fields2[0].name);
    try std.testing.expectEqualStrings("two", fields2[0].value);
}

test "qpack encoder stream split delivery buffers" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);
    _ = try enc.insertDynamic("x-split", "s");
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);
    try std.testing.expect(enc_bytes.len > 2);

    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    // Feed one byte at a time: partial instructions buffer, never fail.
    for (enc_bytes) |b| {
        try dec.readEncoderStream(&.{b}, false);
    }
    try std.testing.expectEqual(@as(u64, STATIC_TABLE_SIZE + 1), dec.insertCount());
    const res = try dec.lookupDynamic(STATIC_TABLE_SIZE);
    try std.testing.expectEqualStrings("x-split", res.name);
    // The same truncation at FIN is corruption, not a split.
    try std.testing.expectError(Error.InvalidInstruction, dec.readEncoderStream(&.{0x40}, true));
}

test "qpack set capacity above advertised max is rejected" {
    const a = std.testing.allocator;
    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(64);
    var ib: [16]u8 = undefined;
    const n = try encodeInt(&ib, 5, 4096);
    ib[0] |= 0x20;
    try std.testing.expectError(Error.InvalidInstruction, dec.readEncoderStream(ib[0..n], true));
}

test "qpack duplicate instruction copies entries" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);
    const abs0 = (try enc.insertDynamic("x-dup", "d")).?;
    try std.testing.expectEqual(STATIC_TABLE_SIZE, abs0);
    // Duplicate relative 0 -> copies abs 99 to abs 100.
    var dup: [16]u8 = undefined;
    const n = try encodeInt(&dup, 5, 0);
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);
    var combined = std.ArrayList(u8).empty;
    defer combined.deinit(a);
    try combined.appendSlice(a, enc_bytes);
    try combined.appendSlice(a, dup[0..n]);

    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    try dec.readEncoderStream(combined.items, true);
    try std.testing.expectEqual(@as(u64, STATIC_TABLE_SIZE + 2), dec.insertCount());
    const res = try dec.lookupDynamic(STATIC_TABLE_SIZE + 1);
    try std.testing.expectEqualStrings("x-dup", res.name);
    try std.testing.expectEqualStrings("d", res.value);
}

test "qpack decoder stream instructions parse strictly" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    // SectionAck(4) + StreamCancel(4) + Increment(2): all complete.
    try enc.readDecoderStream(&.{ 0x84, 0x44, 0x02 }, true);
    try std.testing.expectEqual(@as(u64, STATIC_TABLE_SIZE + 2), enc.peerKnownInserts);
    // Split delivery across calls buffers instead of failing.
    try enc.readDecoderStream(&.{0x80}, false);
    try enc.readDecoderStream(&.{0x09}, false);
    // Overflowing increment is corruption, not a split: fatal mid-buffer.
    var bad: [16]u8 = undefined;
    const n = try encodeInt(&bad, 6, std.math.maxInt(u64));
    try std.testing.expectError(Error.InvalidInstruction, enc.readDecoderStream(bad[0..n], true));
}

test "qpack ack and cancel instruction bytes" {
    const a = std.testing.allocator;
    var dec = Decoder.init(a);
    defer dec.deinit();
    var ack = std.ArrayList(u8).empty;
    defer ack.deinit(a);
    try dec.insertCountIncrement(&ack); // nothing new: silent
    try std.testing.expectEqual(@as(usize, 0), ack.items.len);

    var cancel = std.ArrayList(u8).empty;
    defer cancel.deinit(a);
    try dec.cancelSection(&cancel, 4);
    try std.testing.expectEqual(@as(usize, 1), cancel.items.len);
    try std.testing.expectEqual(@as(u8, 0x44), cancel.items[0]);
}

test "qpack field section size limit enforced" {
    const a = std.testing.allocator;
    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxFieldSectionSize(8);
    var big = std.ArrayList(u8).empty;
    defer big.deinit(a);
    try big.appendSlice(a, &.{ 0x00, 0x00 });
    try big.appendNTimes(a, 0x41, 32);
    try std.testing.expectError(Error.InvalidInstruction, dec.decodeSectionCounted(big.items, 0, null));
}

test "qpack encoder falls back to literal when entries are pinned" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    // Capacity fits exactly one 34-byte entry ("a"/"1").
    enc.setMaxTableCapacity(34);
    enc.beginSection();
    var first = std.ArrayList(u8).empty;
    defer first.deinit(a);
    try enc.encodeField(&first, "a", "1");
    // First insert fits without eviction.
    try std.testing.expect(enc.sectionRic() > STATIC_TABLE_SIZE);

    // Second distinct field needs eviction, but abs 99 is pinned by the
    // default barrier: literal fallback, still decodable statically.
    enc.beginSection();
    var second = std.ArrayList(u8).empty;
    defer second.deinit(a);
    try enc.encodeField(&second, "b", "2");
    var dec = Decoder.init(a);
    defer dec.deinit();
    const fields = try dec.decodeSection(second.items);
    defer dec.freeFields(fields);
    try std.testing.expectEqualStrings("b", fields[0].name);

    // Advancing the barrier past abs 99 permits eviction on next insert.
    enc.setEvictBarrier(STATIC_TABLE_SIZE + 1);
    const abs = try enc.insertDynamic("c", "3");
    try std.testing.expect(abs != null);
}

test "qpack encoder prefix encodes nonzero insert counts" {
    const a = std.testing.allocator;
    var enc = Encoder.init(a);
    defer enc.deinit();
    enc.setMaxTableCapacity(4096);
    _ = try enc.insertDynamic("x-p", "v");
    const ric = enc.insertCount();
    var prefix = std.ArrayList(u8).empty;
    defer prefix.deinit(a);
    try enc.encodePrefix(&prefix, ric, ric);
    try std.testing.expectEqual(@as(usize, 2), prefix.items.len);
    // RIC 100 with 128 max entries: 100 % 256 + 1 = 101.
    try std.testing.expectEqual(@as(u8, 101), prefix.items[0]);
    try std.testing.expectEqual(@as(u8, 0x00), prefix.items[1]);

    var dec = Decoder.init(a);
    defer dec.deinit();
    dec.setMaxTableCapacity(4096);
    // Prefix alone (no section body) decodes to zero fields after
    // feeding the encoder bytes the insert produced.
    const enc_bytes = try enc.takeEncoderBytes();
    defer a.free(enc_bytes);
    try dec.readEncoderStream(enc_bytes, true);
    var body = std.ArrayList(u8).empty;
    defer body.deinit(a);
    try body.appendSlice(a, prefix.items);
    try enc.encodeIndexedStatic(&body, 17);
    const fields = try dec.decodeSectionCounted(body.items, 0, null);
    defer dec.freeFields(fields);
    try std.testing.expectEqualStrings(":method", fields[0].name);
}
