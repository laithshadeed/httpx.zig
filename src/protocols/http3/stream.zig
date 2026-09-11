//! HTTP/3 stream layer (RFC 9114 Sections 6-8).
//!
//! Per-stream receive reassembly, unidirectional stream dispatch, and the
//! request/response HTTP state machines: frame ordering, trailers,
//! pseudo-header validation, content-length accounting, and QPACK section
//! handling (blocked sections park and retry after encoder data arrives).
//!
//! Parsing lives here; policy state (settings, GOAWAY monotonicity,
//! duplicate critical streams, stream maps) lives in the connection
//! layer, which feeds QUIC bytes in and drains `(Section Ack)` bytes out.
//! Protocol violations surface as `onError` carrying the H3 wire error
//! code; the connection layer maps them to QUIC resets and closes.
//!
//! References:
//!   - RFC 9114 Section 6 — HTTP/3 streams (control, QPACK, push)
//!   - RFC 9114 Section 7 — HTTP/3 frames and stream-type legality
//!   - RFC 9114 Section 8 — HTTP/3 error codes
//!   - RFC 9114 Section 4 — HTTP message exchanges and trailers
//!   - RFC 9204 Section 4.5 — QPACK field sections

const std = @import("std");
const Allocator = std.mem.Allocator;
const frame_mod = @import("frame.zig");
const qpack_mod = @import("qpack.zig");
const quic_varint = @import("../quic/varint.zig");

pub const H3Error = frame_mod.H3Error;
pub const FieldLine = qpack_mod.FieldLine;

pub const Role = enum { client, server };

/// Which half of the exchange this stream receives.
pub const StreamMode = enum {
    /// Server side: the peer sends a request.
    request_recv,
    /// Client side: the peer sends a response.
    response_recv,
    /// Unidirectional stream; the type varint is parsed from the stream.
    uni,
};

/// HTTP message phase on a request/response stream.
pub const HttpState = enum {
    need_headers,
    headers,
    data,
    trailers,
    done,
};

/// Unidirectional stream kind once the type varint is parsed.
pub const UniKind = enum {
    undecided,
    control,
    qpack_encoder,
    qpack_decoder,
    push,
    unknown,
};

pub const Callbacks = struct {
    ctx: ?*anyopaque = null,
    onHeaders: ?*const fn (ctx: ?*anyopaque, sid: u64, fields: []const FieldLine, interim: bool) void = null,
    onData: ?*const fn (ctx: ?*anyopaque, sid: u64, data: []const u8) void = null,
    onTrailers: ?*const fn (ctx: ?*anyopaque, sid: u64, fields: []const FieldLine) void = null,
    onMessageEnd: ?*const fn (ctx: ?*anyopaque, sid: u64) void = null,
    /// A complete control-stream frame ready for connection state.
    onControlFrame: ?*const fn (ctx: ?*anyopaque, sid: u64, frameType: u64, payload: []const u8) void = null,
    /// Fired once the unidirectional type varint parses, before any
    /// other processing, so the connection layer can reject duplicate
    /// critical streams via `failExtern`.
    onUniType: ?*const fn (ctx: ?*anyopaque, sid: u64, streamType: u64) void = null,
    onReset: ?*const fn (ctx: ?*anyopaque, sid: u64, code: u64) void = null,
    onError: ?*const fn (ctx: ?*anyopaque, sid: u64, code: H3Error) void = null,
};

pub const Error = error{
    StreamClosed,
    OutOfMemory,
};

/// Validates that the peer may open `sid`: HTTP/3 servers never initiate
/// bidirectional streams, and unidirectional streams must be
/// peer-initiated. Returns the connection error on misuse, null when ok.
pub fn checkPeerStreamId(our_role: Role, sid: u64) ?H3Error {
    const bidi = (sid & 0x02) == 0;
    const client_init = (sid & 0x01) == 0;
    if (bidi) {
        // Only clients initiate request streams.
        if (our_role == .client) return .h3_stream_creation_error;
        if (!client_init) return .h3_stream_creation_error;
        return null;
    }
    // Unidirectional: the peer must own the stream.
    if (our_role == .client and client_init) return .h3_stream_creation_error;
    if (our_role == .server and !client_init) return .h3_stream_creation_error;
    return null;
}

/// Parses a unidirectional stream type varint. Returns
/// `error.Truncated` when more bytes are needed.
pub fn parseUniType(data: []const u8) frame_mod.Error!struct { streamType: u64, len: usize } {
    var off: usize = 0;
    const t = quic_varint.decode(data, &off) catch |e| switch (e) {
        error.Truncated => return frame_mod.Error.Truncated,
        else => return frame_mod.Error.InvalidFrame,
    };
    return .{ .streamType = t, .len = off };
}

/// Finds the first field with `name`, or null.
pub fn findField(fields: []const FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return f.value;
    }
    return null;
}

pub const H3Stream = struct {
    allocator: Allocator,
    id: u64,
    mode: StreamMode,
    role: Role,
    cbs: Callbacks,
    qdec: *qpack_mod.Decoder,
    qenc: *qpack_mod.Encoder,

    buf: std.ArrayList(u8) = .empty,
    /// Parse cursor: bytes before it are delivered or skipped.
    off: usize = 0,
    /// QUIC stream FIN observed.
    fin: bool = false,
    failed: bool = false,
    done: bool = false,

    uni_kind: UniKind = .undecided,
    http_state: HttpState = .need_headers,
    /// A QPACK section parked on `error.Blocked`; retried when encoder
    /// data arrives or more stream bytes feed in.
    blocked: bool = false,
    /// SETTINGS seen on this control stream (SETTINGS-first rule).
    control_saw_settings: bool = false,
    /// Extended-CONNECT allowed by peer settings (connection sets this).
    connect_allowed: bool = false,
    /// Decoder-stream acknowledgments staged by dynamic decodes; the
    /// connection layer drains these onto the decoder stream.
    decoderAck: std.ArrayList(u8) = .empty,
    /// Bytes of unknown unidirectional type skipped (visibility for
    /// future excessive-load accounting).
    unknown_skipped: u64 = 0,

    // HTTP message validation state.
    content_length: ?u64 = null,
    body_received: u64 = 0,

    pub fn init(
        allocator: Allocator,
        id: u64,
        mode: StreamMode,
        role: Role,
        cbs: Callbacks,
        qdec: *qpack_mod.Decoder,
        qenc: *qpack_mod.Encoder,
    ) H3Stream {
        return .{
            .allocator = allocator,
            .id = id,
            .mode = mode,
            .role = role,
            .cbs = cbs,
            .qdec = qdec,
            .qenc = qenc,
        };
    }

    pub fn deinit(self: *H3Stream) void {
        self.buf.deinit(self.allocator);
        self.decoderAck.deinit(self.allocator);
    }

    /// Takes staged decoder-stream acknowledgment bytes; caller sends
    /// them on the decoder stream, then frees the slice.
    pub fn takeDecoderAck(self: *H3Stream) ![]u8 {
        return try self.decoderAck.toOwnedSlice(self.allocator);
    }

    /// Forces the stream into the failed state from the outside (e.g.
    /// duplicate critical stream detected by the connection layer).
    pub fn failExtern(self: *H3Stream, code: H3Error) void {
        self.fail(code);
    }

    /// Signals a QUIC-level reset received for this stream.
    pub fn onQuicReset(self: *H3Stream, code: u64) void {
        if (self.failed or self.done) return;
        self.failed = true;
        if (self.cbs.onReset) |cb| cb(self.cbs.ctx, self.id, code);
    }

    /// Feeds received stream bytes (`fin` = QUIC FIN observed).
    pub fn feed(self: *H3Stream, data: []const u8, fin: bool) void {
        if (self.failed or self.done) return;
        self.buf.appendSlice(self.allocator, data) catch {
            self.fail(.h3_internal_error);
            return;
        };
        if (fin) self.fin = true;
        self.parse();
    }

    /// Retries a section parked on `error.Blocked` after encoder-stream
    /// bytes arrived. No-op unless blocked.
    pub fn retryBlocked(self: *H3Stream) void {
        if (!self.blocked or self.failed or self.done) return;
        self.blocked = false;
        self.parse();
    }

    fn fail(self: *H3Stream, code: H3Error) void {
        if (self.failed or self.done) return;
        self.failed = true;
        if (self.cbs.onError) |cb| cb(self.cbs.ctx, self.id, code);
    }

    fn finishMessage(self: *H3Stream) void {
        self.done = true;
        if (self.cbs.onMessageEnd) |cb| cb(self.cbs.ctx, self.id);
    }

    fn parse(self: *H3Stream) void {
        if (self.failed or self.done) return;
        if (self.mode == .uni) {
            self.parseUni();
            return;
        }
        self.parseBidi();
    }

    fn parseUni(self: *H3Stream) void {
        if (self.uni_kind == .undecided) {
            const avail = self.buf.items[self.off..];
            const t = parseUniType(avail) catch |e| switch (e) {
                error.Truncated => {
                    if (self.fin) self.fail(.h3_frame_error);
                    return;
                },
                else => {
                    self.fail(.h3_frame_error);
                    return;
                },
            };
            self.off += t.len;
            if (self.cbs.onUniType) |cb| cb(self.cbs.ctx, self.id, t.streamType);
            if (self.failed) return; // connection rejected (duplicates)
            self.uni_kind = switch (t.streamType) {
                0x00 => .control,
                0x02 => .qpack_encoder,
                0x03 => .qpack_decoder,
                0x01 => {
                    // No-push policy: push streams are rejected.
                    self.fail(.h3_frame_unexpected);
                    return;
                },
                else => .unknown,
            };
        }
        switch (self.uni_kind) {
            .undecided => unreachable,
            .control => self.parseControl(),
            .qpack_encoder => self.parseQpackEncoder(),
            .qpack_decoder => self.parseQpackDecoder(),
            .push => unreachable, // failed at type parse
            .unknown => {
                // Unknown unidirectional types: consume and ignore.
                self.unknown_skipped +|= self.buf.items.len - self.off;
                self.off = self.buf.items.len;
                if (self.fin) self.done = true;
            },
        }
    }

    fn parseControl(self: *H3Stream) void {
        while (self.off < self.buf.items.len) {
            const start = self.off;
            const header = frame_mod.parseFrameHeader(self.buf.items, &self.off) catch |e| switch (e) {
                error.Truncated => {
                    self.off = start;
                    if (self.fin) self.fail(.h3_frame_error);
                    return;
                },
                else => {
                    self.fail(.h3_frame_error);
                    return;
                },
            };
            const n = std.math.cast(usize, header.length) orelse {
                self.fail(.h3_frame_error);
                return;
            };
            if (self.buf.items.len - self.off < n) {
                self.off = start;
                if (self.fin) self.fail(.h3_frame_error);
                return;
            }
            const payload = self.buf.items[self.off..][0..n];
            self.off += n;
            if (frame_mod.checkFrameAllowed(.control, header.frameType)) |code| {
                self.fail(code);
                return;
            }
            if (header.frameType == 0x4 and self.control_saw_settings) {
                // Second SETTINGS: connection state rejects it; flag here
                // so the error surfaces even without the connection layer.
                self.fail(.h3_settings_error);
                return;
            }
            if (header.frameType == 0x4) self.control_saw_settings = true;
            if (!self.control_saw_settings) {
                self.fail(.h3_missing_settings);
                return;
            }
            if (self.cbs.onControlFrame) |cb| cb(self.cbs.ctx, self.id, header.frameType, payload);
            if (self.failed) return; // connection rejected synchronously
        }
        if (self.fin) {
            // A control stream never ends cleanly; FIN is abrupt.
            self.fail(.h3_closed_critical_stream);
        }
    }

    fn parseQpackEncoder(self: *H3Stream) void {
        const avail = self.buf.items[self.off..];
        if (avail.len == 0) {
            if (self.fin) self.done = true;
            return;
        }
        self.qdec.readEncoderStream(avail, self.fin) catch {
            self.fail(.qpack_encoder_stream_error);
            return;
        };
        // readEncoderStream buffers internally; everything fed is consumed.
        self.off = self.buf.items.len;
        if (self.fin) self.done = true;
    }

    fn parseQpackDecoder(self: *H3Stream) void {
        const avail = self.buf.items[self.off..];
        if (avail.len == 0) {
            if (self.fin) self.done = true;
            return;
        }
        self.qenc.readDecoderStream(avail, self.fin) catch {
            self.fail(.qpack_decoder_stream_error);
            return;
        };
        self.off = self.buf.items.len;
        if (self.fin) self.done = true;
    }

    fn parseBidi(self: *H3Stream) void {
        while (self.off < self.buf.items.len) {
            const start = self.off;
            const header = frame_mod.parseFrameHeader(self.buf.items, &self.off) catch |e| switch (e) {
                error.Truncated => {
                    self.off = start;
                    if (self.fin) self.fail(.h3_frame_error);
                    return;
                },
                else => {
                    self.fail(.h3_frame_error);
                    return;
                },
            };
            const n = std.math.cast(usize, header.length) orelse {
                self.fail(.h3_frame_error);
                return;
            };
            if (self.buf.items.len - self.off < n) {
                self.off = start;
                if (self.fin) self.fail(.h3_frame_error);
                return;
            }
            const payload = self.buf.items[self.off..][0..n];
            self.off += n;
            if (frame_mod.checkFrameAllowed(.request_bidi, header.frameType)) |code| {
                self.fail(code);
                return;
            }
            self.dispatchBidiFrame(header.frameType, payload);
            if (self.blocked) {
                // Parked on a QPACK-blocked section: rewind so the
                // section bytes are retried, then stop until unblocked.
                self.off = start;
                return;
            }
            if (self.failed or self.done) return;
        }
        if (self.fin) self.endOfStream();
    }

    fn dispatchBidiFrame(self: *H3Stream, frameType: u64, payload: []const u8) void {
        switch (frameType) {
            0x1 => self.onHeadersFrame(payload),
            0x0 => self.onDataFrame(payload),
            else => {}, // unknown: length-skipped above
        }
    }

    fn onHeadersFrame(self: *H3Stream, payload: []const u8) void {
        const fields = self.qdec.decodeSectionCounted(payload, self.id, &self.decoderAck) catch |e| switch (e) {
            error.Blocked => {
                // Park: the section bytes stay at the cursor; the
                // connection layer retries after encoder data arrives.
                self.blocked = true;
                return;
            },
            else => {
                // 0x200: QPACK decompression failure on a request stream.
                self.fail(.qpack_general_error);
                return;
            },
        };
        defer self.qdec.freeFields(fields);
        self.blocked = false;

        if (self.http_state == .need_headers) {
            if (self.mode == .request_recv) {
                if (self.validateRequest(fields)) |code| {
                    self.fail(code);
                    return;
                }
                self.http_state = .headers;
                if (self.cbs.onHeaders) |cb| cb(self.cbs.ctx, self.id, fields, false);
            } else {
                // 1xx sections keep the stream in need_headers (a DATA
                // frame before the final HEADERS is malformed); the
                // final HEADERS moves to .headers via the same path.
                const interim = isInterimStatus(fields);
                if (self.validateResponse(fields, interim)) |code| {
                    self.fail(code);
                    return;
                }
                if (!interim) self.http_state = .headers;
                if (self.cbs.onHeaders) |cb| cb(self.cbs.ctx, self.id, fields, interim);
            }
            return;
        }
        if (self.http_state == .headers or self.http_state == .data) {
            // Second HEADERS section: trailers (legal with or without a
            // DATA frame in between).
            if (self.validateTrailers(fields)) |code| {
                self.fail(code);
                return;
            }
            self.http_state = .trailers;
            if (self.cbs.onTrailers) |cb| cb(self.cbs.ctx, self.id, fields);
            return;
        }
        // HEADERS in data/trailers/done state.
        self.fail(.h3_message_error);
    }

    fn onDataFrame(self: *H3Stream, payload: []const u8) void {
        if (self.http_state != .headers and self.http_state != .data) {
            self.fail(.h3_message_error);
            return;
        }
        self.http_state = .data;
        if (self.content_length) |expected| {
            self.body_received +|= payload.len;
            if (self.body_received > expected) {
                self.fail(.h3_message_error);
                return;
            }
        } else {
            self.body_received +|= payload.len;
        }
        if (self.cbs.onData) |cb| cb(self.cbs.ctx, self.id, payload);
    }

    fn endOfStream(self: *H3Stream) void {
        // Stream FIN with a partial frame already failed above; an empty
        // stream (or FIN before any HEADERS) is malformed messaging.
        if (self.http_state == .need_headers) {
            self.fail(.h3_message_error);
            return;
        }
        if (self.content_length) |expected| {
            if (self.body_received != expected) {
                self.fail(.h3_message_error);
                return;
            }
        }
        self.finishMessage();
    }

    /// True when the fields carry a 1xx informational status.
    fn isInterimStatus(fields: []const FieldLine) bool {
        const status = findField(fields, ":status") orelse return false;
        if (status.len != 3 or status[0] != '1') return false;
        for (status[1..]) |c| {
            if (c < '0' or c > '9') return false;
        }
        return true;
    }

    /// Validates request HEADERS; null when valid, else the H3 error.
    fn validateRequest(self: *H3Stream, fields: []const FieldLine) ?H3Error {
        var seen_regular = false;
        var method: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var protocol: ?[]const u8 = null;
        var host: ?[]const u8 = null;
        for (fields) |f| {
            if (f.name.len == 0) return .h3_message_error;
            for (f.name) |c| {
                if (c >= 'A' and c <= 'Z') return .h3_message_error;
            }
            if (f.name[0] == ':') {
                if (seen_regular) return .h3_message_error;
                if (std.mem.eql(u8, f.name, ":method")) {
                    if (method != null or f.value.len == 0) return .h3_message_error;
                    for (f.value) |c| {
                        if (c <= ' ' or c == 0x7F) return .h3_message_error;
                    }
                    method = f.value;
                } else if (std.mem.eql(u8, f.name, ":scheme")) {
                    if (scheme != null) return .h3_message_error;
                    scheme = f.value;
                } else if (std.mem.eql(u8, f.name, ":authority")) {
                    if (authority != null or f.value.len == 0) return .h3_message_error;
                    authority = f.value;
                } else if (std.mem.eql(u8, f.name, ":path")) {
                    if (path != null or f.value.len == 0) return .h3_message_error;
                    path = f.value;
                } else if (std.mem.eql(u8, f.name, ":protocol")) {
                    if (protocol != null) return .h3_message_error;
                    protocol = f.value;
                } else {
                    return .h3_message_error; // unknown pseudo-header
                }
            } else {
                seen_regular = true;
                if (std.mem.eql(u8, f.name, "host")) {
                    if (host != null) return .h3_message_error;
                    host = f.value;
                }
                if (self.checkRegularHeader(f.name, f.value)) |code| return code;
            }
        }
        const m = method orelse return .h3_message_error;
        const is_connect = std.mem.eql(u8, m, "CONNECT");
        if (is_connect) {
            // CONNECT omits :scheme/:path and requires :authority.
            if (scheme != null or path != null) return .h3_message_error;
            if (authority == null) return .h3_message_error;
            if (protocol != null and !self.connect_allowed) return .h3_message_error;
        } else {
            if (scheme == null or path == null) return .h3_message_error;
            if (authority == null and host == null) return .h3_message_error;
            if (protocol != null) return .h3_message_error;
            const p = path.?;
            if (p.len == 0) return .h3_message_error;
            if (p[0] != '/' and !(p.len == 1 and p[0] == '*')) return .h3_message_error;
            if (p[0] == '*' and !std.mem.eql(u8, m, "OPTIONS")) return .h3_message_error;
        }
        if (self.captureContentLength(fields)) |code| return code;
        return null;
    }

    fn validateResponse(self: *H3Stream, fields: []const FieldLine, interim: bool) ?H3Error {
        var seen_regular = false;
        var status: ?[]const u8 = null;
        for (fields) |f| {
            if (f.name.len == 0) return .h3_message_error;
            for (f.name) |c| {
                if (c >= 'A' and c <= 'Z') return .h3_message_error;
            }
            if (f.name[0] == ':') {
                if (seen_regular) return .h3_message_error;
                if (std.mem.eql(u8, f.name, ":status")) {
                    if (status != null) return .h3_message_error;
                    if (f.value.len != 3) return .h3_message_error;
                    for (f.value) |c| {
                        if (c < '0' or c > '9') return .h3_message_error;
                    }
                    const code = (f.value[0] - '0') * 100 + (f.value[1] - '0') * 10 + (f.value[2] - '0');
                    if (code < 100 or code > 999) return .h3_message_error;
                    const is_1xx = f.value[0] == '1';
                    if (interim != is_1xx) return .h3_message_error;
                    status = f.value;
                } else {
                    return .h3_message_error; // unknown pseudo-header
                }
            } else {
                seen_regular = true;
                if (self.checkRegularHeader(f.name, f.value)) |code| return code;
            }
        }
        if (status == null) return .h3_message_error;
        if (!interim) {
            if (self.captureContentLength(fields)) |code| return code;
        }
        return null;
    }

    fn validateTrailers(self: *H3Stream, fields: []const FieldLine) ?H3Error {
        for (fields) |f| {
            if (f.name.len == 0) return .h3_message_error;
            if (f.name[0] == ':') return .h3_message_error; // no pseudos in trailers
            for (f.name) |c| {
                if (c >= 'A' and c <= 'Z') return .h3_message_error;
            }
            if (self.checkRegularHeader(f.name, f.value)) |code| return code;
        }
        return null;
    }

    fn checkRegularHeader(_: *H3Stream, name: []const u8, value: []const u8) ?H3Error {
        if (std.mem.eql(u8, name, "connection") or
            std.mem.eql(u8, name, "keep-alive") or
            std.mem.eql(u8, name, "proxy-connection") or
            std.mem.eql(u8, name, "transfer-encoding") or
            std.mem.eql(u8, name, "upgrade"))
        {
            return .h3_message_error;
        }
        if (std.mem.eql(u8, name, "te") and !std.mem.eql(u8, value, "trailers")) {
            return .h3_message_error;
        }
        return null;
    }

    fn captureContentLength(self: *H3Stream, fields: []const FieldLine) ?H3Error {
        var seen: ?[]const u8 = null;
        for (fields) |f| {
            if (!std.mem.eql(u8, f.name, "content-length")) continue;
            if (f.value.len == 0) return .h3_message_error;
            for (f.value) |c| {
                if (c < '0' or c > '9') return .h3_message_error;
            }
            if (seen) |prev| {
                if (!std.mem.eql(u8, prev, f.value)) return .h3_message_error;
                continue;
            }
            seen = f.value;
        }
        if (seen) |v| {
            self.content_length = std.fmt.parseInt(u64, v, 10) catch return .h3_message_error;
        }
        return null;
    }
};

// Tests

const TestRec = struct {
    headers: usize = 0,
    interim: usize = 0,
    data_bytes: usize = 0,
    trailers: usize = 0,
    ends: usize = 0,
    control_frames: usize = 0,
    last_control_type: u64 = 0,
    uni_types: usize = 0,
    last_uni_type: u64 = 0,
    last_err: ?H3Error = null,
    saw_get: bool = false,

    fn cbs(self: *TestRec) Callbacks {
        return .{
            .ctx = self,
            .onHeaders = onH,
            .onData = onD,
            .onTrailers = onT,
            .onMessageEnd = onE,
            .onControlFrame = onC,
            .onUniType = onU,
            .onError = onErr,
        };
    }
    fn onH(ctx: ?*anyopaque, sid: u64, fields: []const FieldLine, interim: bool) void {
        _ = sid;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.headers += 1;
        if (interim) r.interim += 1;
        if (findField(fields, ":method")) |m| {
            if (std.mem.eql(u8, m, "GET")) r.saw_get = true;
        }
    }
    fn onD(ctx: ?*anyopaque, sid: u64, data: []const u8) void {
        _ = sid;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.data_bytes += data.len;
    }
    fn onT(ctx: ?*anyopaque, sid: u64, fields: []const FieldLine) void {
        _ = sid;
        _ = fields;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.trailers += 1;
    }
    fn onE(ctx: ?*anyopaque, sid: u64) void {
        _ = sid;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.ends += 1;
    }
    fn onC(ctx: ?*anyopaque, sid: u64, frameType: u64, payload: []const u8) void {
        _ = sid;
        _ = payload;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.control_frames += 1;
        r.last_control_type = frameType;
    }
    fn onU(ctx: ?*anyopaque, sid: u64, streamType: u64) void {
        _ = sid;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.uni_types += 1;
        r.last_uni_type = streamType;
    }
    fn onErr(ctx: ?*anyopaque, sid: u64, code: H3Error) void {
        _ = sid;
        const r: *TestRec = @ptrCast(@alignCast(ctx.?));
        r.last_err = code;
    }
};

fn testFrame(a: Allocator, ftype: u64, payload: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    var fh: [16]u8 = undefined;
    const n = try frame_mod.encodeFrameHeader(&fh, ftype, payload.len);
    try out.appendSlice(a, fh[0..n]);
    try out.appendSlice(a, payload);
    return out.toOwnedSlice(a);
}

fn testSection(
    a: Allocator,
    enc: *qpack_mod.Encoder,
    heads: []const [2][]const u8,
) ![]u8 {
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);
    enc.beginSection();
    for (heads) |h| try enc.encodeField(&block, h[0], h[1]);
    const ric = enc.sectionRic();
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try enc.encodePrefix(&out, ric, ric);
    try out.appendSlice(a, block.items);
    return out.toOwnedSlice(a);
}

fn testBidi(a: Allocator, rec: *TestRec, sid: u64, mode: StreamMode, qdec: *qpack_mod.Decoder, qenc: *qpack_mod.Encoder) H3Stream {
    return H3Stream.init(a, sid, mode, if (mode == .request_recv) .server else .client, rec.cbs(), qdec, qenc);
}

test "h3stream control accepts settings then rejects data" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = H3Stream.init(a, 2, .uni, .server, rec.cbs(), &qdec, &qenc);
    defer s.deinit();

    var settings_payload = std.ArrayList(u8).empty;
    defer settings_payload.deinit(a);
    try settings_payload.append(a, 0x00); // control type
    const entries = [_]frame_mod.SettingEntry{.{ .id = 0x6, .value = 4096 }};
    const sp = try frame_mod.buildSettingsPayload(a, &entries);
    defer a.free(sp);
    const sf = try testFrame(a, 0x4, sp);
    defer a.free(sf);
    try settings_payload.appendSlice(a, sf);
    s.feed(settings_payload.items, false);
    try std.testing.expectEqual(@as(usize, 1), rec.uni_types);
    try std.testing.expectEqual(@as(usize, 1), rec.control_frames);
    try std.testing.expectEqual(@as(u64, 0x4), rec.last_control_type);
    try std.testing.expect(rec.last_err == null);

    const df = try testFrame(a, 0x0, "x");
    defer a.free(df);
    s.feed(df, false);
    try std.testing.expectEqual(H3Error.h3_frame_unexpected, rec.last_err.?);
}

test "h3stream fragmented uni type then unknown skip" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = H3Stream.init(a, 3, .uni, .client, rec.cbs(), &qdec, &qenc);
    defer s.deinit();

    s.feed(&.{0x40}, false); // 2-byte varint, incomplete
    try std.testing.expectEqual(@as(usize, 0), rec.uni_types);
    try std.testing.expect(rec.last_err == null);
    s.feed(&.{ 0x40, 0x05, 'h', 'e', 'l', 'l', 'o' }, true); // type 64
    try std.testing.expectEqual(@as(usize, 1), rec.uni_types);
    try std.testing.expectEqual(@as(u64, 64), rec.last_uni_type);
    try std.testing.expect(rec.last_err == null);
    try std.testing.expect(s.done);

    // Truncated type at FIN is a frame error.
    var rec2 = TestRec{};
    var s2 = H3Stream.init(a, 7, .uni, .client, rec2.cbs(), &qdec, &qenc);
    defer s2.deinit();
    s2.feed(&.{0x40}, true);
    try std.testing.expectEqual(H3Error.h3_frame_error, rec2.last_err.?);
}

test "h3stream push streams are rejected" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = H3Stream.init(a, 2, .uni, .server, rec.cbs(), &qdec, &qenc);
    defer s.deinit();
    s.feed(&.{0x01}, false);
    try std.testing.expectEqual(H3Error.h3_frame_unexpected, rec.last_err.?);
}

test "h3stream request headers data fin" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var qenc_peer = qpack_mod.Encoder.init(a);
    defer qenc_peer.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();

    const section = try testSection(a, &qenc_peer, &.{
        .{ ":method", "GET" },
        .{ ":scheme", "https" },
        .{ ":authority", "example.com" },
        .{ ":path", "/" },
    });
    defer a.free(section);
    const hf = try testFrame(a, 0x1, section);
    defer a.free(hf);
    const df = try testFrame(a, 0x0, "hi");
    defer a.free(df);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try wire.appendSlice(a, hf);
    try wire.appendSlice(a, df);
    s.feed(wire.items, true);
    try std.testing.expect(rec.last_err == null);
    try std.testing.expectEqual(@as(usize, 1), rec.headers);
    try std.testing.expect(rec.saw_get);
    try std.testing.expectEqual(@as(usize, 2), rec.data_bytes);
    try std.testing.expectEqual(@as(usize, 1), rec.ends);
}

test "h3stream trailers delivered after data" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var qp = qpack_mod.Encoder.init(a);
    defer qp.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();

    const h1 = try testSection(a, &qp, &.{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" } });
    defer a.free(h1);
    const h2 = try testSection(a, &qp, &.{.{ "x-trailer", "1" }});
    defer a.free(h2);
    const f1 = try testFrame(a, 0x1, h1);
    defer a.free(f1);
    const fd = try testFrame(a, 0x0, "body");
    defer a.free(fd);
    const f2 = try testFrame(a, 0x1, h2);
    defer a.free(f2);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try wire.appendSlice(a, f1);
    try wire.appendSlice(a, fd);
    try wire.appendSlice(a, f2);
    s.feed(wire.items, true);
    try std.testing.expect(rec.last_err == null);
    try std.testing.expectEqual(@as(usize, 1), rec.headers);
    try std.testing.expectEqual(@as(usize, 4), rec.data_bytes);
    try std.testing.expectEqual(@as(usize, 1), rec.trailers);
    try std.testing.expectEqual(@as(usize, 1), rec.ends);
}

test "h3stream interim 1xx then final" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var qp = qpack_mod.Encoder.init(a);
    defer qp.deinit();
    var s = testBidi(a, &rec, 0, .response_recv, &qdec, &qenc);
    defer s.deinit();

    const h1 = try testSection(a, &qp, &.{.{ ":status", "103" }});
    defer a.free(h1);
    const h2 = try testSection(a, &qp, &.{ .{ ":status", "200" }, .{ "content-length", "2" } });
    defer a.free(h2);
    const f1 = try testFrame(a, 0x1, h1);
    defer a.free(f1);
    const f2 = try testFrame(a, 0x1, h2);
    defer a.free(f2);
    const fd = try testFrame(a, 0x0, "ok");
    defer a.free(fd);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try wire.appendSlice(a, f1);
    try wire.appendSlice(a, f2);
    try wire.appendSlice(a, fd);
    s.feed(wire.items, true);
    try std.testing.expect(rec.last_err == null);
    try std.testing.expectEqual(@as(usize, 2), rec.headers);
    try std.testing.expectEqual(@as(usize, 1), rec.interim);
    try std.testing.expectEqual(@as(usize, 2), rec.data_bytes);
    try std.testing.expectEqual(@as(usize, 1), rec.ends);
}

test "h3stream data before headers is malformed" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();
    const df = try testFrame(a, 0x0, "early");
    defer a.free(df);
    s.feed(df, false);
    try std.testing.expectEqual(H3Error.h3_message_error, rec.last_err.?);
}

test "h3stream header validation matrix" {
    const a = std.testing.allocator;
    const Case = struct { heads: []const [2][]const u8, ok: bool };
    const cases = [_]Case{
        // Duplicate pseudo-header.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" } }, .ok = false },
        // Uppercase field name.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" }, .{ "X-Bad", "v" } }, .ok = false },
        // Forbidden connection header.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" }, .{ "connection", "close" } }, .ok = false },
        // Missing :path.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" } }, .ok = false },
        // Unknown pseudo-header.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" }, .{ ":foo", "bar" } }, .ok = false },
        // Pseudo-header after a regular one.
        .{ .heads = &.{ .{ "x-a", "1" }, .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" } }, .ok = false },
        // Non-numeric content-length.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" }, .{ "content-length", "abc" } }, .ok = false },
        // Relative path without leading slash.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "nope" } }, .ok = false },
        // Asterisk path only valid for OPTIONS.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "*" } }, .ok = false },
        // OPTIONS asterisk form is valid.
        .{ .heads = &.{ .{ ":method", "OPTIONS" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "*" } }, .ok = true },
        // Minimal valid GET.
        .{ .heads = &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" } }, .ok = true },
    };
    for (cases) |c| {
        var rec = TestRec{};
        var qdec = qpack_mod.Decoder.init(a);
        defer qdec.deinit();
        var qenc = qpack_mod.Encoder.init(a);
        defer qenc.deinit();
        var qp = qpack_mod.Encoder.init(a);
        defer qp.deinit();
        var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
        defer s.deinit();
        const section = try testSection(a, &qp, c.heads);
        defer a.free(section);
        const hf = try testFrame(a, 0x1, section);
        defer a.free(hf);
        s.feed(hf, true);
        if (c.ok) {
            try std.testing.expect(rec.last_err == null);
            try std.testing.expectEqual(@as(usize, 1), rec.ends);
        } else {
            try std.testing.expectEqual(H3Error.h3_message_error, rec.last_err.?);
        }
    }
}

test "h3stream content length mismatch fails at fin" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var qp = qpack_mod.Encoder.init(a);
    defer qp.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();
    const section = try testSection(a, &qp, &.{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":authority", "x" }, .{ ":path", "/" }, .{ "content-length", "10" } });
    defer a.free(section);
    const hf = try testFrame(a, 0x1, section);
    defer a.free(hf);
    const df = try testFrame(a, 0x0, "hi");
    defer a.free(df);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try wire.appendSlice(a, hf);
    try wire.appendSlice(a, df);
    s.feed(wire.items, true); // declares 10, delivers 2
    try std.testing.expectEqual(H3Error.h3_message_error, rec.last_err.?);
}

test "h3stream qpack blocked parks then resumes" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    qdec.setMaxTableCapacity(4096);
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();

    // Peer encoder side (shares nothing with our decoder yet): a full
    // valid request whose last field is dynamic.
    var penc = qpack_mod.Encoder.init(a);
    defer penc.deinit();
    penc.setMaxTableCapacity(4096);
    penc.beginSection();
    var field = std.ArrayList(u8).empty;
    defer field.deinit(a);
    try penc.encodeField(&field, ":method", "GET");
    try penc.encodeField(&field, ":scheme", "https");
    try penc.encodeField(&field, ":authority", "example.com");
    try penc.encodeField(&field, ":path", "/");
    try penc.encodeField(&field, "x-dynamic", "d");
    const ric = penc.sectionRic();
    var section = std.ArrayList(u8).empty;
    defer section.deinit(a);
    try penc.encodePrefix(&section, ric, ric);
    try section.appendSlice(a, field.items);
    const enc_bytes = try penc.takeEncoderBytes();
    defer a.free(enc_bytes);

    const hf = try testFrame(a, 0x1, section.items);
    defer a.free(hf);
    s.feed(hf, false);
    try std.testing.expect(s.blocked);
    try std.testing.expectEqual(@as(usize, 0), rec.headers);
    try std.testing.expect(rec.last_err == null);

    // Encoder bytes arrive on the encoder stream; the bidi retries.
    var es = H3Stream.init(a, 6, .uni, .server, rec.cbs(), &qdec, &qenc);
    defer es.deinit();
    var ewire = std.ArrayList(u8).empty;
    defer ewire.deinit(a);
    try ewire.append(a, 0x02);
    try ewire.appendSlice(a, enc_bytes);
    es.feed(ewire.items, false);
    try std.testing.expect(rec.last_err == null);
    s.retryBlocked();
    try std.testing.expect(!s.blocked);
    try std.testing.expectEqual(@as(usize, 1), rec.headers);
    try std.testing.expect(rec.saw_get);
    const ack = try s.takeDecoderAck();
    defer a.free(ack);
    try std.testing.expect(ack.len > 0);
}

test "h3stream fin mid-frame and empty fin" {
    const a = std.testing.allocator;
    var rec = TestRec{};
    var qdec = qpack_mod.Decoder.init(a);
    defer qdec.deinit();
    var qenc = qpack_mod.Encoder.init(a);
    defer qenc.deinit();
    var s = testBidi(a, &rec, 0, .request_recv, &qdec, &qenc);
    defer s.deinit();
    // HEADERS header declares 10 payload bytes, stream ends after 2.
    s.feed(&.{ 0x01, 0x0A, 0x00, 0x00 }, true);
    try std.testing.expectEqual(H3Error.h3_frame_error, rec.last_err.?);

    var rec2 = TestRec{};
    var s2 = testBidi(a, &rec2, 4, .request_recv, &qdec, &qenc);
    defer s2.deinit();
    s2.feed(&.{}, true);
    try std.testing.expectEqual(H3Error.h3_message_error, rec2.last_err.?);
}

test "h3stream check peer stream ids" {
    try std.testing.expect(checkPeerStreamId(.server, 0) == null);
    try std.testing.expect(checkPeerStreamId(.server, 4) == null);
    try std.testing.expect(checkPeerStreamId(.server, 1) != null);
    try std.testing.expect(checkPeerStreamId(.server, 2) == null);
    try std.testing.expect(checkPeerStreamId(.server, 3) != null);
    try std.testing.expect(checkPeerStreamId(.client, 0) != null);
    try std.testing.expect(checkPeerStreamId(.client, 3) == null);
    try std.testing.expect(checkPeerStreamId(.client, 2) != null);
}
