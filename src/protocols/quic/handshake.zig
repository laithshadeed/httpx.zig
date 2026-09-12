//! Production TLS 1.3 handshake driver for QUIC (RFC 9001).
//!
//! Where the loopback `TlsHandshakeDriver` in `connection.zig` uses empty
//! certificates and fixed keys, this driver runs REAL handshakes: the
//! client offers ALPN `h3` with SNI and verifies the server chain against
//! system/custom trust; the server selects `h3` and signs with its real
//! P-256 identity; both sides exchange Finished and the server confirms
//! with HANDSHAKE_DONE.
//!
//! Deliberate scope (documented, not hidden):
//!   * Full handshakes only — no PSK resumption over QUIC yet (the TLS
//!     engine supports it on TCP; wiring offer/capture through CRYPTO
//!     streams is future work).
//!   * No HelloRetryRequest handling: our client always offers an x25519
//!     share, so a conforming server never needs to retry. A foreign HRR
//!     surfaces as a handshake timeout, never silent corruption.
//!   * Transport parameters (`quic_transport_parameters`, ext 57) are
//!     exchanged in ClientHello/EncryptedExtensions and applied to
//!     flow-control windows, stream limits, and connection IDs; absent
//!     values keep compiled-in defaults. Retry/token and version
//!     negotiation stay future work.
//!   * No Retry/token round trip: first flight validates routability on
//!     loopback; deployments facing the open internet must add Retry.
//!   * No loss recovery / congestion control: reliable paths only
//!     (loopback, LAN). Lossy networks will stall to the deadline.
//!
//! Thread-safety: thread-confined per connection (one driver per side).

const std = @import("std");
const Allocator = std.mem.Allocator;
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const SpaceKind = conn_mod.SpaceKind;
const transport_mod = @import("transport.zig");
const Endpoint = transport_mod.Endpoint;
const tls_engine = @import("../tls/engine.zig");
const qtls = @import("../tls/quicTls.zig");
const ths = @import("../tls/handshake.zig");
const verify_mod = @import("../tls/verify.zig");
const transport_tls = @import("../tls/transport.zig");
const packet_mod = @import("packet.zig");
const frames = @import("frames.zig");
const params_mod = @import("params.zig");
const quic_varint = @import("varint.zig");
const clock_mod = @import("../../common/clock.zig");
const address_mod = @import("../../net/address.zig");

pub const ClientConfig = struct {
    /// Server hostname: SNI (DNS names) + chain hostname check + ticket binding.
    host: []const u8,
    verify: transport_tls.VerifyMode = .caBundle,
    /// Extra/custom CA PEM trusted in addition to system roots.
    caPem: ?[]const u8 = null,
};

pub const ServerConfig = struct {
    certChainPem: []const u8,
    privateKeyPem: []const u8,
};

/// Precise handshake failure cause, preserved across the TlsDriver seam.
pub const Detail = enum {
    none,
    alpn_mismatch,
    cert_failed,
    handshake_failed,
};

/// Production handshake driver state (one per connection side).
pub const Driver = struct {
    allocator: Allocator,
    role: conn_mod.Role,
    engine: tls_engine.Engine,
    /// Own ClientHello bytes (client: for key derivation binding).
    flight: std.ArrayList(u8) = .empty,
    /// Accumulated inbound CRYPTO bytes for record reassembly.
    incoming: std.ArrayList(u8) = .empty,
    /// Full peer flight (client: server SH..Fin, for key derivation).
    peer_flight: std.ArrayList(u8) = .empty,
    /// Server certificate DERs presented to this client (owned).
    cert_ders: std.ArrayList([]u8) = .empty,
    hs_secret: ?[32]u8 = null,
    flight_done: bool = false,
    /// Precise failure cause for the H3 layer to map (the TlsDriver
    /// seam only carries `conn_mod.Error`; this preserves the loud,
    /// specific reason across it).
    detail: Detail = .none,
    /// Latched on any driver failure. Pump loops poll this to fail FAST
    /// (precise cause via `detail`) instead of burning the whole
    /// deadline after the handshake is already doomed. Set and read on
    /// the owner thread only (the driver never runs on pump threads).
    failed: bool = false,
    // Client policy (unused on server role).
    host: []const u8 = "",
    verify: transport_tls.VerifyMode = .caBundle,
    caPem: ?[]const u8 = null,
    // Server identity (unused on client role).
    cert_chain_pem: []const u8 = "",
    private_key_pem: []const u8 = "",

    pub fn initClient(allocator: Allocator, cfg: ClientConfig) Driver {
        return .{
            .allocator = allocator,
            .role = .client,
            .engine = tls_engine.Engine.initClient(allocator, .{}),
            .host = cfg.host,
            .verify = cfg.verify,
            .caPem = cfg.caPem,
        };
    }

    pub fn initServer(allocator: Allocator, cfg: ServerConfig) Driver {
        return .{
            .allocator = allocator,
            .role = .server,
            .engine = tls_engine.Engine.initServer(allocator, .{}),
            .cert_chain_pem = cfg.certChainPem,
            .private_key_pem = cfg.privateKeyPem,
        };
    }

    pub fn deinit(self: *Driver) void {
        self.engine.deinit();
        self.flight.deinit(self.allocator);
        self.incoming.deinit(self.allocator);
        self.peer_flight.deinit(self.allocator);
        for (self.cert_ders.items) |d| self.allocator.free(d);
        self.cert_ders.deinit(self.allocator);
    }

    /// Builds our transport-parameters block: numeric limits from the
    /// connection config plus our connection IDs. Stateless-reset and
    /// retry tokens are omitted (unsupported); peers must not expect
    /// them from us.
    fn buildLocalTransportParams(a: Allocator, conn: *Connection) ![]u8 {
        const cfg = conn.cfg;
        const p = params_mod.Params{
            .maxIdleTimeoutMs = cfg.maxIdleTimeoutMs,
            .maxUdpPayloadSize = @intCast(cfg.maxUdpPayload),
            .initialMaxData = cfg.initialMaxData,
            .initialMaxStreamDataBidiLocal = 65536,
            .initialMaxStreamDataBidiRemote = 65536,
            .initialMaxStreamDataUni = 65536,
            .initialMaxStreamsBidi = conn.maxStreamsBidiLocal,
            .initialMaxStreamsUni = conn.maxStreamsUniLocal,
        };
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(a);
        try params_mod.encode(&out, a, p);
        // initial_source_connection_id: our SCID so the peer can bind it.
        {
            var vb: [8]u8 = undefined;
            var n = try quic_varint.encode(&vb, 0x0F);
            try out.appendSlice(a, vb[0..n]);
            n = try quic_varint.encode(&vb, conn.scidLen);
            try out.appendSlice(a, vb[0..n]);
            try out.appendSlice(a, conn.scid[0..conn.scidLen]);
        }
        // original_destination_connection_id: servers echo the DCID the
        // client first used (already installed by acceptInitial).
        if (conn.role == .server) {
            var vb: [8]u8 = undefined;
            var n = try quic_varint.encode(&vb, 0x00);
            try out.appendSlice(a, vb[0..n]);
            n = try quic_varint.encode(&vb, conn.dcidLen);
            try out.appendSlice(a, vb[0..n]);
            try out.appendSlice(a, conn.dcid[0..conn.dcidLen]);
        }
        return out.toOwnedSlice(a);
    }

    /// Applies decoded peer transport parameters to the connection.
    /// Nonzero values override the compiled defaults; absent values
    /// keep them (so unit paths without a TLS exchange keep working).
    /// Fails closed on Retry tokens (we never send Retry) and on an
    /// original-DCID mismatch (server side).
    fn applyPeerTransportParams(conn: *Connection, tp: []const u8, is_server: bool) conn_mod.Error!void {
        const p = params_mod.decode(tp) catch return conn_mod.Error.TransportParameterError;
        const cids = params_mod.parseCidParams(tp) catch return conn_mod.Error.TransportParameterError;
        if (cids.retrySourceConnectionId != null) return conn_mod.Error.TransportParameterError;
        if (is_server) {
            // Servers never receive original_destination_connection_id
            // (they send it); requiring it here would fail every client.
            if (cids.originalDestinationConnectionId != null) return conn_mod.Error.TransportParameterError;
        } else if (cids.originalDestinationConnectionId) |odcid| {
            // The server echoes the DCID from our Initial; a mismatch
            // means we are talking to a confused or hostile peer.
            if (odcid.len != conn.origDcidLen or !std.mem.eql(u8, odcid, conn.origDcid[0..conn.origDcidLen])) {
                return conn_mod.Error.TransportParameterError;
            }
        }
        if (p.initialMaxData != 0) conn.maxDataRemote = p.initialMaxData;
        // Our sends: streams we initiate use the peer's "remote" limit,
        // peer-initiated streams use their "local" limit; take the
        // tighter nonzero bound so either direction stays legal.
        var bidi: ?u64 = null;
        if (p.initialMaxStreamDataBidiLocal != 0) bidi = p.initialMaxStreamDataBidiLocal;
        if (p.initialMaxStreamDataBidiRemote != 0) {
            bidi = if (bidi) |b| @min(b, p.initialMaxStreamDataBidiRemote) else p.initialMaxStreamDataBidiRemote;
        }
        if (bidi) |b| conn.sendWindowBidi = b;
        if (p.initialMaxStreamDataUni != 0) conn.sendWindowUni = p.initialMaxStreamDataUni;
        if (p.initialMaxStreamsBidi != 0) conn.maxStreamsBidiRemote = p.initialMaxStreamsBidi;
        if (p.initialMaxStreamsUni != 0) conn.maxStreamsUniRemote = p.initialMaxStreamsUni;
        if (p.maxAckDelayMs != 0) conn.recovery.cfg.maxAckDelayMs = p.maxAckDelayMs;
        conn.peerParams = p;
    }

    /// Drains queued CRYPTO bytes into packet(s) on the given space.
    fn sendQueued(conn: *Connection, kind: SpaceKind, nowMs: u64) conn_mod.Error!void {
        const B = struct {
            var target: ?*Connection = null;
            var skind: SpaceKind = .initial;
            pub fn build(gpa: Allocator, payload: *std.ArrayList(u8)) conn_mod.Error!void {
                const c = target orelse return;
                while (c.takeCrypto(skind, 1200)) |chunk| {
                    frames.encode(payload, gpa, .{ .crypto = .{ .offset = chunk.offset, .data = chunk.data } }) catch
                        return conn_mod.Error.OutOfMemory;
                    _ = c.consumeCrypto(skind, chunk.data.len);
                }
            }
        };
        if (conn.takeCrypto(kind, 1) == null) return;
        B.target = conn;
        B.skind = kind;
        try conn.sendFrames(kind, B.build, nowMs);
    }

    /// Consumes one complete handshake record from the front of `buf`.
    fn takeRecord(buf: *std.ArrayList(u8)) ?struct { kind: u8, msg: []const u8 } {
        if (buf.items.len < 4) return null;
        const body_len: usize = (@as(usize, buf.items[1]) << 16) | (@as(usize, buf.items[2]) << 8) | buf.items[3];
        if (buf.items.len < 4 + body_len) return null;
        return .{ .kind = buf.items[0], .msg = buf.items[0 .. 4 + body_len] };
    }

    fn dropFront(buf: *std.ArrayList(u8), a: Allocator, n: usize) void {
        buf.replaceRange(a, 0, n, &.{}) catch {};
    }

    fn sniFor(host: []const u8) ?[]const u8 {
        var probe = address_mod.Address{ .family = .ip4, .port = 0 };
        return if (probe.parseIp(host)) |_| null else |_| host;
    }

    pub fn clientStart(ctx: ?*anyopaque, conn: *Connection, nowMs: u64) conn_mod.Error!void {
        const d: *Driver = @ptrCast(@alignCast(ctx.?));
        const tp = buildLocalTransportParams(conn.allocator, conn) catch
            return conn_mod.Error.OutOfMemory;
        defer conn.allocator.free(tp);
        const ch = d.engine.produceClientHelloWithSni(&.{"h3"}, &.{}, sniFor(d.host), tp) catch
            return conn_mod.Error.TlsDriverFailed;
        defer conn.allocator.free(ch);
        d.flight.appendSlice(conn.allocator, ch) catch return conn_mod.Error.OutOfMemory;
        _ = conn.queueCrypto(.initial, ch) catch return conn_mod.Error.TlsDriverFailed;
        try sendQueued(conn, .initial, nowMs);
    }

    pub fn onData(ctx: ?*anyopaque, conn: *Connection, data: []const u8, nowMs: u64) conn_mod.Error!void {
        const d: *Driver = @ptrCast(@alignCast(ctx.?));
        if (d.role == .client) {
            clientOnData(d, conn, data, nowMs) catch |e| {
                d.failed = true;
                return e;
            };
        } else {
            serverOnData(d, conn, data, nowMs) catch |e| {
                d.failed = true;
                return e;
            };
        }
    }

    fn clientOnData(d: *Driver, conn: *Connection, data: []const u8, nowMs: u64) conn_mod.Error!void {
        const a = conn.allocator;
        d.incoming.appendSlice(a, data) catch return conn_mod.Error.OutOfMemory;
        d.peer_flight.appendSlice(a, data) catch return conn_mod.Error.OutOfMemory;
        while (takeRecord(&d.incoming)) |rec| {
            switch (rec.kind) {
                @intFromEnum(ths.HandshakeType.server_hello) => {
                    d.engine.processServerHello(rec.msg) catch return conn_mod.Error.TlsDriverFailed;
                    const shared = d.engine.sharedSecret orelse return conn_mod.Error.TlsDriverFailed;
                    const ch_sh = d.engine.transcript.finish();
                    const hs = qtls.handshakeKeys(shared, ch_sh);
                    d.hs_secret = hs.hsSecret;
                    try conn.installKeys(.handshake, hs.keys.txSecret, hs.keys.rxSecret);
                    conn.discardInitialKeys();
                },
                @intFromEnum(ths.HandshakeType.encrypted_extensions) => {
                    d.engine.processEncryptedExtensions(rec.msg) catch return conn_mod.Error.TlsDriverFailed;
                    const alpn = d.engine.negotiatedAlpn orelse {
                        d.detail = .alpn_mismatch;
                        return conn_mod.Error.TlsDriverFailed;
                    };
                    if (!std.mem.eql(u8, alpn, "h3")) {
                        d.detail = .alpn_mismatch;
                        return conn_mod.Error.TlsDriverFailed;
                    }
                    // Apply the peer's transport parameters before any
                    // 1-RTT traffic flows.
                    if (d.engine.peerQuicTransportParams) |tp| {
                        applyPeerTransportParams(conn, tp, false) catch {
                            d.detail = .handshake_failed;
                            return conn_mod.Error.TlsDriverFailed;
                        };
                    }
                },
                @intFromEnum(ths.HandshakeType.certificate) => {
                    var presented = d.engine.processClientCertificate(rec.msg) catch
                        return conn_mod.Error.TlsDriverFailed;
                    defer presented.deinit();
                    for (presented.ders) |der| {
                        const owned = a.dupe(u8, der) catch return conn_mod.Error.OutOfMemory;
                        d.cert_ders.append(a, owned) catch {
                            a.free(owned);
                            return conn_mod.Error.OutOfMemory;
                        };
                    }
                },
                @intFromEnum(ths.HandshakeType.certificate_verify) => {
                    // Full verification (decode + signature + feed) in one
                    // step: calling the decode-only processCertificateVerify
                    // first would feed twice and verify against the wrong
                    // transcript (including CV itself).
                    if (d.cert_ders.items.len == 0) {
                        d.detail = .cert_failed;
                        return conn_mod.Error.TlsDriverFailed;
                    }
                    d.engine.processServerCertificateVerify(rec.msg, d.cert_ders.items[0]) catch {
                        d.detail = .cert_failed;
                        return conn_mod.Error.TlsDriverFailed;
                    };
                },
                @intFromEnum(ths.HandshakeType.finished) => {
                    d.engine.processFinished(rec.msg) catch return conn_mod.Error.TlsDriverFailed;
                    // Chain verification BEFORE installing application
                    // keys: never encrypt to an untrusted peer.
                    verify_mod.verifyServerChain(a, connIo(conn), d.verify, d.caPem, d.host, d.cert_ders.items) catch {
                        d.detail = .cert_failed;
                        return conn_mod.Error.TlsDriverFailed;
                    };
                    const hs_secret = d.hs_secret orelse return conn_mod.Error.TlsDriverFailed;
                    const ch_sf = d.engine.transcript.finish();
                    const ap = qtls.applicationKeys(hs_secret, ch_sf);
                    try conn.installKeys(.application, ap.keys.txSecret, ap.keys.rxSecret);
                    // Our Finished completes the client flight.
                    const fin = d.engine.produceClientFinished() catch
                        return conn_mod.Error.TlsDriverFailed;
                    defer a.free(fin);
                    _ = conn.queueCrypto(.handshake, fin) catch return conn_mod.Error.TlsDriverFailed;
                    try sendQueued(conn, .handshake, nowMs);
                },
                else => return conn_mod.Error.ProtocolViolation,
            }
            dropFront(&d.incoming, a, rec.msg.len);
        }
    }

    fn serverOnData(d: *Driver, conn: *Connection, data: []const u8, nowMs: u64) conn_mod.Error!void {
        const a = conn.allocator;
        if (d.flight_done) {
            // Post-flight: only the client's Finished is expected.
            d.incoming.appendSlice(a, data) catch return conn_mod.Error.OutOfMemory;
            while (takeRecord(&d.incoming)) |rec| {
                if (rec.kind != @intFromEnum(ths.HandshakeType.finished)) {
                    return conn_mod.Error.ProtocolViolation;
                }
                d.engine.verifyClientFinished(rec.msg) catch return conn_mod.Error.TlsDriverFailed;
                conn.state = .established;
                dropFront(&d.incoming, a, rec.msg.len);
                // Handshake confirmed: tell the client to open 1-RTT.
                const DoneB = struct {
                    pub fn build(gpa: Allocator, payload: *std.ArrayList(u8)) conn_mod.Error!void {
                        frames.encode(payload, gpa, .handshakeDone) catch
                            return conn_mod.Error.OutOfMemory;
                    }
                };
                try conn.sendFrames(.application, DoneB.build, nowMs);
            }
            return;
        }
        d.incoming.appendSlice(a, data) catch return conn_mod.Error.OutOfMemory;
        const rec = takeRecord(&d.incoming) orelse return;
        if (rec.kind != @intFromEnum(ths.HandshakeType.client_hello)) return conn_mod.Error.ProtocolViolation;
        const ch_msg = rec.msg;
        d.engine.processClientHello(ch_msg) catch return conn_mod.Error.TlsDriverFailed;
        const client_alpn = parseOfferedAlpn(a, ch_msg[4..]) catch return conn_mod.Error.TlsDriverFailed;
        defer {
            for (client_alpn) |s| a.free(s);
            a.free(client_alpn);
        }
        // RFC 9001 Section 7.4: no overlap means no_application_protocol
        // (120, application close 0x178), not a silent stall. The client
        // maps the close to its alpn_mismatch detail.
        var offers_h3 = false;
        for (client_alpn) |proto| {
            if (std.mem.eql(u8, proto, "h3")) {
                offers_h3 = true;
                break;
            }
        }
        if (!offers_h3) {
            d.detail = .alpn_mismatch;
            // Transport close (0x1C) on the Initial space: Initial keys
            // are installed (acceptInitial ran) while application keys
            // never exist at this point, and a 0x1D application close is
            // forbidden before 1-RTT. Best effort: the driver error
            // below is the backstop.
            conn.queueControlFrame(.{ .connectionClose = .{
                .errorCode = 0x178,
                .triggeringFrameType = 0,
                .reason = "no application protocol",
                .application = false,
            } }) catch {};
            conn.flushControl(.initial, nowMs) catch {};
            return conn_mod.Error.TlsDriverFailed;
        }
        // Apply the client's transport parameters before sending ours.
        if (d.engine.peerQuicTransportParams) |tp| {
            applyPeerTransportParams(conn, tp, true) catch {
                d.detail = .handshake_failed;
                return conn_mod.Error.TlsDriverFailed;
            };
        }
        const local_tp = buildLocalTransportParams(a, conn) catch
            return conn_mod.Error.OutOfMemory;
        defer a.free(local_tp);
        var flight = d.engine.produceServerFlight(ch_msg[4..], d.cert_chain_pem, d.private_key_pem, &.{.h3}, client_alpn, local_tp) catch
            return conn_mod.Error.TlsDriverFailed;
        defer flight.deinit(a);

        d.flight.appendSlice(a, flight.serverHello) catch return conn_mod.Error.OutOfMemory;
        d.flight.appendSlice(a, flight.encryptedExtensions) catch return conn_mod.Error.OutOfMemory;
        d.flight.appendSlice(a, flight.certificate) catch return conn_mod.Error.OutOfMemory;
        d.flight.appendSlice(a, flight.certificateVerify) catch return conn_mod.Error.OutOfMemory;
        d.flight.appendSlice(a, flight.finished) catch return conn_mod.Error.OutOfMemory;

        const shared = d.engine.sharedSecret orelse return conn_mod.Error.TlsDriverFailed;
        const hs = qtls.handshakeKeys(shared, flight.hsHash);
        // LevelKeys are client-oriented (tx = client); mirror them.
        try conn.installKeys(.handshake, hs.keys.rxSecret, hs.keys.txSecret);

        // ServerHello leaves in an Initial packet (RFC 9001 4.1 pattern);
        // EE..Finished follow in Handshake packets.
        _ = conn.queueCrypto(.initial, flight.serverHello) catch return conn_mod.Error.TlsDriverFailed;
        try sendQueued(conn, .initial, nowMs);
        _ = conn.queueCrypto(.handshake, flight.encryptedExtensions) catch return conn_mod.Error.TlsDriverFailed;
        _ = conn.queueCrypto(.handshake, flight.certificate) catch return conn_mod.Error.TlsDriverFailed;
        _ = conn.queueCrypto(.handshake, flight.certificateVerify) catch return conn_mod.Error.TlsDriverFailed;
        _ = conn.queueCrypto(.handshake, flight.finished) catch return conn_mod.Error.TlsDriverFailed;
        try sendQueued(conn, .handshake, nowMs);

        const ch_sf = flight.sfHash;
        const ap = qtls.applicationKeys(hs.hsSecret, ch_sf);
        try conn.installKeys(.application, ap.keys.rxSecret, ap.keys.txSecret);

        // Consume the hello only after its last use above: `incoming` is
        // reused for the post-flight Finished, and stale bytes would
        // poison its record parser. (Dropping earlier would invalidate
        // `ch_msg`, which borrows this buffer.)
        dropFront(&d.incoming, a, rec.msg.len);

        // An authentic ClientHello validates return routability on
        // loopback; open-internet deployments must gate amplification
        // on Retry/token instead (see module docs).
        conn.addressValidated = true;
        d.flight_done = true;
    }

    /// std.Io for trust-store time/random. Connections are driven by an
    /// Endpoint that owns io; threaded global io matches everywhere the
    /// TCP client uses it.
    fn connIo(conn: *Connection) std.Io {
        _ = conn;
        return std.Io.Threaded.global_single_threaded.io();
    }
};

/// Extracts offered ALPN protocols from a ClientHello body (owned strings).
fn parseOfferedAlpn(a: Allocator, body: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).empty;
    errdefer {
        for (out.items) |s| a.free(s);
        out.deinit(a);
    }
    if (body.len < 34) return out.toOwnedSlice(a);
    var pos: usize = 34;
    if (pos + 1 > body.len) return out.toOwnedSlice(a);
    pos += 1 + body[pos];
    if (pos + 2 > body.len) return out.toOwnedSlice(a);
    const cs_len: usize = (@as(usize, body[pos]) << 8) | body[pos + 1];
    pos += 2 + cs_len;
    if (pos + 1 > body.len) return out.toOwnedSlice(a);
    pos += 1 + body[pos];
    if (pos + 2 > body.len) return out.toOwnedSlice(a);
    const ext_len: usize = (@as(usize, body[pos]) << 8) | body[pos + 1];
    pos += 2;
    const ext_end = @min(body.len, pos + ext_len);
    const alpn_type: u16 = 16; // application_layer_protocol_negotiation
    while (pos + 4 <= ext_end) {
        const t = std.mem.readInt(u16, body[pos..][0..2], .big);
        const l: usize = (@as(usize, body[pos + 2]) << 8) | body[pos + 3];
        pos += 4;
        if (pos + l > ext_end) break;
        if (t == alpn_type) {
            const data = body[pos..][0..l];
            if (data.len >= 2) {
                const list_len: usize = (@as(usize, data[0]) << 8) | data[1];
                var p: usize = 2;
                const list_end = @min(data.len, 2 + list_len);
                while (p < list_end) {
                    const n: usize = data[p];
                    p += 1;
                    if (p + n > list_end) break;
                    try out.append(a, try a.dupe(u8, data[p..][0..n]));
                    p += n;
                }
            }
        }
        pos += l;
    }
    return out.toOwnedSlice(a);
}

/// Feeds one pumped datagram into `ep` (if any arrived) and flushes
/// queued output. `dest` overrides the learned peer (client's first
/// flight); null flushes to the peer.
/// The flush is UNCONDITIONAL (even with no inbound datagram): queued
/// flights must reach the wire without waiting for peer traffic first,
/// or both sides idle forever. Pumps NEVER block: the reader thread
/// owns all waiting, so this is purely feed + flush on the owner thread.
pub fn feedPumped(
    ep: *Endpoint,
    pump: *transport_mod.Pump,
    dest: ?std.Io.net.IpAddress,
    quantumMs: u64,
    nowMs: u64,
) !void {
    if (try pump.next(quantumMs)) |d| {
        // Free with the PUMP's allocator (it duped these bytes) — never
        // the connection's: the two are independently chosen and mixing
        // them corrupts the heap.
        defer pump.allocator.free(d.data);
        ep.peer = d.from;
        ep.conn.receiveDatagram(d.data, nowMs) catch |e| switch (e) {
            error.Draining => return e,
            else => {}, // drop bad datagrams, keep going
        };
    }
    // Loss and PTO timers fire here so every pump-driven runtime (client
    // transport, server loops, tests) gets retransmission without extra
    // plumbing. Best-effort like receives: only death propagates.
    ep.conn.pollTimeouts(nowMs) catch |e| switch (e) {
        error.Draining, error.ConnectionClosed => return e,
        else => {},
    };
    if (dest) |dst| {
        _ = ep.flush(dst) catch 0;
    } else {
        _ = ep.flush(null) catch 0;
    }
}

/// Server side of a live handshake over an already-started pump:
/// bootstraps Initial keys from the first datagram's DCID, then pumps
/// until `.established` (client Finished verified) or the deadline
/// passes. `driver` (nullable) is polled for fast failure. The pump is
/// NOT stopped here — the caller owns its lifetime (handshake, then
/// request exchange, then stop).
pub fn serveHandshake(server_ep: *Endpoint, pump: *transport_mod.Pump, driver: ?*Driver, deadlineMs: u64) !void {
    const a = server_ep.conn.allocator;
    const start: u64 = @intCast(clock_mod.millisNow());
    var booted = false;
    while (true) {
        const now: u64 = @intCast(clock_mod.millisNow());
        if (now -| start > deadlineMs) return error.HandshakeTimeout;
        // Driver-doomed handshakes fail fast with a mappable error (the
        // precise cause stays on `driver.detail`); only the truly quiet
        // peer burns the deadline.
        if (driver) |d| {
            if (d.failed) return error.HandshakeFailed;
        }
        const remain = deadlineMs -| (now -| start);
        if (!booted) {
            const d = try pump.next(@min(remain, 1000)) orelse continue;
            defer a.free(d.data);
            const parsed = packet_mod.parseLongHeader(d.data) catch continue;
            if (parsed.header.type != .initial) continue;
            server_ep.peer = d.from;
            try server_ep.conn.acceptInitial(parsed.header.dcid);
            server_ep.conn.receiveDatagram(d.data, now) catch continue;
            booted = true;
            continue;
        }
        try feedPumped(server_ep, pump, null, @min(remain, 1000), now);
        if (server_ep.conn.state == .established) return;
    }
}

const hs_test_cert_pem = @embedFile("../tls/testdata/localhost_cert.pem");
const hs_test_key_pem = @embedFile("../tls/testdata/localhost_key.pem");

test "live handshake over real udp loopback establishes both ends" {
    const a = std.testing.allocator;
    var ctx = @import("../../sockets/tcp.zig").IoContext.init(a) catch return;
    defer ctx.deinit();

    var cli_conn = try conn_mod.Connection.init(a, .client, .{}, 0x4311);
    defer cli_conn.deinit();
    var srv_conn = try conn_mod.Connection.init(a, .server, .{}, 0x4312);
    defer srv_conn.deinit();

    var cli_ep = try transport_mod.Endpoint.init(a, ctx.io, cli_conn);
    defer cli_ep.deinit();
    var srv_ep = try transport_mod.Endpoint.initPort(a, ctx.io, srv_conn, 0);
    defer srv_ep.deinit();
    const sport = srv_ep.localPort();

    var cli_drv = Driver.initClient(a, .{ .host = "127.0.0.1", .caPem = hs_test_cert_pem });
    defer cli_drv.deinit();
    var srv_drv = Driver.initServer(a, .{ .certChainPem = hs_test_cert_pem, .privateKeyPem = hs_test_key_pem });
    defer srv_drv.deinit();
    cli_conn.tls = .{ .ctx = &cli_drv, .start = Driver.clientStart, .onData = Driver.onData };
    srv_conn.tls = .{ .ctx = &srv_drv, .start = Driver.clientStart, .onData = Driver.onData };

    var cli_pump: transport_mod.Pump = undefined;
    try cli_pump.start(&cli_ep, a);
    defer cli_pump.stop();
    var srv_pump: transport_mod.Pump = undefined;
    try srv_pump.start(&srv_ep, a);
    defer srv_pump.stop();

    const dest = std.Io.net.IpAddress.parseIp4("127.0.0.1", sport) catch unreachable;
    try performHandshake(&cli_ep, &cli_pump, &cli_drv, &srv_ep, &srv_pump, &srv_drv, dest, 15_000);
    try std.testing.expectEqual(conn_mod.State.established, cli_conn.state);
    try std.testing.expectEqual(conn_mod.State.established, srv_conn.state);
    // ALPN h3 was negotiated through the real TLS flight.
    try std.testing.expectEqualStrings("h3", cli_drv.engine.negotiatedAlpn.?);
    try std.testing.expectEqualStrings("h3", srv_drv.engine.negotiatedAlpn.?);
}

/// Drives a client handshake to completion. `client_pump` must be
/// started; with `server_ep`/`server_pump` set, an in-process peer is
/// co-pumped (loopback), otherwise only our side pumps against `dest`
/// (external peer). `client_driver` (nullable) is polled for fast
/// failure with a mappable cause. No pump is stopped here — lifetimes
/// stay with the caller. Returns when our side reaches `.established`
/// (and the peer confirms, when co-pumped).
pub fn performHandshake(
    client_ep: *Endpoint,
    client_pump: *transport_mod.Pump,
    client_driver: ?*Driver,
    server_ep: ?*Endpoint,
    server_pump: ?*transport_mod.Pump,
    server_driver: ?*Driver,
    dest: std.Io.net.IpAddress,
    deadlineMs: u64,
) !void {
    const start: u64 = @intCast(clock_mod.millisNow());
    try client_ep.conn.startHandshake(start);
    _ = try client_ep.flush(dest);
    var server_booted = server_ep == null;
    while (true) {
        const now: u64 = @intCast(clock_mod.millisNow());
        if (now -| start > deadlineMs) return error.HandshakeTimeout;
        if (client_driver) |d| {
            if (d.failed) return error.HandshakeFailed;
        }
        if (server_driver) |d| {
            if (d.failed) return error.HandshakeFailed;
        }
        const remain = deadlineMs -| (now -| start);
        if (server_ep) |sep| {
            const spump = server_pump orelse return error.HandshakeTimeout;
            if (!server_booted) {
                const d = try spump.next(@min(remain, 1000)) orelse continue;
                defer spump.allocator.free(d.data);
                const parsed = packet_mod.parseLongHeader(d.data) catch continue;
                if (parsed.header.type != .initial) continue;
                sep.peer = d.from;
                try sep.conn.acceptInitial(parsed.header.dcid);
                sep.conn.receiveDatagram(d.data, now) catch continue;
                server_booted = true;
                continue;
            }
            try feedPumped(sep, spump, null, @min(remain, 1000), now);
        }
        try feedPumped(client_ep, client_pump, dest, @min(remain, 1000), now);
        if (client_ep.conn.state == .established) {
            if (server_ep) |sep| {
                if (sep.conn.state == .established) return;
            } else {
                return;
            }
        }
    }
}
test "peer transport parameters apply to connection windows" {
    const a = std.testing.allocator;
    var conn = try conn_mod.Connection.init(a, .client, .{}, 0x7771);
    defer conn.deinit();

    const putCid = struct {
        fn f(out: *std.ArrayList(u8), gpa: Allocator, id: u64, v: []const u8) !void {
            var vb: [8]u8 = undefined;
            var n = try quic_varint.encode(&vb, id);
            try out.appendSlice(gpa, vb[0..n]);
            n = try quic_varint.encode(&vb, v.len);
            try out.appendSlice(gpa, vb[0..n]);
            try out.appendSlice(gpa, v);
        }
    }.f;

    var p = params_mod.Params{};
    p.initialMaxData = 2 << 20;
    p.initialMaxStreamDataBidiLocal = 1 << 20;
    p.initialMaxStreamDataBidiRemote = 512 << 10;
    p.initialMaxStreamDataUni = 256 << 10;
    p.initialMaxStreamsBidi = 64;
    p.initialMaxStreamsUni = 8;
    p.maxAckDelayMs = 42;

    const fake_iscid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04 };
    const wrong_cid = [_]u8{0x11} ** 8;

    // Server first flight: odcid echoes our original DCID.
    var block = std.ArrayList(u8).empty;
    defer block.deinit(a);
    try params_mod.encode(&block, a, p);
    try putCid(&block, a, 0x00, conn.origDcid[0..conn.origDcidLen]);
    try putCid(&block, a, 0x0F, &fake_iscid);

    try Driver.applyPeerTransportParams(conn, block.items, false);
    try std.testing.expectEqual(@as(u64, 2 << 20), conn.maxDataRemote);
    // Bidi send window is the tighter of the peer local/remote limits.
    try std.testing.expectEqual(@as(u64, 512 << 10), conn.sendWindowBidi);
    try std.testing.expectEqual(@as(u64, 256 << 10), conn.sendWindowUni);
    try std.testing.expectEqual(@as(u64, 64), conn.maxStreamsBidiRemote);
    try std.testing.expectEqual(@as(u64, 8), conn.maxStreamsUniRemote);
    try std.testing.expectEqual(@as(u64, 42), conn.recovery.cfg.maxAckDelayMs);
    try std.testing.expect(conn.peerParams != null);

    // The server path takes a block WITHOUT odcid (servers send it,
    // they never receive it) and rejects one that carries it.
    var srv_block = std.ArrayList(u8).empty;
    defer srv_block.deinit(a);
    try params_mod.encode(&srv_block, a, p);
    try putCid(&srv_block, a, 0x0F, &fake_iscid);
    try Driver.applyPeerTransportParams(conn, srv_block.items, true);
    try std.testing.expectError(
        conn_mod.Error.TransportParameterError,
        Driver.applyPeerTransportParams(conn, block.items, true),
    );

    // A forged original_destination_connection_id is rejected.
    var bad = std.ArrayList(u8).empty;
    defer bad.deinit(a);
    try params_mod.encode(&bad, a, p);
    try putCid(&bad, a, 0x00, &wrong_cid);
    try putCid(&bad, a, 0x0F, &fake_iscid);
    try std.testing.expectError(
        conn_mod.Error.TransportParameterError,
        Driver.applyPeerTransportParams(conn, bad.items, false),
    );

    // A retry_source_connection_id without a Retry is rejected.
    var rsc = std.ArrayList(u8).empty;
    defer rsc.deinit(a);
    try params_mod.encode(&rsc, a, p);
    try putCid(&rsc, a, 0x00, conn.origDcid[0..conn.origDcidLen]);
    try putCid(&rsc, a, 0x0F, &fake_iscid);
    try putCid(&rsc, a, 0x10, &wrong_cid);
    try std.testing.expectError(
        conn_mod.Error.TransportParameterError,
        Driver.applyPeerTransportParams(conn, rsc.items, false),
    );
}

test "server closes unknown alpn with no_application_protocol" {
    const a = std.testing.allocator;
    var srv_conn = try conn_mod.Connection.init(a, .server, .{}, 0x7772);
    defer srv_conn.deinit();
    // Initial keys + validated address so the close packet can fly.
    try srv_conn.installInitialKeys();
    srv_conn.addressValidated = true;
    var srv_drv = Driver.initServer(a, .{ .certChainPem = hs_test_cert_pem, .privateKeyPem = hs_test_key_pem });
    defer srv_drv.deinit();
    srv_conn.tls = .{ .ctx = &srv_drv, .start = Driver.clientStart, .onData = Driver.onData };

    // A ClientHello offering only HTTP/1.1, no h3.
    var tmp = tls_engine.Engine.initClient(a, .{});
    defer tmp.deinit();
    const ch = try tmp.produceClientHelloWithSni(&.{"http/1.1"}, &.{}, "localhost", null);
    defer a.free(ch);

    const r = Driver.onData(&srv_drv, srv_conn, ch, 1000);
    try std.testing.expectError(conn_mod.Error.TlsDriverFailed, r);
    try std.testing.expect(srv_drv.failed);
    try std.testing.expectEqual(Detail.alpn_mismatch, srv_drv.detail);
    // RFC 9001 Section 7.4: a transport close 0x178 went out on the
    // Initial space (outbuf holds the datagram) and no TLS flight was
    // built for the rejected client.
    try std.testing.expect(srv_conn.outbuf.items.len > 0);
    try std.testing.expectEqual(@as(usize, 0), srv_drv.flight.items.len);
}
