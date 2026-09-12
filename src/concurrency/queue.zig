//! Bounded blocking MPMC (multi-producer, multi-consumer) task queue.
//!
//! Features:
//!   - Fixed-capacity circular ring buffer.
//!   - Blocking `push` and `pop` with backpressure and yield-based backoff.
//!   - Non-blocking `tryPush` and `tryPop`.
//!   - Deterministic and thread-safe `close()`: wakes all blocked producers and
//!     consumers, allowing queued items to be drained before consumers see `error.Closed`.
//!   - Zero memory allocations after initialization.
//!   - Thread-safe across multiple concurrent producers and consumers.

const std = @import("std");
const sync = @import("../common/sync.zig");

pub fn BoundedQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        mu: sync.Spinlock = .{},
        space: sync.Semaphore,
        itemsAvail: sync.Semaphore,
        buf: []T,
        head: usize = 0, // pop index
        tail: usize = 0, // push index
        len: usize = 0,
        closed: bool = false,
        allocator: std.mem.Allocator,

        /// Initializes a bounded queue with fixed capacity.
        pub fn init(allocator: std.mem.Allocator, capSize: usize) !Self {
            const cap = @max(1, capSize);
            const buf = try allocator.alloc(T, cap);
            return .{
                .space = sync.Semaphore.init(@intCast(cap)),
                .itemsAvail = sync.Semaphore.init(0),
                .buf = buf,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.allocator.free(self.buf);
        }

        /// Blocks when full until space is available or the queue is closed.
        pub fn push(self: *Self, item: T) error{Closed}!void {
            while (true) {
                if (self.isClosed()) return error.Closed;
                if (self.space.tryWait()) {
                    self.mu.lock();
                    defer self.mu.unlock();
                    if (self.closed) {
                        self.space.post();
                        return error.Closed;
                    }
                    self.buf[self.tail % self.buf.len] = item;
                    self.tail +%= 1;
                    self.len += 1;
                    self.itemsAvail.post();
                    return;
                }
                std.Thread.yield() catch {};
            }
        }

        /// Non-blocking push. Returns `error.Full` if full or `error.Closed` if closed.
        pub fn tryPush(self: *Self, item: T) error{ Closed, Full }!void {
            self.mu.lock();
            defer self.mu.unlock();
            if (self.closed) return error.Closed;
            if (self.len == self.buf.len) return error.Full;
            _ = self.space.tryWait();
            self.buf[self.tail % self.buf.len] = item;
            self.tail +%= 1;
            self.len += 1;
            self.itemsAvail.post();
        }

        /// Blocks when empty. Returns queued items first (drain mode) and returns `error.Closed` once completely empty and closed.
        pub fn pop(self: *Self) error{Closed}!T {
            while (true) {
                if (self.itemsAvail.tryWait()) {
                    self.mu.lock();
                    if (self.len > 0) {
                        const item = self.buf[self.head % self.buf.len];
                        self.head +%= 1;
                        self.len -= 1;
                        self.mu.unlock();
                        self.space.post();
                        return item;
                    }
                    const closedFlag = self.closed;
                    self.mu.unlock();
                    if (closedFlag) return error.Closed;
                }
                self.mu.lock();
                const closedFlag = self.closed;
                const isEmpty = (self.len == 0);
                self.mu.unlock();
                if (closedFlag and isEmpty) return error.Closed;
                std.Thread.yield() catch {};
            }
        }

        /// Non-blocking pop. Returns `null` if the queue is currently empty.
        pub fn tryPop(self: *Self) ?T {
            self.mu.lock();
            defer self.mu.unlock();
            if (self.len == 0) return null;
            _ = self.itemsAvail.tryWait();
            const item = self.buf[self.head % self.buf.len];
            self.head +%= 1;
            self.len -= 1;
            self.space.post();
            return item;
        }

        /// Marks the queue as closed and wakes all blocked threads.
        pub fn close(self: *Self) void {
            self.mu.lock();
            const wasClosed = self.closed;
            self.closed = true;
            self.mu.unlock();

            if (!wasClosed) {
                var i: usize = 0;
                while (i < self.buf.len + 32) : (i += 1) {
                    self.itemsAvail.post();
                    self.space.post();
                }
            }
        }

        pub fn isClosed(self: *Self) bool {
            self.mu.lock();
            defer self.mu.unlock();
            return self.closed;
        }

        pub fn count(self: *Self) usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.len;
        }

        pub fn capacity(self: *Self) usize {
            return self.buf.len;
        }
    };
}

test "queue fifo order" {
    const Q = BoundedQueue(u32);
    var q = try Q.init(std.testing.allocator, 4);
    defer q.deinit();
    try q.push(1);
    try q.push(2);
    try q.push(3);
    try std.testing.expectEqual(@as(u32, 1), try q.pop());
    try q.push(4);
    try std.testing.expectEqual(@as(u32, 2), try q.pop());
    try std.testing.expectEqual(@as(u32, 3), try q.pop());
    try std.testing.expectEqual(@as(u32, 4), try q.pop());
}

test "queue tryPush rejects when full" {
    const Q = BoundedQueue(u8);
    var q = try Q.init(std.testing.allocator, 2);
    defer q.deinit();
    try q.tryPush(1);
    try q.tryPush(2);
    try std.testing.expectError(error.Full, q.tryPush(3));
    _ = try q.pop();
    try q.tryPush(3);
}

test "queue close wakes and reports closed" {
    const Q = BoundedQueue(u32);
    var q = try Q.init(std.testing.allocator, 2);
    defer q.deinit();
    q.close();
    try std.testing.expectError(error.Closed, q.push(1));
}

test "queue drained-then-closed pops fail" {
    const Q = BoundedQueue(u32);
    var q = try Q.init(std.testing.allocator, 2);
    defer q.deinit();
    try q.push(9);
    q.close();
    const item = try q.pop();
    try std.testing.expectEqual(@as(u32, 9), item);
    try std.testing.expectError(error.Closed, q.pop());
}

test "queue capacity 1 edge case" {
    const Q = BoundedQueue(u64);
    var q = try Q.init(std.testing.allocator, 1);
    defer q.deinit();
    try q.push(100);
    try std.testing.expectError(error.Full, q.tryPush(200));
    try std.testing.expectEqual(@as(u64, 100), try q.pop());
    try q.push(200);
    try std.testing.expectEqual(@as(u64, 200), try q.pop());
}

test "queue multi-threaded producer-consumer" {
    const Q = BoundedQueue(usize);
    var q = try Q.init(std.testing.allocator, 8);
    defer q.deinit();

    const Producer = struct {
        fn run(queue: *Q, startVal: usize, countVal: usize) void {
            var i: usize = 0;
            while (i < countVal) : (i += 1) {
                queue.push(startVal + i) catch return;
            }
        }
    };

    const Consumer = struct {
        fn run(queue: *Q, totalRecv: *std.atomic.Value(usize), expected: usize) void {
            while (totalRecv.load(.monotonic) < expected) {
                _ = queue.pop() catch break;
                _ = totalRecv.fetchAdd(1, .monotonic);
            }
        }
    };

    var totalRecv = std.atomic.Value(usize).init(0);
    const totalItems: usize = 50;

    const t1 = try std.Thread.spawn(.{}, Producer.run, .{ &q, 0, 25 });
    const t2 = try std.Thread.spawn(.{}, Producer.run, .{ &q, 25, 25 });
    const c1 = try std.Thread.spawn(.{}, Consumer.run, .{ &q, &totalRecv, totalItems });
    const c2 = try std.Thread.spawn(.{}, Consumer.run, .{ &q, &totalRecv, totalItems });

    t1.join();
    t2.join();
    q.close();
    c1.join();
    c2.join();

    try std.testing.expectEqual(totalItems, totalRecv.load(.monotonic));
}
