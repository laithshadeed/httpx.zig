//! Thread-safe compiled template cache with dependency graph tracking.

const std = @import("std");
const Allocator = std.mem.Allocator;
const parserMod = @import("parser.zig");
pub const TemplateAst = parserMod.TemplateAst;

pub const CachedTemplate = struct {
    name: []const u8,
    ast: TemplateAst,
    source: []const u8,
};

/// An evicted entry awaiting safe release once no render references it.
pub const GarbageEntry = struct {
    name: []const u8,
    ast: TemplateAst,
    source: []const u8,
};

pub const CacheConfig = struct {
    enabled: bool = true,
    maxTemplates: usize = 1024,
};

const sync = @import("../../common/sync.zig");

pub const Cache = struct {
    allocator: Allocator,
    config: CacheConfig,
    lock: sync.Spinlock = .{},
    // map templateName -> CachedTemplate
    entries: std.StringHashMap(CachedTemplate),
    // map dependencyName -> list of dependents
    // e.g. "base.html" -> ["index.html", "about.html"]
    dependents: std.StringHashMap(std.ArrayList([]const u8)),
    /// Renders currently borrowing AST pointers. Evicted entries are
    /// parked in `garbage` (not freed) while this is nonzero, so a
    /// concurrent `invalidate`/`put` can never free an AST under an
    /// in-flight render. Drained when the last render ends.
    activeRenders: usize = 0,
    garbage: std.ArrayList(GarbageEntry) = .empty,

    pub fn init(allocator: Allocator, config: CacheConfig) Cache {
        return .{
            .allocator = allocator,
            .config = config,
            .entries = std.StringHashMap(CachedTemplate).init(allocator),
            .dependents = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    /// Marks a render as borrowing ASTs; pair with `endRender`.
    pub fn beginRender(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.activeRenders += 1;
    }

    /// Ends a render borrow, freeing parked entries when idle.
    pub fn endRender(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.activeRenders -= 1;
        if (self.activeRenders == 0) self.drainGarbageLocked();
    }

    fn freeEntry(self: *Cache, name: []const u8, ast: *TemplateAst, source: []const u8) void {
        self.allocator.free(name);
        self.allocator.free(source);
        ast.deinit();
    }

    fn retireLocked(self: *Cache, name: []const u8, ast: TemplateAst, source: []const u8) void {
        if (self.activeRenders > 0) {
            self.garbage.append(self.allocator, .{ .name = name, .ast = ast, .source = source }) catch {
                // OOM while parking: leak rather than use-after-free.
                return;
            };
            return;
        }
        var mutAst = ast;
        self.freeEntry(name, &mutAst, source);
    }

    fn drainGarbageLocked(self: *Cache) void {
        for (self.garbage.items) |*g| self.freeEntry(g.name, &g.ast, g.source);
        self.garbage.clearRetainingCapacity();
    }

    pub fn deinit(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.source);
            entry.value_ptr.ast.deinit();
        }
        self.entries.deinit();

        var depIt = self.dependents.iterator();
        while (depIt.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |dep| {
                self.allocator.free(dep);
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.dependents.deinit();

        for (self.garbage.items) |*g| self.freeEntry(g.name, &g.ast, g.source);
        self.garbage.deinit(self.allocator);
    }

    /// Looks up a compiled template AST by name. Caller must not retain pointer beyond cache lifetime.
    pub fn get(self: *Cache, name: []const u8) ?*const TemplateAst {
        if (!self.config.enabled) return null;

        self.lock.lock();
        defer self.lock.unlock();

        if (self.entries.getPtr(name)) |entry| {
            return &entry.ast;
        }
        return null;
    }

    /// Stores a compiled template AST and records its dependency relationships.
    pub fn put(
        self: *Cache,
        name: []const u8,
        source: []const u8,
        ast: TemplateAst,
    ) !void {
        if (!self.config.enabled) {
            var mutAst = ast;
            mutAst.deinit();
            self.allocator.free(source);
            return;
        }

        self.lock.lock();
        defer self.lock.unlock();

        // If existing entry, retire it first (parked while renders borrow it)
        if (self.entries.fetchRemove(name)) |kv| {
            self.retireLocked(kv.key, kv.value.ast, kv.value.source);
        }

        const ownedName = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(ownedName);

        try self.entries.put(ownedName, .{
            .name = ownedName,
            .ast = ast,
            .source = source,
        });

        // Track dependencies: if this template extends a parent or includes partials,
        // register this template as a dependent of those parent/partial templates.
        if (ast.extendsPath) |parent| {
            try self.addDependencyInternal(parent, name);
        }
        for (ast.includes) |inc| {
            try self.addDependencyInternal(inc, name);
        }
    }

    fn addDependencyInternal(self: *Cache, target: []const u8, dependent: []const u8) !void {
        const gop = try self.dependents.getOrPut(target);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, target);
            gop.value_ptr.* = std.ArrayList([]const u8).empty;
        }

        // Avoid duplicates
        for (gop.value_ptr.items) |existing| {
            if (std.mem.eql(u8, existing, dependent)) return;
        }

        const ownedDep = try self.allocator.dupe(u8, dependent);
        try gop.value_ptr.append(self.allocator, ownedDep);
    }

    /// Invalidates a template and recursively invalidates all templates that depend on it.
    pub fn invalidate(self: *Cache, name: []const u8) void {
        self.lock.lock();
        defer self.lock.unlock();

        self.invalidateRecursive(name);
    }

    fn invalidateRecursive(self: *Cache, name: []const u8) void {
        // Invalidate target
        if (self.entries.fetchRemove(name)) |kv| {
            self.retireLocked(kv.key, kv.value.ast, kv.value.source);
        }

        // Invalidate dependents
        if (self.dependents.get(name)) |depList| {
            for (depList.items) |dep| {
                self.invalidateRecursive(dep);
            }
        }
    }

    /// Invalidates all cached templates.
    pub fn invalidateAll(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.retireLocked(entry.key_ptr.*, entry.value_ptr.ast, entry.value_ptr.source);
        }
        self.entries.clearRetainingCapacity();
    }
};

test "Cache stores and invalidates with dependency tracking" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var cache = Cache.init(alloc, .{});
    defer cache.deinit();

    // Create a base template AST
    const baseSrc = try alloc.dupe(u8, "<html>{% block body %}{% endblock %}</html>");
    var baseParser = parserMod.Parser.init(alloc, "base.html", baseSrc);
    const baseAst = try baseParser.parse();
    try cache.put("base.html", baseSrc, baseAst);

    // Create a child template AST that extends base.html
    const childSrc = try alloc.dupe(u8, "{% extends \"base.html\" %}{% block body %}Hello{% endblock %}");
    var childParser = parserMod.Parser.init(alloc, "index.html", childSrc);
    const childAst = try childParser.parse();
    try cache.put("index.html", childSrc, childAst);

    try testing.expect(cache.get("base.html") != null);
    try testing.expect(cache.get("index.html") != null);

    // Invalidating base.html should also invalidate index.html!
    cache.invalidate("base.html");
    try testing.expect(cache.get("base.html") == null);
    try testing.expect(cache.get("index.html") == null);
}
