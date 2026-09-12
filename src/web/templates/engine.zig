//! Template engine owner and orchestrator.
//!
//! Owns configuration, loader, cache, compiler, and renderer.
//! Reusable and concurrency-safe across multiple HTTP requests.

const std = @import("std");
const Allocator = std.mem.Allocator;
const loaderMod = @import("loader.zig");
const cacheMod = @import("cache.zig");
const parserMod = @import("parser.zig");
const rendererMod = @import("renderer.zig");
const contextMod = @import("context.zig");
const errMod = @import("error.zig");

const sync = @import("../../common/sync.zig");

pub const Config = struct {
    enabled: bool = true,
    directory: []const u8 = "templates",
    enableCache: bool = true,
    maxTemplates: usize = 1024,
    maxFileSize: usize = 10 * 1024 * 1024,
    maxIncludeDepth: usize = 32,
    maxInheritanceDepth: usize = 16,
    /// When true, rendering an undefined value fails instead of emitting empty.
    strictUndefined: bool = false,
};

pub const Engine = struct {
    allocator: Allocator,
    io: std.Io,
    config: Config,
    loader: loaderMod.Loader,
    cache: cacheMod.Cache,
    renderer: rendererMod.Renderer,
    filters: rendererMod.FilterRegistry,
    globals: rendererMod.GlobalMap,
    lock: sync.Spinlock = .{},
    lastError: ?errMod.SourceError = null,
    /// Scratch AST for cache-disabled mode: getOrCompile parses fresh on
    /// every call and owns the result here (previous entry freed first),
    /// so rendering works with enableCache=false instead of TemplateNotFound.
    scratchAst: ?parserMod.TemplateAst = null,
    scratchSource: ?[]u8 = null,

    pub fn init(allocator: Allocator, io: std.Io, config: Config) !Engine {
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .loader = loaderMod.Loader.init(.{
                .directory = config.directory,
                .maxFileSize = config.maxFileSize,
            }),
            .cache = cacheMod.Cache.init(allocator, .{
                .enabled = config.enableCache,
                .maxTemplates = config.maxTemplates,
            }),
            .renderer = rendererMod.Renderer{
                .options = .{
                    .maxIncludeDepth = config.maxIncludeDepth,
                    .maxInheritanceDepth = config.maxInheritanceDepth,
                    .strictUndefined = config.strictUndefined,
                },
            },
            .filters = rendererMod.FilterRegistry.init(allocator),
            .globals = rendererMod.GlobalMap.init(allocator),
        };
    }

    pub fn deinit(self: *Engine) void {
        if (self.scratchAst) |*ast| ast.deinit();
        if (self.scratchSource) |s| self.allocator.free(s);
        self.cache.deinit();
        self.filters.deinit();
        self.globals.deinit();
    }

    /// Registers a custom filter for `{{ value|name }}` pipelines.
    /// Register before rendering; builtins remain available as fallback.
    pub fn registerFilter(self: *Engine, name: []const u8, func: rendererMod.FilterFn) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.filters.register(name, func);
    }

    /// Registers a global callable for `{{ name(args) }}` expressions.
    /// `userData` is passed through on every call (e.g. a router pointer
    /// for `urlFor`); it must outlive the engine. Macros and the `range`
    /// builtin take precedence at call sites.
    pub fn addGlobal(self: *Engine, name: []const u8, func: rendererMod.GlobalFn, userData: ?*const anyopaque) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.globals.map.put(name, .{ .func = func, .userData = userData });
    }

    /// Provides AST lookup for includes and inheritance.
    pub fn provider(self: *Engine) rendererMod.TemplateProvider {
        return .{
            .ptr = @ptrCast(self),
            .getAstFn = getAstCallback,
        };
    }

    fn getAstCallback(ptr: *const anyopaque, name: []const u8) ?*const parserMod.TemplateAst {
        const self: *Engine = @ptrCast(@alignCast(@constCast(ptr)));
        return self.getOrCompile(name) catch null;
    }

    /// Compiles a template or retrieves it from cache.
    /// With enableCache=false, parses fresh on every call into an owned
    /// scratch slot (previous scratch freed), so callers always get a valid AST.
    pub fn getOrCompile(self: *Engine, name: []const u8) !*const parserMod.TemplateAst {
        if (!self.config.enableCache) {
            self.lock.lock();
            defer self.lock.unlock();
            if (self.scratchAst) |*ast| ast.deinit();
            if (self.scratchSource) |s| self.allocator.free(s);
            self.scratchAst = null;
            self.scratchSource = null;
            const source = try self.loader.load(self.allocator, name);
            errdefer self.allocator.free(source);
            var parser = parserMod.Parser.init(self.allocator, name, source);
            const ast = parser.parse() catch |err| {
                if (parser.lastError) |diag| self.lastError = diag;
                self.allocator.free(source);
                return err;
            };
            self.scratchSource = source;
            self.scratchAst = ast;
            return &self.scratchAst.?;
        }
        if (self.cache.get(name)) |cached| {
            return cached;
        }

        const source = try self.loader.load(self.allocator, name);
        errdefer self.allocator.free(source);

        var parser = parserMod.Parser.init(self.allocator, name, source);
        const ast = parser.parse() catch |err| {
            if (parser.lastError) |diag| {
                self.lastError = diag;
            }
            return err;
        };

        try self.cache.put(name, source, ast);

        // Preload any extends parent
        if (ast.extendsPath) |parent| {
            _ = self.getOrCompile(parent) catch {};
        }

        // Preload any includes
        for (ast.includes) |inc| {
            _ = self.getOrCompile(inc) catch {};
        }

        return self.cache.get(name) orelse error.TemplateNotFound;
    }

    /// Renders a template directly into a writer using arbitrary Zig data.
    pub fn render(
        self: *Engine,
        name: []const u8,
        data: anytype,
        writer: anytype,
    ) !void {
        const ast = try self.getOrCompile(name);

        var ctx = try contextMod.Context.init(self.allocator, data);
        defer ctx.deinit();

        var renderer = self.renderer;
        renderer.filters = &self.filters;
        renderer.globals = &self.globals;
        try renderer.render(ast, &ctx, self.provider(), writer);
    }

    /// Renders a template to an allocated string.
    pub fn renderToString(
        self: *Engine,
        allocator: Allocator,
        name: []const u8,
        data: anytype,
    ) ![]u8 {
        var list = std.ArrayList(u8).empty;
        errdefer list.deinit(allocator);
        var lw = rendererMod.ListWriter{ .list = &list, .allocator = allocator };
        try self.render(name, data, &lw);
        return try list.toOwnedSlice(allocator);
    }

    /// Compiles template directly from in-memory string (useful for testing or inline templates).
    pub fn renderString(
        self: *Engine,
        source: []const u8,
        data: anytype,
        writer: anytype,
    ) !void {
        var parser = parserMod.Parser.init(self.allocator, "<inline>", source);
        var ast = try parser.parse();
        defer ast.deinit();

        var ctx = try contextMod.Context.init(self.allocator, data);
        defer ctx.deinit();

        var renderer = self.renderer;
        renderer.filters = &self.filters;
        renderer.globals = &self.globals;
        try renderer.render(&ast, &ctx, self.provider(), writer);
    }

    /// Invalidate a template and all its dependents when a watched file changes.
    pub fn invalidate(self: *Engine, path: []const u8) void {
        // Strip template directory prefix if present
        var relName = path;
        if (std.mem.startsWith(u8, path, self.config.directory)) {
            relName = path[self.config.directory.len..];
            if (relName.len > 0 and (relName[0] == '/' or relName[0] == '\\')) {
                relName = relName[1..];
            }
        }

        // Normalize backslashes to forward slashes for cross-platform lookup
        var normBuf: [256]u8 = undefined;
        var normName = relName;
        if (relName.len <= normBuf.len) {
            @memcpy(normBuf[0..relName.len], relName);
            for (normBuf[0..relName.len]) |*b| {
                if (b.* == '\\') b.* = '/';
            }
            normName = normBuf[0..relName.len];
        }

        self.cache.invalidate(normName);
        if (!std.mem.eql(u8, normName, relName)) {
            self.cache.invalidate(relName);
        }
    }
};

test "Engine cache-disabled still renders" {
    const testing = std.testing;
    const alloc = testing.allocator;
    const fsMod = @import("../../utils/fs.zig");

    // Filesystem-backed template (no global embedded registry, which is
    // process-lifetime and would leak under the test allocator).
    const dir = "test_nocache_templates.tmp";
    const tplPath = dir ++ "/hello.html";
    {
        var tmp: [512]u8 = undefined;
        @memcpy(tmp[0..dir.len], dir);
        tmp[dir.len] = 0;
        _ = std.c.mkdir(tmp[0..dir.len :0], 0o755);
    }
    defer {
        fsMod.deleteFile(tplPath) catch {};
        var tmp: [512]u8 = undefined;
        @memcpy(tmp[0..dir.len], dir);
        tmp[dir.len] = 0;
        _ = std.c.rmdir(tmp[0..dir.len :0]);
    }
    try fsMod.writeFile(tplPath, "<h1>{{ title }}</h1>");

    var engine = try Engine.init(alloc, undefined, .{ .directory = dir, .enableCache = false });
    defer engine.deinit();

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    var lw = rendererMod.ListWriter{ .list = &list, .allocator = alloc };
    try engine.render("hello.html", .{ .title = "Hi" }, &lw);
    try testing.expect(std.mem.indexOf(u8, list.items, "<h1>Hi</h1>") != null);

    // Second render must work too (scratch slot recycled, no TemplateNotFound).
    list.clearRetainingCapacity();
    try engine.render("hello.html", .{ .title = "Again" }, &lw);
    try testing.expect(std.mem.indexOf(u8, list.items, "<h1>Again</h1>") != null);
}

test "Engine renders safely under concurrent load" {
    const testing = std.testing;
    const alloc = testing.allocator;
    var engine = try Engine.init(alloc, undefined, .{});
    defer engine.deinit();

    const src = "<h1>{{ title }}</h1>{% for item in items %}<span>{{ item }}</span>{% endfor %}";
    const Worker = struct {
        fn run(eng: *Engine, out: *?[]const u8) void {
            var list = std.ArrayList(u8).empty;
            defer list.deinit(std.testing.allocator);
            var lw = rendererMod.ListWriter{ .list = &list, .allocator = std.testing.allocator };
            eng.renderString(src, .{ .title = "T", .items = [_][]const u8{ "a", "b" } }, &lw) catch {
                out.* = null;
                return;
            };
            out.* = std.testing.allocator.dupe(u8, list.items) catch null;
        }
    };
    var outs: [8]?[]const u8 = .{null} ** 8;
    defer for (outs) |o| {
        if (o) |s| alloc.free(s);
    };
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &engine, &outs[i] });
    for (&threads) |*t| t.join();
    for (outs) |o| {
        try testing.expect(o != null);
        try testing.expect(std.mem.indexOf(u8, o.?, "<h1>T</h1>") != null);
        try testing.expect(std.mem.indexOf(u8, o.?, "<span>b</span>") != null);
    }
}

test "Engine custom globals resolve in expressions" {
    const testing = std.testing;
    const alloc = testing.allocator;
    const double = struct {
        fn f(_: ?*const anyopaque, _: Allocator, args: []const contextMod.Value, kwargs: []const rendererMod.GlobalKwarg) anyerror!contextMod.Value {
            _ = kwargs;
            if (args.len != 1 or args[0] != .integer) return .nullVal;
            return .{ .integer = args[0].integer * 2 };
        }
    }.f;

    var engine = try Engine.init(alloc, undefined, .{});
    defer engine.deinit();
    try engine.addGlobal("double", double, null);

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    var lw = rendererMod.ListWriter{ .list = &list, .allocator = alloc };
    try engine.renderString("{{ double(21) }}", .{}, &lw);
    try testing.expectEqualStrings("42", list.items);
}

test "Engine strictUndefined config fails on missing output" {
    const testing = std.testing;
    const alloc = testing.allocator;
    var engine = try Engine.init(alloc, undefined, .{ .strictUndefined = true });
    defer engine.deinit();
    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    var lw = rendererMod.ListWriter{ .list = &list, .allocator = alloc };
    try testing.expectError(error.UnknownVariable, engine.renderString("{{ nope }}", .{}, &lw));
    list.clearRetainingCapacity();
    try engine.renderString("{{ nope|default(\"ok\") }}", .{}, &lw);
    try testing.expectEqualStrings("ok", list.items);
}

test "Engine in-memory rendering and context evaluation" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var engine = try Engine.init(alloc, undefined, .{});
    defer engine.deinit();

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);

    const src =
        \\<h1>{{ title }}</h1>
        \\{% for item in items %}
        \\<span>{{ item }}</span>
        \\{% endfor %}
    ;

    var lw = rendererMod.ListWriter{ .list = &list, .allocator = alloc };
    try engine.renderString(src, .{
        .title = "Hello HTTPX",
        .items = [_][]const u8{ "A", "B" },
    }, &lw);

    const out = list.items;
    try testing.expect(std.mem.indexOf(u8, out, "<h1>Hello HTTPX</h1>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<span>A</span>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<span>B</span>") != null);
}
