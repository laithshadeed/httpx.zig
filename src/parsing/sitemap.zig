//! Sitemap XML parser (sitemaps.org protocol 0.9).

const std = @import("std");
const Allocator = std.mem.Allocator;
const dom = @import("dom.zig");
const xml = @import("xml.zig");

pub const ChangeFreq = enum {
    always,
    hourly,
    daily,
    weekly,
    monthly,
    yearly,
    never,
    unknown,
};

pub const SitemapUrl = struct {
    loc: []const u8 = "",
    lastMod: []const u8 = "",
    changeFreq: ChangeFreq = .unknown,
    priority: ?f32 = null,
};

pub const Sitemap = struct {
    allocator: Allocator,
    isIndex: bool = false,
    urls: []SitemapUrl = &.{},
    sitemaps: [][]const u8 = &.{},

    pub fn deinit(self: *Sitemap) void {
        self.allocator.free(self.urls);
        self.allocator.free(self.sitemaps);
    }
};

pub fn parse(allocator: Allocator, src: []const u8) !Sitemap {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const al = arena.allocator();

    var tree = try xml.parse(al, src, .{});
    defer tree.deinit(al);

    var sitemapIndexNodes: std.ArrayList(u32) = .empty;
    try tree.getElementsByTag(al, 0, "sitemapindex", &sitemapIndexNodes);

    if (sitemapIndexNodes.items.len > 0) {
        var smList: std.ArrayList([]const u8) = .empty;
        var sitemaps: std.ArrayList(u32) = .empty;
        try tree.getElementsByTag(al, 0, "sitemap", &sitemaps);
        for (sitemaps.items) |sIdx| {
            var locNodes: std.ArrayList(u32) = .empty;
            try tree.getElementsByTag(al, sIdx, "loc", &locNodes);
            if (locNodes.items.len > 0) {
                const locText = getText(&tree, locNodes.items[0]);
                if (locText.len > 0) try smList.append(allocator, locText);
            }
        }
        return Sitemap{
            .allocator = allocator,
            .isIndex = true,
            .sitemaps = try smList.toOwnedSlice(allocator),
        };
    }

    var urlNodes: std.ArrayList(u32) = .empty;
    try tree.getElementsByTag(al, 0, "url", &urlNodes);

    var urls: std.ArrayList(SitemapUrl) = .empty;
    for (urlNodes.items) |uIdx| {
        var u = SitemapUrl{};
        var locs: std.ArrayList(u32) = .empty;
        try tree.getElementsByTag(al, uIdx, "loc", &locs);
        if (locs.items.len > 0) u.loc = getText(&tree, locs.items[0]);

        var mods: std.ArrayList(u32) = .empty;
        try tree.getElementsByTag(al, uIdx, "lastMod", &mods);
        if (mods.items.len > 0) u.lastMod = getText(&tree, mods.items[0]);

        var freqs: std.ArrayList(u32) = .empty;
        try tree.getElementsByTag(al, uIdx, "changeFreq", &freqs);
        if (freqs.items.len > 0) {
            const f = getText(&tree, freqs.items[0]);
            if (std.ascii.eqlIgnoreCase(f, "always")) u.changeFreq = .always else if (std.ascii.eqlIgnoreCase(f, "hourly")) u.changeFreq = .hourly else if (std.ascii.eqlIgnoreCase(f, "daily")) u.changeFreq = .daily else if (std.ascii.eqlIgnoreCase(f, "weekly")) u.changeFreq = .weekly else if (std.ascii.eqlIgnoreCase(f, "monthly")) u.changeFreq = .monthly else if (std.ascii.eqlIgnoreCase(f, "yearly")) u.changeFreq = .yearly else if (std.ascii.eqlIgnoreCase(f, "never")) u.changeFreq = .never;
        }

        var prios: std.ArrayList(u32) = .empty;
        try tree.getElementsByTag(al, uIdx, "priority", &prios);
        if (prios.items.len > 0) {
            const p = getText(&tree, prios.items[0]);
            if (std.fmt.parseFloat(f32, p)) |v| u.priority = v else |_| {}
        }

        try urls.append(allocator, u);
    }

    return Sitemap{
        .allocator = allocator,
        .isIndex = false,
        .urls = try urls.toOwnedSlice(allocator),
    };
}

fn getText(tree: *const dom.Tree, root: u32) []const u8 {
    var c = tree.get(root).firstChild;
    while (c != dom.NO_NODE) {
        const node = tree.get(c);
        if (node.kind == .text or node.kind == .cdata) {
            return std.mem.trim(u8, node.data, " \t\r\n");
        }
        c = node.nextSibling;
    }
    return "";
}
