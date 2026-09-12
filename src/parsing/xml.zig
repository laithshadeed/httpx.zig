//! XML parser with a Tree-sitter structural foundation.
//!
//! The Tree-sitter XML grammar below tokenizes source into tags, text,
//! comments, CDATA, and processing instructions. The DOM builder consumes
//! those syntax nodes directly, preserving tag case and namespaces.
//! Parses XML into a dom.Tree. Preserves tag case and CDATA sections.

const std = @import("std");
const Allocator = std.mem.Allocator;
const dom = @import("dom.zig");
const ts = @import("treesitter");
const Tree = dom.Tree;
const Attribute = dom.Attribute;

pub const XmlTree = ts.Tree;
pub const XmlNode = ts.Node;

const xmlSymEnd: u16 = 0;
const xmlSymOpenTag: u16 = 1;
const xmlSymCloseTag: u16 = 2;
const xmlSymSelfcloseTag: u16 = 3;
const xmlSymComment: u16 = 4;
const xmlSymCdata: u16 = 5;
const xmlSymPi: u16 = 6;
const xmlSymDoctype: u16 = 7;
const xmlSymText: u16 = 8;
const xmlSymProgram: u16 = 9;
const xmlSymNodes: u16 = 10;
const xmlSymNode: u16 = 11;
const xmlSymError: u16 = 12;

fn isXmlTagChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == ':' or c == '.' or c == '?';
}

fn xmlTagNameLen(source: []const u8, start: usize) usize {
    var i = start;
    while (i < source.len and isXmlTagChar(source[i])) : (i += 1) {}
    return i - start;
}

fn matchXmlOpenTag(source: []const u8, start: usize) ?usize {
    if (start + 2 > source.len or source[start] != '<') return null;
    const c1 = source[start + 1];
    if (c1 == '/' or c1 == '!' or c1 == '?') return null;
    if (!std.ascii.isAlphabetic(c1) and c1 != '_' and c1 != ':') return null;
    var i = start + 1 + xmlTagNameLen(source, start + 1);
    var inQuote: u8 = 0;
    while (i < source.len) {
        const c = source[i];
        if (inQuote != 0) {
            if (c == inQuote) inQuote = 0;
            i += 1;
            continue;
        }
        if (c == '"' or c == '\'') {
            inQuote = c;
            i += 1;
            continue;
        }
        if (c == '>') {
            if (i > start + 1 and source[i - 1] == '/') return null;
            return i + 1 - start;
        }
        i += 1;
    }
    return null;
}

fn matchXmlCloseTag(source: []const u8, start: usize) ?usize {
    if (start + 3 > source.len or source[start] != '<' or source[start + 1] != '/') return null;
    var i = start + 2;
    while (i < source.len and (source[i] == ' ' or source[i] == '\t' or source[i] == '\r' or source[i] == '\n')) : (i += 1) {}
    if (xmlTagNameLen(source, i) == 0) return null;
    i += xmlTagNameLen(source, i);
    while (i < source.len and (source[i] == ' ' or source[i] == '\t' or source[i] == '\r' or source[i] == '\n')) : (i += 1) {}
    if (i >= source.len or source[i] != '>') return null;
    return i + 1 - start;
}

fn matchXmlSelfCloseTag(source: []const u8, start: usize) ?usize {
    if (start + 3 > source.len or source[start] != '<') return null;
    const c1 = source[start + 1];
    if (c1 == '/' or c1 == '!' or c1 == '?') return null;
    if (!std.ascii.isAlphabetic(c1) and c1 != '_' and c1 != ':') return null;
    var i = start + 1 + xmlTagNameLen(source, start + 1);
    var inQuote: u8 = 0;
    while (i < source.len) {
        const c = source[i];
        if (inQuote != 0) {
            if (c == inQuote) inQuote = 0;
            i += 1;
            continue;
        }
        if (c == '"' or c == '\'') {
            inQuote = c;
            i += 1;
            continue;
        }
        if (c == '>' and i > start + 1 and source[i - 1] == '/') return i + 1 - start;
        if (c == '>') return null;
        i += 1;
    }
    return null;
}

fn matchXmlComment(source: []const u8, start: usize) ?usize {
    if (start + 4 > source.len) return null;
    if (!std.mem.eql(u8, source[start .. start + 4], "<!--")) return null;
    const close = std.mem.indexOfPos(u8, source, start + 4, "-->") orelse return source.len - start;
    return close + 3 - start;
}

fn matchXmlCdata(source: []const u8, start: usize) ?usize {
    if (start + 9 > source.len) return null;
    if (!std.mem.eql(u8, source[start .. start + 9], "<![CDATA[")) return null;
    const close = std.mem.indexOfPos(u8, source, start + 9, "]]>") orelse return source.len - start;
    return close + 3 - start;
}

fn matchXmlPi(source: []const u8, start: usize) ?usize {
    if (start + 2 > source.len or source[start] != '<' or source[start + 1] != '?') return null;
    const close = std.mem.indexOfPos(u8, source, start + 2, "?>") orelse return null;
    return close + 2 - start;
}

fn matchXmlDoctype(source: []const u8, start: usize) ?usize {
    if (start + 2 > source.len or source[start] != '<' or source[start + 1] != '!') return null;
    if (start + 9 <= source.len and std.mem.eql(u8, source[start .. start + 9], "<![CDATA[")) return null;
    if (start + 4 <= source.len and std.mem.eql(u8, source[start .. start + 4], "<!--")) return null;
    var i = start + 2;
    var depth: usize = 0;
    var inQuote: u8 = 0;
    while (i < source.len) {
        const c = source[i];
        if (inQuote != 0) {
            if (c == inQuote) inQuote = 0;
            i += 1;
            continue;
        }
        if (c == '"' or c == '\'') {
            inQuote = c;
            i += 1;
            continue;
        }
        if (c == '[') depth += 1;
        if (c == '>') {
            if (depth == 0) return i + 1 - start;
            depth -= 0;
        }
        if (c == ']' and depth > 0) depth -= 1;
        i += 1;
    }
    return null;
}

fn matchXmlText(source: []const u8, start: usize) ?usize {
    if (start >= source.len) return null;
    if (source[start] == '<') {
        if (start + 1 >= source.len) return 1;
        const n = source[start + 1];
        if (std.ascii.isAlphabetic(n) or n == '_' or n == ':' or n == '/' or n == '!' or n == '?') return null;
        return 1;
    }
    var i = start;
    while (i < source.len and source[i] != '<') : (i += 1) {}
    return i - start;
}

const xmlSymbolTable: []const ts.language_mod.symbols.SymbolInfo = &.{
    .{ .id = xmlSymEnd, .name = "end", .kind = .end, .metadata = .{ .visible = false, .named = false } },
    .{ .id = xmlSymOpenTag, .name = "open_tag", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymCloseTag, .name = "close_tag", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymSelfcloseTag, .name = "selfclose_tag", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymComment, .name = "comment", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymCdata, .name = "cdata", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymPi, .name = "pi", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymDoctype, .name = "doctype", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymText, .name = "text", .kind = .terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymProgram, .name = "program", .kind = .non_terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymNodes, .name = "nodes", .kind = .non_terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymNode, .name = "node", .kind = .non_terminal, .metadata = .{ .visible = true, .named = true } },
    .{ .id = xmlSymError, .name = "ERROR", .kind = .non_terminal, .metadata = .{ .visible = true, .named = true } },
};

const xmlTokenMatchers: []const ts.language_mod.TokenMatcher = &.{
    .{ .symbol = xmlSymCdata, .match = matchXmlCdata },
    .{ .symbol = xmlSymComment, .match = matchXmlComment },
    .{ .symbol = xmlSymPi, .match = matchXmlPi },
    .{ .symbol = xmlSymDoctype, .match = matchXmlDoctype },
    .{ .symbol = xmlSymCloseTag, .match = matchXmlCloseTag },
    .{ .symbol = xmlSymSelfcloseTag, .match = matchXmlSelfCloseTag },
    .{ .symbol = xmlSymOpenTag, .match = matchXmlOpenTag },
    .{ .symbol = xmlSymText, .match = matchXmlText },
};

const xmlS0Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymOpenTag, .action = .{ .shift = 6 } },
    .{ .symbol = xmlSymCloseTag, .action = .{ .shift = 12 } },
    .{ .symbol = xmlSymSelfcloseTag, .action = .{ .shift = 7 } },
    .{ .symbol = xmlSymText, .action = .{ .shift = 8 } },
    .{ .symbol = xmlSymComment, .action = .{ .shift = 9 } },
    .{ .symbol = xmlSymCdata, .action = .{ .shift = 10 } },
    .{ .symbol = xmlSymPi, .action = .{ .shift = 13 } },
    .{ .symbol = xmlSymDoctype, .action = .{ .shift = 14 } },
    .{ .symbol = xmlSymEnd, .action = .{ .reduce = .{ .symbol = xmlSymProgram, .child_count = 0, .production_id = 0 } } },
};
const xmlS0Gotos: []const ts.language_mod.tables.GotoEntry = &.{
    .{ .symbol = xmlSymProgram, .state = 1 },
    .{ .symbol = xmlSymNodes, .state = 2 },
    .{ .symbol = xmlSymNode, .state = 3 },
};
const xmlS1Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymEnd, .action = .accept },
};
const xmlS2Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymOpenTag, .action = .{ .shift = 6 } },
    .{ .symbol = xmlSymCloseTag, .action = .{ .shift = 12 } },
    .{ .symbol = xmlSymSelfcloseTag, .action = .{ .shift = 7 } },
    .{ .symbol = xmlSymText, .action = .{ .shift = 8 } },
    .{ .symbol = xmlSymComment, .action = .{ .shift = 9 } },
    .{ .symbol = xmlSymCdata, .action = .{ .shift = 10 } },
    .{ .symbol = xmlSymPi, .action = .{ .shift = 13 } },
    .{ .symbol = xmlSymDoctype, .action = .{ .shift = 14 } },
    .{ .symbol = xmlSymEnd, .action = .{ .reduce = .{ .symbol = xmlSymProgram, .child_count = 1, .production_id = 1 } } },
};
const xmlS2Gotos: []const ts.language_mod.tables.GotoEntry = &.{
    .{ .symbol = xmlSymNode, .state = 4 },
};
const xmlS3Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymOpenTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymCloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymSelfcloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymText, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymComment, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymCdata, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymPi, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymDoctype, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
    .{ .symbol = xmlSymEnd, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 1, .production_id = 2 } } },
};
const xmlS4Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymOpenTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymCloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymSelfcloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymText, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymComment, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymCdata, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymPi, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymDoctype, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
    .{ .symbol = xmlSymEnd, .action = .{ .reduce = .{ .symbol = xmlSymNodes, .child_count = 2, .production_id = 3 } } },
};
const xmlS5Actions: []const ts.language_mod.tables.ActionEntry = &.{
    .{ .symbol = xmlSymOpenTag, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymCloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymSelfcloseTag, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymText, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymComment, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymCdata, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymPi, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymDoctype, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
    .{ .symbol = xmlSymEnd, .action = .{ .reduce = .{ .symbol = xmlSymNode, .child_count = 1, .production_id = 4 } } },
};

const xmlParseStates: []const ts.language_mod.tables.ParseState = &.{
    .{ .actions = xmlS0Actions, .gotos = xmlS0Gotos },
    .{ .actions = xmlS1Actions },
    .{ .actions = xmlS2Actions, .gotos = xmlS2Gotos },
    .{ .actions = xmlS3Actions },
    .{ .actions = xmlS4Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
    .{ .actions = xmlS5Actions },
};

pub const xmlLanguage: ts.Language = .{
    .metadata = .{
        .name = "xml",
        .abi_version = ts.language_mod.metadata.current_abi_version,
        .version = "0.0.1",
        .symbol_count = 13,
        .state_count = 15,
        .field_count = 0,
    },
    .symbols = xmlSymbolTable,
    .token_matchers = xmlTokenMatchers,
    .extra_symbols = &.{},
    .table = .{
        .states = xmlParseStates,
        .start_state = 0,
        .end_symbol = xmlSymEnd,
        .error_symbol = xmlSymError,
    },
    .fields = .{},
};

fn parseXmlTree(allocator: Allocator, src: []const u8) ParseError!XmlTree {
    var parser = ts.Parser.init(allocator);
    defer parser.deinit();
    parser.setLanguage(xmlLanguage) catch return error.OutOfMemory;
    return parser.parseString(src) catch return error.OutOfMemory;
}

const XmlTokenKind = enum { openTag, closeTag, selfcloseTag, comment, cdata, pi, doctype, text };

const XmlToken = struct {
    kind: XmlTokenKind,
    start: usize,
    end: usize,
};

fn collectXmlTokens(tree: *const XmlTree, allocator: Allocator) Allocator.Error![]XmlToken {
    var out = std.ArrayList(XmlToken).empty;
    errdefer out.deinit(allocator);
    var stack = std.ArrayList(ts.Node).empty;
    defer stack.deinit(allocator);
    try stack.append(allocator, tree.rootNode());
    var ordered = std.ArrayList(ts.Node).empty;
    defer ordered.deinit(allocator);
    while (stack.pop()) |cur| {
        const t = cur.nodeType();
        if (std.mem.eql(u8, t, "open_tag") or std.mem.eql(u8, t, "close_tag") or
            std.mem.eql(u8, t, "selfclose_tag") or std.mem.eql(u8, t, "comment") or
            std.mem.eql(u8, t, "cdata") or std.mem.eql(u8, t, "pi") or
            std.mem.eql(u8, t, "doctype") or std.mem.eql(u8, t, "text"))
        {
            try ordered.append(allocator, cur);
            continue;
        }
        var i: u32 = cur.childCount();
        while (i > 0) {
            i -= 1;
            if (cur.child(i)) |c| try stack.append(allocator, c);
        }
    }
    std.mem.sort(ts.Node, ordered.items, {}, struct {
        fn less(_: void, a: ts.Node, b: ts.Node) bool {
            return a.startByte() < b.startByte();
        }
    }.less);
    for (ordered.items) |n| {
        const t = n.nodeType();
        const kind: XmlTokenKind = if (std.mem.eql(u8, t, "open_tag")) .openTag else if (std.mem.eql(u8, t, "close_tag")) .closeTag else if (std.mem.eql(u8, t, "selfclose_tag")) .selfcloseTag else if (std.mem.eql(u8, t, "comment")) .comment else if (std.mem.eql(u8, t, "cdata")) .cdata else if (std.mem.eql(u8, t, "pi")) .pi else if (std.mem.eql(u8, t, "doctype")) .doctype else .text;
        try out.append(allocator, .{ .kind = kind, .start = n.startByte(), .end = n.endByte() });
    }
    return out.toOwnedSlice(allocator);
}

pub const ParseError = error{
    OutOfMemory,
    TooManyNodes,
    TooDeep,
    TooManyAttributes,
    MalformedXml,
    InputTooLarge,
};

pub const Options = struct {
    lenient: bool = true,
    maxNodes: u32 = dom.MAX_NODES,
    maxDepth: u32 = dom.MAX_DEPTH,
    maxAttrs: u32 = 256,
    maxAttrValue: usize = 8192,
};

pub fn parse(arena: Allocator, xmlSrc: []const u8, opts: Options) ParseError!Tree {
    var tree = try Tree.initCapacity(arena, @min(xmlSrc.len / 12 + 4, opts.maxNodes));
    errdefer tree.deinit(arena);
    const root = try tree.append(arena, .{ .kind = .document });
    var p = Parser{
        .arena = arena,
        .tree = &tree,
        .src = xmlSrc,
        .opts = opts,
    };
    try p.openStack.append(arena, root);
    var tsTree = try parseXmlTree(arena, xmlSrc);
    defer tsTree.deinit();
    const tokens = try collectXmlTokens(&tsTree, arena);
    if (tsTree.hasError()) tree.getMut(root).hasError = true;
    try p.runTokens(tokens);
    return tree;
}

const Parser = struct {
    arena: Allocator,
    tree: *Tree,
    src: []const u8,
    opts: Options,
    openStack: std.ArrayList(u32) = .empty,

    fn cur(self: *const Parser) u32 {
        return if (self.openStack.items.len > 0)
            self.openStack.items[self.openStack.items.len - 1]
        else
            0;
    }

    fn runTokens(self: *Parser, tokens: []const XmlToken) ParseError!void {
        var covered: usize = 0;
        for (tokens) |tok| {
            if (tok.start > covered) {
                try self.appendText(self.src[covered..tok.start]);
                covered = tok.start;
            }
            switch (tok.kind) {
                .text => {
                    try self.appendText(self.src[tok.start..tok.end]);
                },
                .comment => {
                    const raw = self.src[tok.start..tok.end];
                    const data = if (raw.len >= 7 and std.mem.eql(u8, raw[0..4], "<!--") and std.mem.endsWith(u8, raw, "-->"))
                        raw[4 .. raw.len - 3]
                    else
                        raw;
                    const idx = try self.tree.append(self.arena, .{ .kind = .comment, .data = data });
                    self.tree.appendChild(self.cur(), idx);
                },
                .cdata => {
                    const raw = self.src[tok.start..tok.end];
                    const data = if (raw.len >= 12 and std.mem.eql(u8, raw[0..9], "<![CDATA[") and std.mem.endsWith(u8, raw, "]]>"))
                        raw[9 .. raw.len - 3]
                    else
                        raw;
                    const idx = try self.tree.append(self.arena, .{ .kind = .cdata, .data = data });
                    self.tree.appendChild(self.cur(), idx);
                },
                .pi, .doctype => {},
                .selfcloseTag => {
                    const tag = try self.parseOpenTag(self.src[tok.start..tok.end]);
                    const nodeIdx = try self.tree.append(self.arena, .{
                        .kind = .element,
                        .tag = tag.name,
                        .attrs = tag.attrs,
                    });
                    self.tree.appendChild(self.cur(), nodeIdx);
                },
                .openTag => {
                    if (self.openStack.items.len >= self.opts.maxDepth) return error.TooDeep;
                    const tag = try self.parseOpenTag(self.src[tok.start..tok.end]);
                    const nodeIdx = try self.tree.append(self.arena, .{
                        .kind = .element,
                        .tag = tag.name,
                        .attrs = tag.attrs,
                    });
                    self.tree.appendChild(self.cur(), nodeIdx);
                    try self.openStack.append(self.arena, nodeIdx);
                },
                .closeTag => {
                    const raw = self.src[tok.start..tok.end];
                    var inner = raw;
                    if (inner.len >= 2) inner = inner[2..];
                    if (inner.len > 0 and inner[inner.len - 1] == '>') inner = inner[0 .. inner.len - 1];
                    const tag = std.mem.trim(u8, inner, " \t\r\n");
                    try self.closeElement(tag);
                },
            }
            covered = @max(covered, tok.end);
        }
        if (covered < self.src.len) {
            try self.appendText(self.src[covered..]);
        }
        if (self.openStack.items.len > 1 and !self.opts.lenient) return error.MalformedXml;
    }

    fn appendText(self: *Parser, raw: []const u8) ParseError!void {
        if (raw.len == 0) return;
        const idx = try self.tree.append(self.arena, .{ .kind = .text, .data = raw });
        self.tree.appendChild(self.cur(), idx);
    }

    const OpenTag = struct {
        name: []const u8,
        attrs: []const Attribute,
    };

    fn parseOpenTag(self: *Parser, slice: []const u8) ParseError!OpenTag {
        var nameEnd: usize = 1;
        while (nameEnd < slice.len and !isStop(slice[nameEnd])) : (nameEnd += 1) {}
        const name = slice[1..nameEnd];
        var attrs: std.ArrayList(Attribute) = .empty;
        defer attrs.deinit(self.arena);
        var selfClosing = false;
        _ = try parseAttrs(self.arena, slice, nameEnd, &attrs, &selfClosing, self.opts.maxAttrValue);
        if (attrs.items.len > self.opts.maxAttrs) return error.TooManyAttributes;
        return .{ .name = name, .attrs = try attrs.toOwnedSlice(self.arena) };
    }

    fn closeElement(self: *Parser, tag: []const u8) ParseError!void {
        var k = self.openStack.items.len;
        while (k > 0) : (k -= 1) {
            const idx = self.openStack.items[k - 1];
            const node = self.tree.get(idx);
            if (node.kind == .element and std.mem.eql(u8, node.tag, tag)) {
                self.openStack.shrinkRetainingCapacity(k - 1);
                return;
            }
        }
        if (!self.opts.lenient) return error.MalformedXml;
    }
};

fn isStop(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n' or c == '\x0C' or c == '>' or c == '/';
}

test "xml grammar tokenizes elements and text" {
    const a = std.testing.allocator;
    var t = try parseXmlTree(a, "<feed xmlns=\"http://a\"><title>x</title></feed>");
    defer t.deinit();
    try std.testing.expect(!t.hasError());
    try std.testing.expectEqualStrings("program", t.rootNode().nodeType());
}

test "xml preserves namespaces and cdata via syntax tree" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const tree = try parse(arena.allocator(), "<rss><channel><item><title><![CDATA[Hi]]></title></item></channel></rss>", .{});
    var foundCdata = false;
    for (tree.nodes.items) |n| {
        if (n.kind == .cdata and std.mem.eql(u8, n.data, "Hi")) foundCdata = true;
    }
    try std.testing.expect(foundCdata);
}

test "xml strict mode rejects mismatched tags" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const res = parse(arena.allocator(), "<a><b></a></b>", .{ .lenient = false });
    try std.testing.expectError(error.MalformedXml, res);
}

fn parseAttrs(
    arena: Allocator,
    src: []const u8,
    start: usize,
    attrs: *std.ArrayList(Attribute),
    selfClosing: *bool,
    maxVal: usize,
) ParseError!usize {
    var i = start;
    while (i < src.len) {
        while (i < src.len and (src[i] == ' ' or src[i] == '\t' or src[i] == '\r' or src[i] == '\n')) : (i += 1) {}
        if (i >= src.len) break;
        if (src[i] == '>') {
            i += 1;
            break;
        }
        if (src[i] == '/' and i + 1 < src.len and src[i + 1] == '>') {
            selfClosing.* = true;
            i += 2;
            break;
        }

        const nameStart = i;
        while (i < src.len and src[i] != '=' and src[i] != '>' and src[i] != '/' and
            src[i] != ' ' and src[i] != '\t' and src[i] != '\r' and src[i] != '\n') : (i += 1)
        {}
        if (i == nameStart) {
            i += 1;
            continue;
        }
        const attrName = src[nameStart..i];

        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) : (i += 1) {}
        if (i >= src.len or src[i] != '=') {
            try attrs.append(arena, .{ .name = attrName, .value = "" });
            continue;
        }
        i += 1;
        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) : (i += 1) {}

        var val: []const u8 = "";
        if (i < src.len and (src[i] == '"' or src[i] == '\'')) {
            const q = src[i];
            i += 1;
            const vs = i;
            while (i < src.len and src[i] != q) : (i += 1) {}
            val = src[vs..i];
            if (i < src.len) i += 1;
        } else {
            const vs = i;
            while (i < src.len and src[i] != ' ' and src[i] != '>' and src[i] != '/') : (i += 1) {}
            val = src[vs..i];
        }
        if (val.len > maxVal) return error.InputTooLarge;
        try attrs.append(arena, .{ .name = attrName, .value = val });
    }
    return i;
}
