// feed-to-entries converts one fetched feed to the posts it holds.
//
// Input is application/warc: one WARC response record, whose target URI is
// the subscribed feed URL and whose block is the origin's HTTP response.
// The body can be RSS 2.0, RSS 1.0 or Atom, in UTF-8 or Latin-1.
//
// Output is multipart/form-data, one part per post. Each part is named
// with the post's key under const/items/, "{invTS}/{hash}", and holds the
// post as an Atom <entry> whose <source> names the feed. invTS is
// 9999999999 minus the post's Unix time, so keys list newest first; hash is
// the first 32 hex digits of SHA-256(feed URL + "\n" + guid or id or link).
//
// Uniform `now_unix_seconds` (i64 Unix seconds) stands in for missing dates and caps
// future ones, so a misdated post can't stay at the top. At its default, 0,
// nothing is capped.
package feed_to_entries

import "base:intrinsics"
import "base:runtime"
import "core:crypto/sha2"
import sh "../shared"

INPUT_CAP :: 8 << 20
OUTPUT_CAP :: 16 << 20
// A body can grow up to threefold: each invalid UTF-8 byte becomes U+FFFD.
DOC_CAP :: 3 * INPUT_CAP
SCRATCH_CAP :: 4 << 20
SMALL_CAP :: 64 << 10

input_buf: [INPUT_CAP]u8
doc_buf: [DOC_CAP]u8
output_buf: [OUTPUT_CAP]u8
scratch_buf: [SCRATCH_CAP]u8
id_buf: [SMALL_CAP]u8
link_buf: [SMALL_CAP]u8
title_buf: [SMALL_CAP]u8
// Room for one field after processing: a post's title, or a plain-text
// summary escaped as HTML.
spare_buf: [SCRATCH_CAP]u8

INPUT_TYPE :: "application/warc"
OUTPUT_TYPE :: "multipart/form-data;boundary=uuid-00000000-0000-0000-0000-000000000000"
input_type: [len(INPUT_TYPE)]u8 = INPUT_TYPE
// The host may replace the boundary's UUID before each render, so it's
// read from memory on every call.
output_type: [len(OUTPUT_TYPE)]u8 = OUTPUT_TYPE
BOUNDARY_AT :: len("multipart/form-data;boundary=")

now_unix_seconds_default :: 0
now_unix_seconds: i64 = now_unix_seconds_default

@(export) input_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_buf[0])) }
@(export) input_bytes_cap :: proc "contextless" () -> u32 { return INPUT_CAP }
@(export) input_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_type[0])) }
@(export) input_content_type_size :: proc "contextless" () -> u32 { return len(INPUT_TYPE) }
@(export) output_utf8_cap :: proc "contextless" () -> u32 { return OUTPUT_CAP }
@(export) output_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&output_type[0])) }
@(export) output_content_type_size :: proc "contextless" () -> u32 { return len(OUTPUT_TYPE) }

@(export)
uniform_set_now_unix_seconds :: proc "contextless" (v: i64) -> i64 {
	now_unix_seconds = v
	return now_unix_seconds
}

// Failure modes, reported with the offset in the input where they apply.
Failure :: enum u32 {
	Malformed_WARC     = 0,
	Malformed_XML      = 1,
	Not_A_Feed         = 2,
	Unsupported_Charset = 3,
	Too_Large          = 4, // the output, or one field, didn't fit
	No_IDs             = 5, // no post has a GUID, an ID or a link
	Boundary_In_Post   = 6,
}
FAILURE_MODES :: len(Failure)

@(export) failure_modes_per_input_offset :: proc "contextless" () -> u32 { return FAILURE_MODES }

input_size_now: int

fail :: proc "contextless" (offset: int, mode: Failure) -> u64 {
	now_unix_seconds = now_unix_seconds_default
	off := u64(clamp(offset, 0, input_size_now))
	return (u64(1) << 63) | (off * FAILURE_MODES + u64(mode))
}

@(export)
render :: proc "contextless" (input_size: u32) -> u64 {
	if input_size > INPUT_CAP {
		intrinsics.trap()
	}
	input_size_now = int(input_size)
	input := input_buf[:input_size]

	url, body, body_at, ok := parse_warc(input)
	if !ok {
		return fail(body_at, .Malformed_WARC)
	}
	doc_w := sh.Writer{buf = doc_buf[:]}
	if !decode_body(&doc_w, body) {
		return fail(body_at, .Unsupported_Charset)
	}
	doc := sh.bytes(&doc_w)

	out := sh.Writer{buf = output_buf[:]}
	f := Feed{doc = doc, url = url, body_at = body_at, out = &out}
	if failure, at, failed := convert(&f); failed {
		return fail(at, failure)
	}
	now_unix_seconds = now_unix_seconds_default
	return (u64(uintptr(&output_buf[0])) << 32) | u64(out.n)
}

// parse_warc finds the target URI and the HTTP response body in a single
// WARC record.
parse_warc :: proc "contextless" (input: []u8) -> (url, body: []u8, body_at: int, ok: bool) {
	if !sh.has_prefix(input, "WARC/1.") {
		return
	}
	headers_end := sh.index(input, "\r\n\r\n")
	if headers_end < 0 {
		return
	}
	length := -1
	lines := input[:headers_end + 2]
	for len(lines) > 0 {
		eol := sh.index(lines, "\r\n")
		line := lines[:eol]
		lines = lines[eol + 2:]
		colon := sh.index_byte(line, ':')
		if colon < 0 {
			continue
		}
		name, value := line[:colon], sh.trim(line[colon + 1:])
		switch {
		case sh.equal_fold(name, "warc-target-uri"):
			url = value
		case sh.equal_fold(name, "content-length"):
			length = 0
			for c in value {
				if c < '0' || c > '9' || length > INPUT_CAP {
					return
				}
				length = length * 10 + int(c - '0')
			}
		}
	}
	block_at := headers_end + 4
	if len(url) == 0 || length < 0 || length > len(input) - block_at {
		return
	}
	// The block is an HTTP response: skip its status line and headers.
	block := input[block_at:block_at + length]
	if !sh.has_prefix(block, "HTTP/") {
		return
	}
	http_end := sh.index(block, "\r\n\r\n")
	if http_end < 0 {
		return
	}
	body_at = block_at + http_end + 4
	return url, input[body_at:block_at + length], body_at, true
}

// decode_body copies the body as valid UTF-8, decoding Latin-1 if the XML
// declaration names it.
decode_body :: proc "contextless" (w: ^sh.Writer, body: []u8) -> bool {
	b := body
	if sh.has_prefix(b, "\xEF\xBB\xBF") {
		b = b[3:]
	} else if len(b) >= 2 && ((b[0] == 0xFE && b[1] == 0xFF) || (b[0] == 0xFF && b[1] == 0xFE)) {
		return false // UTF-16
	}
	latin1 := false
	if sh.has_prefix(b, "<?xml") {
		end := sh.index(b, "?>")
		if end > 0 {
			if enc, ok := sh.attr(b[5:end], "encoding"); ok {
				switch {
				case sh.equal_fold(enc, "utf-8"), sh.equal_fold(enc, "utf8"):
				case sh.equal_fold(enc, "iso-8859-1"), sh.equal_fold(enc, "latin1"), sh.equal_fold(enc, "windows-1252"), sh.equal_fold(enc, "us-ascii"):
					latin1 = true
				case:
					return false
				}
			}
		}
	}
	if latin1 {
		sh.write_latin1(w, b)
	} else {
		sh.write_utf8_sanitized(w, b)
	}
	return !w.overflow
}

Feed :: struct {
	doc:     []u8,
	url:     []u8,
	body_at: int,
	out:     ^sh.Writer,
	title:   []u8, // the feed's title, as plain text
	atom:    bool,
}

// Field is where one child element of a post is in the document.
Field :: struct {
	set:        bool,
	from, to:   int, // its contents
	type_attr:  []u8, // Atom text constructs: text, html or xhtml
}

Post :: struct {
	id, title, published, updated, summary, content: Field,
	// RSS only
	pub_date, dc_date: Field,
	// The first link: an RSS <link> with text, or an Atom alternate
	// link's href.
	link_text: Field,
	link_href: []u8,
}

convert :: proc "contextless" (f: ^Feed) -> (failure: Failure, at: int, failed: bool) {
	s := sh.Scanner{data = f.doc}
	root: sh.Token
	for {
		root = sh.next(&s)
		if root.kind == .Start {
			break
		}
		if root.kind != .Text {
			return .Malformed_XML, f.body_at + root.start, true
		}
	}
	name := sh.local_name(root.name)
	switch {
	case sh.equal(name, "rss"), sh.equal(name, "RDF"):
	case sh.equal(name, "feed"):
		f.atom = true
	case:
		return .Not_A_Feed, f.body_at + root.start, true
	}
	if root.self_closing {
		return
	}

	// Two passes, as the feed's title, which every post names as its
	// source, may come after the posts.
	after_root := s.pos
	if !walk(f, &s, false) {
		return .Malformed_XML, f.body_at + s.pos, true
	}
	posts, kept := 0, 0
	s.pos = after_root
	walk(f, &s, true, &posts, &kept)
	if f.out.overflow {
		return .Too_Large, f.body_at, true
	}
	if posts > 0 && kept == 0 {
		return .No_IDs, f.body_at, true
	}
	if boundary_failed {
		return .Boundary_In_Post, f.body_at, true
	}
	write_close(f.out)
	if f.out.overflow {
		return .Too_Large, f.body_at, true
	}
	return
}

boundary_failed: bool

// walk reads the root element's children. The first pass finds the feed's
// title; the second converts each post.
walk :: proc "contextless" (f: ^Feed, s: ^sh.Scanner, emit: bool, posts: ^int = nil, kept: ^int = nil) -> bool {
	boundary_failed = false
	for {
		t := sh.next(s)
		#partial switch t.kind {
		case .End, .EOF:
			// The root's end, or a document cut short after it.
			return t.kind == .End
		case .Error:
			return false
		case .Start:
			name := sh.local_name(t.name)
			switch {
			case !f.atom && sh.equal(name, "channel"):
				if t.self_closing {
					continue
				}
				for {
					c := sh.next(s)
					#partial switch c.kind {
					case .Error, .EOF:
						return false
					case .Start:
						cname := sh.local_name(c.name)
						if sh.equal(cname, "item") {
							if !post(f, s, c, emit, posts, kept) {
								return false
							}
						} else {
							inner_end := sh.skip_element(s, c) or_return
							if !emit && sh.equal(cname, "title") && f.title == nil {
								set_title(f, c, inner_end)
							}
						}
						continue
					case .End:
					case:
						continue
					}
					break
				}
			case (!f.atom && sh.equal(name, "item")) || (f.atom && sh.equal(name, "entry")):
				if !post(f, s, t, emit, posts, kept) {
					return false
				}
			case:
				inner_end := sh.skip_element(s, t) or_return
				if f.atom && !emit && sh.equal(name, "title") && f.title == nil {
					set_title(f, t, inner_end)
				}
			}
		}
	}
}

set_title :: proc "contextless" (f: ^Feed, t: sh.Token, inner_end: int) {
	w := sh.Writer{buf = title_buf[:]}
	field := Field{set = true, from = t.end, to = inner_end}
	if f.atom {
		field.type_attr, _ = sh.attr(t.attrs, "type")
		write_plain(&w, f.doc, field)
	} else {
		sw := scratch()
		sh.write_inner_text(&sw, f.doc, field.from, field.to)
		sh.write(&w, sh.trim(sh.bytes(&sw)))
	}
	f.title = sh.bytes(&w)
}

// post reads one RSS <item> or Atom <entry> and, in the second pass,
// writes it out.
post :: proc "contextless" (f: ^Feed, s: ^sh.Scanner, start: sh.Token, emit: bool, posts, kept: ^int) -> bool {
	p: Post
	if !start.self_closing {
		for {
			t := sh.next(s)
			#partial switch t.kind {
			case .Error, .EOF:
				return false
			case .End:
				break
			case .Start:
				inner_end := sh.skip_element(s, t) or_return
				if emit {
					child(f, &p, t, inner_end)
				}
				continue
			case:
				continue
			}
			break
		}
	}
	if emit {
		posts^ += 1
		if write_post(f, &p) {
			kept^ += 1
		}
	}
	return true
}

child :: proc "contextless" (f: ^Feed, p: ^Post, t: sh.Token, inner_end: int) {
	name := sh.local_name(t.name)
	field := Field{set = true, from = t.end, to = inner_end}
	field.type_attr, _ = sh.attr(t.attrs, "type")
	set :: proc "contextless" (dst: ^Field, v: Field) {
		if !dst.set {
			dst^ = v
		}
	}
	if f.atom {
		switch string(name) {
		case "id":        set(&p.id, field)
		case "title":     set(&p.title, field)
		case "published": set(&p.published, field)
		case "updated":   set(&p.updated, field)
		case "summary":   set(&p.summary, field)
		case "content":   set(&p.content, field)
		case "link":
			rel, _ := sh.attr(t.attrs, "rel")
			if p.link_href == nil && (len(rel) == 0 || sh.equal(rel, "alternate")) {
				if href, ok := sh.attr(t.attrs, "href"); ok {
					p.link_href = href
				}
			}
		}
		return
	}
	switch string(name) {
	case "guid":        set(&p.id, field)
	case "title":       set(&p.title, field)
	case "pubDate":     set(&p.pub_date, field)
	case "date":        set(&p.dc_date, field)
	case "description": set(&p.summary, field)
	case "encoded":     set(&p.content, field)
	case "link":
		// atom:link in an RSS item has an href and no text, and is skipped.
		if !p.link_text.set && len(text(f.doc, field)) > 0 {
			p.link_text = field
		}
	}
}

scratch :: proc "contextless" () -> sh.Writer {
	return sh.Writer{buf = scratch_buf[:]}
}

// text returns a field's character data, decoded and trimmed, in scratch.
text :: proc "contextless" (doc: []u8, field: Field) -> []u8 {
	if !field.set {
		return nil
	}
	w := scratch()
	sh.write_inner_text(&w, doc, field.from, field.to)
	if w.overflow {
		return nil
	}
	return sh.trim(sh.bytes(&w))
}

// write_plain writes an Atom text construct as plain text.
write_plain :: proc "contextless" (w: ^sh.Writer, doc: []u8, field: Field) {
	switch {
	case sh.equal(field.type_attr, "html"):
		sh.write_stripped(w, text(doc, field))
	case sh.equal(field.type_attr, "xhtml"):
		sh.write_stripped(w, doc[field.from:field.to])
	case:
		sh.write_collapsed(w, text(doc, field))
	}
}

// write_post writes one part, unless the post has nothing to identify it
// by next time.
write_post :: proc "contextless" (f: ^Feed, p: ^Post) -> bool {
	// The link, resolved against the feed's URL.
	link_w := sh.Writer{buf = link_buf[:]}
	if p.link_text.set {
		resolve(&link_w, f.url, text(f.doc, p.link_text))
	} else if p.link_href != nil {
		raw_w := scratch()
		sh.write_decoded(&raw_w, p.link_href)
		resolve(&link_w, f.url, sh.trim(sh.bytes(&raw_w)))
	}
	link := sh.bytes(&link_w)

	id_w := sh.Writer{buf = id_buf[:]}
	sh.write(&id_w, text(f.doc, p.id))
	if id_w.n == 0 {
		sh.write(&id_w, link)
	}
	id := sh.bytes(&id_w)
	if len(id) == 0 || id_w.overflow || link_w.overflow {
		return false
	}

	// Dates: the published date, else the updated date, else now, never
	// after now.
	published, updated: i64
	has_published, has_updated: bool
	if f.atom {
		published, has_published = sh.parse_date(text(f.doc, p.published))
		updated, has_updated = sh.parse_date(text(f.doc, p.updated))
	} else {
		d := text(f.doc, p.pub_date)
		if len(d) == 0 {
			d = text(f.doc, p.dc_date)
		}
		published, has_published = sh.parse_date(d)
	}
	sort := published if has_published else (updated if has_updated else now_unix_seconds)
	if now_unix_seconds != 0 && sort > now_unix_seconds {
		sort = now_unix_seconds
	}
	if !has_updated {
		updated = published if has_published else now_unix_seconds
	}

	out := f.out
	write_part_header(out, f.url, id, sort)
	body_start := out.n
	sh.write_string(out, "<entry xmlns=\"http://www.w3.org/2005/Atom\">\n  <id>")
	sh.write_xml_escaped(out, id)
	sh.write_string(out, "</id>\n  <title>")
	{
		tw := sh.Writer{buf = spare_buf[:]}
		if f.atom {
			write_plain(&tw, f.doc, p.title)
		} else {
			sh.write(&tw, text(f.doc, p.title))
		}
		if tw.overflow {
			out.overflow = true
		}
		sh.write_xml_escaped(out, sh.bytes(&tw))
	}
	sh.write_string(out, "</title>\n  <link href=\"")
	sh.write_xml_escaped(out, link)
	sh.write_string(out, "\" rel=\"alternate\"></link>\n")
	if has_published {
		sh.write_string(out, "  <published>")
		sh.write_rfc3339(out, published)
		sh.write_string(out, "</published>\n")
	}
	sh.write_string(out, "  <updated>")
	sh.write_rfc3339(out, updated)
	sh.write_string(out, "</updated>\n")
	write_html_field(out, f, "summary", p.summary)
	write_html_field(out, f, "content", p.content)
	sh.write_string(out, "  <source>\n    <id>")
	sh.write_xml_escaped(out, f.url)
	sh.write_string(out, "</id>\n    <title>")
	sh.write_xml_escaped(out, f.title)
	sh.write_string(out, "</title>\n    <link href=\"")
	sh.write_xml_escaped(out, f.url)
	sh.write_string(out, "\" rel=\"self\"></link>\n  </source>\n</entry>")
	if !out.overflow && sh.index(out.buf[body_start:out.n], string(output_type[BOUNDARY_AT:])) >= 0 {
		boundary_failed = true
	}
	sh.write_string(out, "\r\n")
	return true
}

// write_html_field writes a summary or content as type="html", the one
// form stored posts use. Atom's plain text is escaped into HTML first.
write_html_field :: proc "contextless" (out: ^sh.Writer, f: ^Feed, name: string, field: Field) {
	if !field.set {
		return
	}
	body: []u8
	xhtml := f.atom && sh.equal(field.type_attr, "xhtml")
	if xhtml {
		body = sh.trim(f.doc[field.from:field.to])
	} else {
		body = text(f.doc, field)
	}
	if len(body) == 0 {
		return
	}
	sh.write_string(out, "  <")
	sh.write_string(out, name)
	sh.write_string(out, " type=\"html\">")
	if f.atom && !xhtml && !sh.equal(field.type_attr, "html") {
		hw := sh.Writer{buf = spare_buf[:]}
		sh.write_html_escaped(&hw, body)
		if hw.overflow {
			out.overflow = true
		}
		body = sh.bytes(&hw)
	}
	sh.write_xml_escaped(out, body)
	sh.write_string(out, "</")
	sh.write_string(out, name)
	sh.write_string(out, ">\n")
}

// boundary reads the boundary from the output type on every call, as the
// host may have replaced its UUID.
boundary :: proc "contextless" (w: ^sh.Writer) {
	sh.write_string(w, "--")
	for i in BOUNDARY_AT ..< len(OUTPUT_TYPE) {
		sh.write_byte(w, intrinsics.volatile_load(&output_type[i]))
	}
}

write_part_header :: proc "contextless" (out: ^sh.Writer, url, id: []u8, sort: i64) {
	boundary(out)
	sh.write_string(out, "\r\nContent-Disposition: form-data; name=\"")
	inv := 9999999999 - clamp(sort, 0, 9999999999)
	sh.write_uint(out, u64(inv), 10)
	sh.write_byte(out, '/')
	write_item_hash(out, url, id)
	sh.write_string(out, "\"\r\nContent-Type: application/atom+xml\r\n\r\n")
}

write_close :: proc "contextless" (out: ^sh.Writer) {
	boundary(out)
	sh.write_string(out, "--\r\n")
}

// write_item_hash identifies a post. It includes the feed, so two feeds
// using the same GUID don't collide.
write_item_hash :: proc "contextless" (out: ^sh.Writer, url, id: []u8) {
	context = runtime.default_context()
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, url)
	sha2.update(&ctx, []u8{'\n'})
	sha2.update(&ctx, id)
	sum: [32]u8
	sha2.final(&ctx, sum[:])
	hex := "0123456789abcdef"
	for b in sum[:16] {
		sh.write_byte(out, hex[b >> 4])
		sh.write_byte(out, hex[b & 15])
	}
}

// resolve writes ref resolved against base (RFC 3986 section 5.2).
resolve :: proc "contextless" (w: ^sh.Writer, base, ref: []u8) {
	if len(ref) == 0 {
		return
	}
	// A scheme: letters, digits, + - . before the first colon.
	for c, i in ref {
		if c == ':' && i > 0 {
			sh.write(w, ref)
			return
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'))) {
			break
		}
	}
	scheme_end := sh.index(base, "://")
	if scheme_end < 0 {
		sh.write(w, ref)
		return
	}
	if sh.has_prefix(ref, "//") {
		sh.write(w, base[:scheme_end + 1])
		sh.write(w, ref)
		return
	}
	auth_end := scheme_end + 3
	for auth_end < len(base) && base[auth_end] != '/' && base[auth_end] != '?' && base[auth_end] != '#' {
		auth_end += 1
	}
	path_end := auth_end
	for path_end < len(base) && base[path_end] != '?' && base[path_end] != '#' {
		path_end += 1
	}
	if ref[0] == '#' {
		frag := sh.index_byte(base, '#')
		sh.write(w, base if frag < 0 else base[:frag])
		sh.write(w, ref)
		return
	}
	sh.write(w, base[:auth_end])
	if ref[0] == '?' {
		sh.write(w, base[auth_end:path_end])
		sh.write(w, ref)
		return
	}
	// Merge the paths, then remove dot segments as the output is written.
	path_start := w.n
	if ref[0] != '/' {
		dir := base[auth_end:path_end]
		last := -1
		for c, i in dir {
			if c == '/' {
				last = i
			}
		}
		sh.write(w, dir[:last + 1] if last >= 0 else transmute([]u8)string("/"))
	}
	q := len(ref)
	for c, i in ref {
		if c == '?' || c == '#' {
			q = i
			break
		}
	}
	segs := ref[:q]
	for len(segs) > 0 {
		slash := sh.index_byte(segs, '/')
		seg := segs if slash < 0 else segs[:slash + 1]
		segs = segs[len(seg):]
		switch {
		case sh.equal(seg, "./"), sh.equal(seg, "."):
		case sh.equal(seg, "../"), sh.equal(seg, ".."):
			// Drop the last segment written, keeping the leading slash.
			n := w.n - 1
			for n > path_start && w.buf[n - 1] != '/' {
				n -= 1
			}
			w.n = max(n, path_start + 1)
		case:
			sh.write(w, seg)
		}
	}
	sh.write(w, ref[q:])
}
