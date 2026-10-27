// atom-to-html renders an Atom feed of stored posts, newest first, as the
// reader's web page. Every value is escaped, and only http and https links
// are kept, so a hostile feed can't inject markup or script into the page.
//
// Uniform `now_unix_seconds` (i64 Unix seconds) is shown as when the page was built; at
// its default, 0, it's left out.
package atom_to_html

import "base:intrinsics"
import sh "../shared"

INPUT_CAP :: 8 << 20
OUTPUT_CAP :: 2 << 20
SCRATCH_CAP :: 1 << 20

input_buf: [INPUT_CAP]u8
output_buf: [OUTPUT_CAP]u8
scratch_a: [SCRATCH_CAP]u8
scratch_b: [SCRATCH_CAP]u8

INPUT_TYPE :: "application/atom+xml"
OUTPUT_TYPE :: "text/html"
input_type: [len(INPUT_TYPE)]u8 = INPUT_TYPE
output_type: [len(OUTPUT_TYPE)]u8 = OUTPUT_TYPE

SNIPPET_RUNES :: 280

now_unix_seconds_default :: 0
now_unix_seconds: i64 = now_unix_seconds_default

@(export) input_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_buf[0])) }
@(export) input_utf8_cap :: proc "contextless" () -> u32 { return INPUT_CAP }
@(export) input_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_type[0])) }
@(export) input_content_type_size :: proc "contextless" () -> u32 { return len(INPUT_TYPE) }
@(export) output_utf8_cap :: proc "contextless" () -> u32 { return OUTPUT_CAP }
@(export) output_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&output_type[0])) }
@(export) output_content_type_size :: proc "contextless" () -> u32 { return len(OUTPUT_TYPE) }

Failure :: enum u32 {
	Malformed_XML = 0,
	Not_Atom      = 1,
	Too_Large     = 2,
}
@(export) failure_modes_per_input_offset :: proc "contextless" () -> u32 { return len(Failure) }

@(export)
uniform_set_now_unix_seconds :: proc "contextless" (v: i64) -> i64 {
	now_unix_seconds = v
	return now_unix_seconds
}

HEAD :: `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latest posts</title>
<style>
body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
article { border-bottom: 1px solid #ddd; padding: 0.75rem 0; }
h2 { font-size: 1.05rem; margin: 0; }
a { color: #0645ad; text-decoration: none; }
.meta { color: #666; font-size: 0.85rem; }
p { margin: 0.25rem 0 0; }
footer { color: #888; font-size: 0.8rem; margin-top: 1rem; }
@media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } a { color: #8ab4f8; } article { border-color: #333; } }
</style>
<h1>Latest posts</h1>
`

Field :: struct {
	set:      bool,
	from, to: int,
}

Entry :: struct {
	title, published, updated, summary, content, source_title, source_id: Field,
	link:                                                                   []u8,
}

@(export)
render :: proc "contextless" (input_size: u32) -> u64 {
	if input_size > INPUT_CAP {
		intrinsics.trap()
	}
	built := now_unix_seconds
	now_unix_seconds = now_unix_seconds_default
	doc := input_buf[:input_size]
	out := sh.Writer{buf = output_buf[:]}
	sh.write_string(&out, HEAD)

	s := sh.Scanner{data = doc}
	root: sh.Token
	for {
		root = sh.next(&s)
		if root.kind == .Start {
			break
		}
		if root.kind != .Text {
			return reject(root.start, .Malformed_XML, len(doc))
		}
	}
	if !sh.equal(sh.local_name(root.name), "feed") {
		return reject(root.start, .Not_Atom, len(doc))
	}
	posts := 0
	for !root.self_closing {
		t := sh.next(&s)
		#partial switch t.kind {
		case .End:
		case .EOF, .Error:
			return reject(t.start, .Malformed_XML, len(doc))
		case .Start:
			if !sh.equal(sh.local_name(t.name), "entry") {
				if _, ok := sh.skip_element(&s, t); !ok {
					return reject(t.start, .Malformed_XML, len(doc))
				}
				continue
			}
			e, ok := read_entry(&s, doc, t)
			if !ok {
				return reject(s.pos, .Malformed_XML, len(doc))
			}
			write_entry(&out, doc, e)
			posts += 1
			continue
		case:
			continue
		}
		break
	}
	if posts == 0 {
		sh.write_string(&out, "<p>No posts yet.</p>\n")
	}
	sh.write_string(&out, "<footer>Built ")
	if built != 0 {
		sh.write_readable(&out, built)
		sh.write_byte(&out, ' ')
	}
	sh.write_string(&out, "from const/items/ by rss-reader.</footer>\n</html>\n")
	if out.overflow {
		return reject(0, .Too_Large, len(doc))
	}
	return (u64(uintptr(&output_buf[0])) << 32) | u64(out.n)
}

reject :: proc "contextless" (offset: int, mode: Failure, size: int) -> u64 {
	return (u64(1) << 63) | (u64(clamp(offset, 0, size)) * len(Failure) + u64(mode))
}

read_entry :: proc "contextless" (s: ^sh.Scanner, doc: []u8, start: sh.Token) -> (e: Entry, ok: bool) {
	if start.self_closing {
		return e, true
	}
	for {
		t := sh.next(s)
		#partial switch t.kind {
		case .End:
			return e, true
		case .EOF, .Error:
			return e, false
		case .Start:
			name := sh.local_name(t.name)
			if sh.equal(name, "source") && !t.self_closing {
				read_source(s, &e) or_return
				continue
			}
			inner_end := sh.skip_element(s, t) or_return
			f := Field{true, t.end, inner_end}
			switch string(name) {
			case "title":     e.title = f
			case "published": e.published = f
			case "updated":   e.updated = f
			case "summary":   if !e.summary.set { e.summary = f }
			case "content":   if !e.content.set { e.content = f }
			case "link":
				rel, _ := sh.attr(t.attrs, "rel")
				if e.link == nil && (len(rel) == 0 || sh.equal(rel, "alternate")) {
					e.link, _ = sh.attr(t.attrs, "href")
				}
			}
		}
	}
}

read_source :: proc "contextless" (s: ^sh.Scanner, e: ^Entry) -> bool {
	for {
		t := sh.next(s)
		#partial switch t.kind {
		case .End:
			return true
		case .EOF, .Error:
			return false
		case .Start:
			inner_end := sh.skip_element(s, t) or_return
			f := Field{true, t.end, inner_end}
			switch string(sh.local_name(t.name)) {
			case "title": e.source_title = f
			case "id":    e.source_id = f
			}
		}
	}
}

// text writes a field's decoded character data, trimmed, to w and returns
// it.
text :: proc "contextless" (w: ^sh.Writer, doc: []u8, f: Field) -> []u8 {
	w.n = 0
	if f.set {
		sh.write_inner_text(w, doc, f.from, f.to)
	}
	return sh.trim(sh.bytes(w))
}

write_entry :: proc "contextless" (out: ^sh.Writer, doc: []u8, e: Entry) {
	a := sh.Writer{buf = scratch_a[:]}
	b := sh.Writer{buf = scratch_b[:]}

	sh.write_string(out, "<article>\n<h2>")
	link: []u8
	if e.link != nil {
		sh.write_decoded(&a, e.link)
		if u := sh.trim(sh.bytes(&a)); safe_url(u) {
			link = u
		}
	}
	if link != nil {
		sh.write_string(out, "<a href=\"")
		sh.write_html_escaped(out, link)
		sh.write_string(out, "\">")
	}
	title := text(&b, doc, e.title)
	if len(title) == 0 {
		title = transmute([]u8)string("(untitled)")
	}
	sh.write_html_escaped(out, title)
	if link != nil {
		sh.write_string(out, "</a>")
	}
	sh.write_string(out, "</h2>\n<div class=\"meta\">")
	source := text(&a, doc, e.source_title)
	if len(source) == 0 {
		source = text(&a, doc, e.source_id)
	}
	sh.write_html_escaped(out, source)
	date, ok := sh.parse_date(text(&a, doc, e.published))
	if !ok {
		date, ok = sh.parse_date(text(&a, doc, e.updated))
	}
	if ok {
		sh.write_string(out, " · <time datetime=\"")
		sh.write_rfc3339(out, date)
		sh.write_string(out, "\">")
		sh.write_readable(out, date)
		sh.write_string(out, "</time>")
	}
	sh.write_string(out, "</div>\n")

	// The snippet: the summary, else the content, as plain text.
	body := e.summary if e.summary.set else e.content
	if body.set {
		html := text(&a, doc, body)
		b.n = 0
		sh.write_stripped(&b, html)
		snippet, cut := sh.truncate_runes(sh.bytes(&b), SNIPPET_RUNES)
		if len(snippet) > 0 {
			sh.write_string(out, "<p>")
			sh.write_html_escaped(out, snippet)
			if cut {
				sh.write_string(out, "…")
			}
			sh.write_string(out, "</p>\n")
		}
	}
	sh.write_string(out, "</article>\n")
}

// safe_url accepts only absolute http and https URLs, so javascript: and
// data: links are dropped.
safe_url :: proc "contextless" (u: []u8) -> bool {
	lower: [8]u8
	n := min(len(u), len(lower))
	for i in 0 ..< n {
		c := u[i]
		lower[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	l := lower[:n]
	return sh.has_prefix(l, "http://") || sh.has_prefix(l, "https://")
}
