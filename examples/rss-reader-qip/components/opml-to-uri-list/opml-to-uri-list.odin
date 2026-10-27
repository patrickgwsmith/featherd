// opml-to-uri-list flattens an OPML subscription list to the feeds it
// names: the xmlUrl of every <outline>, at any depth, in order, without
// duplicates, and only http and https URLs. Output is text/uri-list.
package opml_to_uri_list

import "base:intrinsics"
import sh "../shared"

INPUT_CAP :: 1 << 20
OUTPUT_CAP :: INPUT_CAP

input_buf: [INPUT_CAP]u8
output_buf: [OUTPUT_CAP]u8
// One URL, decoded, before it's compared with those already written.
url_buf: [8 << 10]u8

INPUT_TYPE :: "text/x-opml"
OUTPUT_TYPE :: "text/uri-list"
input_type: [len(INPUT_TYPE)]u8 = INPUT_TYPE
output_type: [len(OUTPUT_TYPE)]u8 = OUTPUT_TYPE

@(export) input_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_buf[0])) }
@(export) input_utf8_cap :: proc "contextless" () -> u32 { return INPUT_CAP }
@(export) input_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_type[0])) }
@(export) input_content_type_size :: proc "contextless" () -> u32 { return len(INPUT_TYPE) }
@(export) output_utf8_cap :: proc "contextless" () -> u32 { return OUTPUT_CAP }
@(export) output_content_type_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&output_type[0])) }
@(export) output_content_type_size :: proc "contextless" () -> u32 { return len(OUTPUT_TYPE) }
// The one failure: malformed XML, at the offset where it starts.
@(export) failure_modes_per_input_offset :: proc "contextless" () -> u32 { return 1 }

@(export)
render :: proc "contextless" (input_size: u32) -> u64 {
	if input_size > INPUT_CAP {
		intrinsics.trap()
	}
	s := sh.Scanner{data = input_buf[:input_size]}
	out := sh.Writer{buf = output_buf[:]}
	for {
		t := sh.next(&s)
		#partial switch t.kind {
		case .EOF:
			return (u64(uintptr(&output_buf[0])) << 32) | u64(out.n)
		case .Error:
			return (u64(1) << 63) | u64(t.start)
		case .Start:
			if !sh.equal(sh.local_name(t.name), "outline") {
				continue
			}
			raw, ok := sh.attr(t.attrs, "xmlUrl")
			if !ok {
				continue
			}
			w := sh.Writer{buf = url_buf[:]}
			sh.write_decoded(&w, raw)
			url := sh.trim(sh.bytes(&w))
			if w.overflow || !(sh.has_prefix(url, "http://") || sh.has_prefix(url, "https://")) || written(sh.bytes(&out), url) {
				continue
			}
			// A URL can't hold a line break; one that does isn't a URL.
			if sh.index_byte(url, '\n') >= 0 || sh.index_byte(url, '\r') >= 0 {
				continue
			}
			sh.write(&out, url)
			sh.write_string(&out, "\r\n")
		}
	}
}

// written reports whether url is already one of the lines in list.
written :: proc "contextless" (list, url: []u8) -> bool {
	rest := list
	for len(rest) > 0 {
		eol := sh.index(rest, "\r\n")
		if string(rest[:eol]) == string(url) {
			return true
		}
		rest = rest[eol + 2:]
	}
	return false
}
