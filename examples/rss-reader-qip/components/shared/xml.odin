// Package shared holds what the components have in common: a small XML
// scanner, text and HTML helpers, dates, and a bounded output writer. It
// allocates nothing, so every component runs with fixed memory.
package shared

// Kind is a token's kind. Comments, processing instructions and the
// doctype are skipped, so the scanner never returns them.
Kind :: enum u8 {
	EOF,
	Start,
	End,
	Text,
	CData,
	Error,
}

// Token is one piece of the document. name is the qualified name, attrs
// the raw bytes between the name and the closing > or />, and text the raw
// text (entities not yet decoded) or the CDATA contents. start and end are
// the token's offsets in the document.
Token :: struct {
	kind:         Kind,
	self_closing: bool,
	name:         []u8,
	attrs:        []u8,
	text:         []u8,
	start, end:   int,
}

// Scanner reads a document as tokens. It's lenient, as feeds need: it
// doesn't check that end tags match start tags, and attribute values may be
// unquoted. It fails only where it can't tell where a token ends.
Scanner :: struct {
	data: []u8,
	pos:  int,
}

next :: proc "contextless" (s: ^Scanner) -> Token {
	d := s.data
	for {
		start := s.pos
		if start >= len(d) {
			return Token{kind = .EOF, start = start, end = start}
		}
		if d[start] != '<' {
			i := start
			for i < len(d) && d[i] != '<' {
				i += 1
			}
			s.pos = i
			return Token{kind = .Text, text = d[start:i], start = start, end = i}
		}
		rest := d[start:]
		switch {
		case has_prefix(rest, "<!--"):
			i := index(rest[4:], "-->")
			if i < 0 {
				return error_at(s, start)
			}
			s.pos = start + 4 + i + 3
			continue
		case has_prefix(rest, "<![CDATA["):
			i := index(rest[9:], "]]>")
			if i < 0 {
				return error_at(s, start)
			}
			s.pos = start + 9 + i + 3
			return Token{kind = .CData, text = rest[9:9 + i], start = start, end = s.pos}
		case has_prefix(rest, "<?"):
			i := index(rest[2:], "?>")
			if i < 0 {
				return error_at(s, start)
			}
			s.pos = start + 2 + i + 2
			continue
		case has_prefix(rest, "<!"):
			// A doctype, perhaps with an internal subset in brackets.
			depth := 0
			i := 2
			for ; i < len(rest); i += 1 {
				c := rest[i]
				if c == '[' {
					depth += 1
				} else if c == ']' {
					depth -= 1
				} else if c == '>' && depth <= 0 {
					break
				}
			}
			if i >= len(rest) {
				return error_at(s, start)
			}
			s.pos = start + i + 1
			continue
		case has_prefix(rest, "</"):
			i := index_byte(rest, '>')
			if i < 0 {
				return error_at(s, start)
			}
			s.pos = start + i + 1
			return Token{kind = .End, name = trim(rest[2:i]), start = start, end = s.pos}
		}

		// A start tag: its name, then attributes up to a > outside quotes.
		i := 1
		for i < len(rest) && !is_space(rest[i]) && rest[i] != '>' && rest[i] != '/' {
			i += 1
		}
		if i == 1 {
			return error_at(s, start)
		}
		name := rest[1:i]
		attrs_start := i
		quote: u8 = 0
		for ; i < len(rest); i += 1 {
			c := rest[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else if c == '"' || c == '\'' {
				quote = c
			} else if c == '>' {
				break
			}
		}
		if i >= len(rest) {
			return error_at(s, start)
		}
		attrs := rest[attrs_start:i]
		self_closing := len(attrs) > 0 && attrs[len(attrs) - 1] == '/'
		if self_closing {
			attrs = attrs[:len(attrs) - 1]
		}
		s.pos = start + i + 1
		return Token{kind = .Start, name = name, attrs = attrs, self_closing = self_closing, start = start, end = s.pos}
	}
}

@(private)
error_at :: proc "contextless" (s: ^Scanner, at: int) -> Token {
	s.pos = len(s.data)
	return Token{kind = .Error, start = at, end = at}
}

// skip_element moves past the end of the element whose start tag was just
// read, and returns where its contents end: the offset of its end tag. It
// counts depth rather than matching names, as the scanner is lenient.
skip_element :: proc "contextless" (s: ^Scanner, start: Token) -> (inner_end: int, ok: bool) {
	if start.self_closing {
		return start.end, true
	}
	depth := 1
	for {
		t := next(s)
		#partial switch t.kind {
		case .Start:
			if !t.self_closing {
				depth += 1
			}
		case .End:
			depth -= 1
			if depth == 0 {
				return t.start, true
			}
		case .EOF, .Error:
			return t.start, false
		}
	}
}

// local_name drops a name's namespace prefix: "dc:date" is "date".
local_name :: proc "contextless" (name: []u8) -> []u8 {
	for i := len(name) - 1; i >= 0; i -= 1 {
		if name[i] == ':' {
			return name[i + 1:]
		}
	}
	return name
}

// attr returns the raw value of the attribute with this local name.
attr :: proc "contextless" (attrs: []u8, want: string) -> (value: []u8, ok: bool) {
	i := 0
	for i < len(attrs) {
		for i < len(attrs) && is_space(attrs[i]) {
			i += 1
		}
		name_start := i
		for i < len(attrs) && attrs[i] != '=' && !is_space(attrs[i]) {
			i += 1
		}
		name := attrs[name_start:i]
		for i < len(attrs) && is_space(attrs[i]) {
			i += 1
		}
		if i >= len(attrs) || attrs[i] != '=' {
			if len(name) == 0 {
				i += 1 // a stray byte; step over it
			}
			continue // an attribute with no value
		}
		i += 1
		for i < len(attrs) && is_space(attrs[i]) {
			i += 1
		}
		v_start, v_end: int
		if i < len(attrs) && (attrs[i] == '"' || attrs[i] == '\'') {
			q := attrs[i]
			i += 1
			v_start = i
			for i < len(attrs) && attrs[i] != q {
				i += 1
			}
			v_end = i
			i += 1
		} else {
			v_start = i
			for i < len(attrs) && !is_space(attrs[i]) {
				i += 1
			}
			v_end = i
		}
		if equal(local_name(name), want) {
			return attrs[v_start:min(v_end, len(attrs))], true
		}
	}
	return nil, false
}

// write_decoded writes text with XML's entities and character references
// decoded. An unknown entity, such as an HTML &nbsp; in a feed that never
// declared it, is kept as written.
write_decoded :: proc "contextless" (w: ^Writer, raw: []u8) {
	i := 0
	for i < len(raw) {
		c := raw[i]
		if c != '&' {
			j := i
			for j < len(raw) && raw[j] != '&' {
				j += 1
			}
			write(w, raw[i:j])
			i = j
			continue
		}
		n, r := xml_entity(raw[i:])
		if n == 0 {
			write_byte(w, '&')
			i += 1
			continue
		}
		write_rune(w, r)
		i += n
	}
}

// xml_entity decodes the entity at the start of s, returning its length,
// or 0 if it isn't one of XML's.
@(private)
xml_entity :: proc "contextless" (s: []u8) -> (n: int, r: rune) {
	semi := -1
	for i in 1 ..< min(len(s), 12) {
		if s[i] == ';' {
			semi = i
			break
		}
	}
	if semi < 0 {
		return 0, 0
	}
	name := s[1:semi]
	if len(name) > 1 && name[0] == '#' {
		if v, ok := char_ref(name[1:]); ok {
			return semi + 1, v
		}
		return 0, 0
	}
	switch string(name) {
	case "lt":
		return semi + 1, '<'
	case "gt":
		return semi + 1, '>'
	case "amp":
		return semi + 1, '&'
	case "quot":
		return semi + 1, '"'
	case "apos":
		return semi + 1, '\''
	}
	return 0, 0
}

// char_ref parses the digits of &#N; or &#xN;, replacing a code point that
// isn't a valid character with U+FFFD.
char_ref :: proc "contextless" (digits: []u8) -> (r: rune, ok: bool) {
	hex := len(digits) > 0 && (digits[0] == 'x' || digits[0] == 'X')
	d := digits[1:] if hex else digits
	if len(d) == 0 {
		return 0, false
	}
	v: u32 = 0
	for c in d {
		x: u32
		switch {
		case c >= '0' && c <= '9':
			x = u32(c - '0')
		case hex && c >= 'a' && c <= 'f':
			x = u32(c - 'a' + 10)
		case hex && c >= 'A' && c <= 'F':
			x = u32(c - 'A' + 10)
		case:
			return 0, false
		}
		v = v * (16 if hex else 10) + x
		if v > 0x10FFFF {
			return 0xFFFD, true
		}
	}
	if v == 0 || (v >= 0xD800 && v <= 0xDFFF) {
		return 0xFFFD, true
	}
	return rune(v), true
}

// write_inner_text writes the character data of doc[from:to], decoded,
// with any markup inside it left out.
write_inner_text :: proc "contextless" (w: ^Writer, doc: []u8, from, to: int) {
	s := Scanner{data = doc[:to], pos = from}
	for {
		t := next(&s)
		#partial switch t.kind {
		case .Text:
			write_decoded(w, t.text)
		case .CData:
			write(w, t.text)
		case .EOF, .Error:
			return
		}
	}
}
