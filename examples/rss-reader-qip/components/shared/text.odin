package shared

// Writer appends to a fixed buffer. Running out of room sets overflow and
// drops the rest; the caller rejects the input rather than return a
// truncated result.
Writer :: struct {
	buf:      []u8,
	n:        int,
	overflow: bool,
}

bytes :: proc "contextless" (w: ^Writer) -> []u8 {
	return w.buf[:w.n]
}

write :: proc "contextless" (w: ^Writer, s: []u8) {
	if w.overflow {
		return
	}
	if len(s) > len(w.buf) - w.n {
		w.overflow = true
		return
	}
	copy(w.buf[w.n:], s)
	w.n += len(s)
}

write_string :: proc "contextless" (w: ^Writer, s: string) {
	write(w, transmute([]u8)s)
}

write_byte :: proc "contextless" (w: ^Writer, c: u8) {
	if w.overflow {
		return
	}
	if w.n >= len(w.buf) {
		w.overflow = true
		return
	}
	w.buf[w.n] = c
	w.n += 1
}

write_rune :: proc "contextless" (w: ^Writer, r: rune) {
	c := u32(r)
	switch {
	case c < 0x80:
		write_byte(w, u8(c))
	case c < 0x800:
		write_byte(w, u8(0xC0 | c >> 6))
		write_byte(w, u8(0x80 | c & 0x3F))
	case c < 0x10000:
		write_byte(w, u8(0xE0 | c >> 12))
		write_byte(w, u8(0x80 | (c >> 6) & 0x3F))
		write_byte(w, u8(0x80 | c & 0x3F))
	case:
		write_byte(w, u8(0xF0 | c >> 18))
		write_byte(w, u8(0x80 | (c >> 12) & 0x3F))
		write_byte(w, u8(0x80 | (c >> 6) & 0x3F))
		write_byte(w, u8(0x80 | c & 0x3F))
	}
}

write_uint :: proc "contextless" (w: ^Writer, v: u64, width := 0) {
	digits: [20]u8
	n := 0
	x := v
	for {
		digits[n] = u8('0' + x % 10)
		n += 1
		x /= 10
		if x == 0 {
			break
		}
	}
	for _ in n ..< width {
		write_byte(w, '0')
	}
	for n > 0 {
		n -= 1
		write_byte(w, digits[n])
	}
}

// write_xml_escaped writes s as XML character data or an attribute value.
write_xml_escaped :: proc "contextless" (w: ^Writer, s: []u8) {
	start := 0
	for c, i in s {
		esc: string
		switch c {
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		case '"':
			esc = "&quot;"
		case '\r':
			esc = "&#xD;"
		case:
			continue
		}
		write(w, s[start:i])
		write_string(w, esc)
		start = i + 1
	}
	write(w, s[start:])
}

// write_html_escaped writes s as HTML text or a quoted attribute value.
write_html_escaped :: proc "contextless" (w: ^Writer, s: []u8) {
	start := 0
	for c, i in s {
		esc: string
		switch c {
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		case '"':
			esc = "&#34;"
		case '\'':
			esc = "&#39;"
		case:
			continue
		}
		write(w, s[start:i])
		write_string(w, esc)
		start = i + 1
	}
	write(w, s[start:])
}

// Spaces collapses runs of whitespace to one space and drops it at either
// end, as strings.Fields joined with " " does.
Spaces :: struct {
	w:       ^Writer,
	pending: bool,
	started: bool,
}

spaces_space :: proc "contextless" (s: ^Spaces) {
	s.pending = s.started
}

spaces_write :: proc "contextless" (s: ^Spaces, b: []u8) {
	i := 0
	for i < len(b) {
		if n := space_len(b[i:]); n > 0 {
			spaces_space(s)
			i += n
			continue
		}
		j := i + 1
		for j < len(b) && space_len(b[j:]) == 0 {
			j += 1
		}
		if s.pending {
			write_byte(s.w, ' ')
			s.pending = false
		}
		write(s.w, b[i:j])
		s.started = true
		i = j
	}
}

spaces_rune :: proc "contextless" (s: ^Spaces, r: rune) {
	if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' || r == 0xA0 {
		spaces_space(s)
		return
	}
	if s.pending {
		write_byte(s.w, ' ')
		s.pending = false
	}
	write_rune(s.w, r)
	s.started = true
}

// space_len is the length of the whitespace at the start of b: ASCII
// whitespace or a no-break space, which feeds often use as a space.
@(private)
space_len :: proc "contextless" (b: []u8) -> int {
	if len(b) == 0 {
		return 0
	}
	if is_space(b[0]) || b[0] == '\f' || b[0] == '\v' {
		return 1
	}
	if len(b) >= 2 && b[0] == 0xC2 && b[1] == 0xA0 {
		return 2
	}
	return 0
}

// write_collapsed writes s with its whitespace collapsed.
write_collapsed :: proc "contextless" (w: ^Writer, s: []u8) {
	sp := Spaces{w = w}
	spaces_write(&sp, s)
}

// write_stripped turns an HTML fragment into plain text, for titles and
// snippets. Block tags become spaces and inline ones vanish, so
// "<p>a</p><p>b</p>" reads "a b" and "<b>a</b>." reads "a.". Entities are
// decoded after the tags are found, so "&lt;b&gt;" stays as text.
write_stripped :: proc "contextless" (w: ^Writer, s: []u8) {
	sp := Spaces{w = w}
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '<' {
			end := index_byte(s[i:], '>')
			if end < 0 {
				break
			}
			name := s[i + 1:i + end]
			for len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
			for k in 0 ..< len(name) {
				if is_space(name[k]) || name[k] == '/' {
					name = name[:k]
					break
				}
			}
			if !is_inline_tag(name) {
				spaces_space(&sp)
			}
			i += end + 1
			continue
		}
		if c == '&' {
			if n, r := html_entity(s[i:]); n > 0 {
				spaces_rune(&sp, r)
				i += n
				continue
			}
		}
		j := i + 1
		for j < len(s) && s[j] != '<' && s[j] != '&' {
			j += 1
		}
		spaces_write(&sp, s[i:j])
		i = j
	}
}

@(private)
is_inline_tag :: proc "contextless" (name: []u8) -> bool {
	lower: [8]u8
	if len(name) > len(lower) {
		return false
	}
	for c, i in name {
		lower[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	switch string(lower[:len(name)]) {
	case "a", "abbr", "b", "cite", "code", "em", "i", "kbd", "mark", "q", "s", "small", "span", "strong", "sub", "sup", "u":
		return true
	}
	return false
}

// html_entity decodes the HTML entity at the start of s: a character
// reference or one of the names feeds use most.
@(private)
html_entity :: proc "contextless" (s: []u8) -> (n: int, r: rune) {
	semi := -1
	for i in 1 ..< min(len(s), 10) {
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
	case "lt":     r = '<'
	case "gt":     r = '>'
	case "amp":    r = '&'
	case "quot":   r = '"'
	case "apos":   r = '\''
	case "nbsp":   r = 0xA0
	case "hellip": r = 0x2026
	case "mdash":  r = 0x2014
	case "ndash":  r = 0x2013
	case "lsquo":  r = 0x2018
	case "rsquo":  r = 0x2019
	case "ldquo":  r = 0x201C
	case "rdquo":  r = 0x201D
	case "copy":   r = 0xA9
	case "reg":    r = 0xAE
	case "trade":  r = 0x2122
	case "eacute": r = 0xE9
	case "middot": r = 0xB7
	case "bull":   r = 0x2022
	case "zwnj":   r = 0x200C
	case "zwj":    r = 0x200D
	case "shy":    r = 0xAD
	case "thinsp": r = 0x2009
	case "ensp":   r = 0x2002
	case "emsp":   r = 0x2003
	case "laquo":  r = 0xAB
	case "raquo":  r = 0xBB
	case "times":  r = 0xD7
	case "deg":    r = 0xB0
	case "euro":   r = 0x20AC
	case "pound":  r = 0xA3
	case "prime":  r = 0x2032
	case "aacute": r = 0xE1
	case "iacute": r = 0xED
	case "oacute": r = 0xF3
	case "uacute": r = 0xFA
	case "egrave": r = 0xE8
	case "agrave": r = 0xE0
	case "ntilde": r = 0xF1
	case "ccedil": r = 0xE7
	case "auml":   r = 0xE4
	case "ouml":   r = 0xF6
	case "uuml":   r = 0xFC
	case:
		return 0, 0
	}
	return semi + 1, r
}

is_space :: proc "contextless" (c: u8) -> bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

trim :: proc "contextless" (s: []u8) -> []u8 {
	a, b := 0, len(s)
	for a < b && is_space(s[a]) {
		a += 1
	}
	for b > a && is_space(s[b - 1]) {
		b -= 1
	}
	return s[a:b]
}

has_prefix :: proc "contextless" (s: []u8, prefix: string) -> bool {
	return len(s) >= len(prefix) && string(s[:len(prefix)]) == prefix
}

equal :: proc "contextless" (s: []u8, t: string) -> bool {
	return string(s) == t
}

// equal_fold compares s with a lowercase ASCII t, ignoring case.
equal_fold :: proc "contextless" (s: []u8, t: string) -> bool {
	if len(s) != len(t) {
		return false
	}
	for c, i in s {
		l := c + 32 if c >= 'A' && c <= 'Z' else c
		if l != t[i] {
			return false
		}
	}
	return true
}

index_byte :: proc "contextless" (s: []u8, c: u8) -> int {
	for b, i in s {
		if b == c {
			return i
		}
	}
	return -1
}

index :: proc "contextless" (s: []u8, sub: string) -> int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i + len(sub) <= len(s); i += 1 {
		if s[i] == sub[0] && string(s[i:i + len(sub)]) == sub {
			return i
		}
	}
	return -1
}

// truncate_runes returns s cut to at most n code points, and whether it
// was cut.
truncate_runes :: proc "contextless" (s: []u8, n: int) -> ([]u8, bool) {
	count := 0
	for c, i in s {
		if c & 0xC0 != 0x80 {
			if count == n {
				return s[:i], true
			}
			count += 1
		}
	}
	return s, false
}

// write_utf8_sanitized copies s, replacing each invalid UTF-8 sequence with
// U+FFFD and dropping the control characters XML doesn't allow.
write_utf8_sanitized :: proc "contextless" (w: ^Writer, s: []u8) {
	i := 0
	for i < len(s) {
		c := s[i]
		if c < 0x80 {
			j := i
			for j < len(s) && s[j] < 0x80 && (s[j] >= 0x20 || s[j] == '\t' || s[j] == '\n') {
				j += 1
			}
			write(w, s[i:j])
			if j == i {
				write_line_end(w, s, j)
				j += 1 // a carriage return, or a control character to drop
			}
			i = j
			continue
		}
		n := utf8_len(s[i:])
		if n == 0 {
			write_rune(w, 0xFFFD)
			i += 1
		} else {
			write(w, s[i:i + n])
			i += n
		}
	}
}

// write_latin1 decodes ISO-8859-1 to UTF-8. Windows-1252 differs only in
// 0x80–0x9F, which are rare enough in feeds to pass through as Latin-1.
write_latin1 :: proc "contextless" (w: ^Writer, s: []u8) {
	for c, i in s {
		if c >= 0x80 {
			write_rune(w, rune(c))
		} else if c >= 0x20 || c == '\t' || c == '\n' {
			write_byte(w, c)
		} else {
			write_line_end(w, s, i)
		}
	}
}

// write_line_end handles a control character at s[i] as XML's end-of-line
// rule says: a lone CR becomes LF, a CR before LF is dropped, and other
// control characters, which XML doesn't allow, are dropped too.
@(private)
write_line_end :: proc "contextless" (w: ^Writer, s: []u8, i: int) {
	if s[i] == '\r' && (i + 1 >= len(s) || s[i + 1] != '\n') {
		write_byte(w, '\n')
	}
}

// utf8_len is the length of the valid UTF-8 sequence at the start of s, or
// 0 if it isn't one.
utf8_len :: proc "contextless" (s: []u8) -> int {
	cont :: proc "contextless" (s: []u8, i: int) -> bool {
		return i < len(s) && s[i] & 0xC0 == 0x80
	}
	b := s[0]
	switch {
	case b < 0x80:
		return 1
	case b >= 0xC2 && b <= 0xDF:
		return 2 if cont(s, 1) else 0
	case b >= 0xE0 && b <= 0xEF:
		if !cont(s, 1) || !cont(s, 2) {
			return 0
		}
		if (b == 0xE0 && s[1] < 0xA0) || (b == 0xED && s[1] >= 0xA0) {
			return 0
		}
		return 3
	case b >= 0xF0 && b <= 0xF4:
		if !cont(s, 1) || !cont(s, 2) || !cont(s, 3) {
			return 0
		}
		if (b == 0xF0 && s[1] < 0x90) || (b == 0xF4 && s[1] >= 0x90) {
			return 0
		}
		return 4
	}
	return 0
}
