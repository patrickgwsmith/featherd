package shared

// Times are Unix seconds, UTC. Components have no clock: the host passes
// the current time as the `now_unix_seconds` uniform.

days_from_civil :: proc "contextless" (y, m, d: i64) -> i64 {
	yy := y - 1 if m <= 2 else y
	era := (yy if yy >= 0 else yy - 399) / 400
	yoe := yy - era * 400
	mp := (m + 9) % 12
	doy := (153 * mp + 2) / 5 + d - 1
	doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
	return era * 146097 + doe - 719468
}

civil_from_days :: proc "contextless" (days: i64) -> (y, m, d: i64) {
	z := days + 719468
	era := (z if z >= 0 else z - 146096) / 146097
	doe := z - era * 146097
	yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
	doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
	mp := (5 * doy + 2) / 153
	d = doy - (153 * mp + 2) / 5 + 1
	m = mp + 3 if mp < 10 else mp - 9
	y = yoe + era * 400
	if m <= 2 {
		y += 1
	}
	return
}

@(private)
floor_div :: proc "contextless" (a, b: i64) -> i64 {
	q := a / b
	if (a % b != 0) && ((a < 0) != (b < 0)) {
		q -= 1
	}
	return q
}

MONTHS := [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
WEEKDAYS := [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// write_rfc3339 writes t as 2006-01-02T15:04:05Z.
write_rfc3339 :: proc "contextless" (w: ^Writer, t: i64) {
	days := floor_div(t, 86400)
	secs := t - days * 86400
	y, m, d := civil_from_days(days)
	write_uint(w, u64(max(y, 0)), 4)
	write_byte(w, '-')
	write_uint(w, u64(m), 2)
	write_byte(w, '-')
	write_uint(w, u64(d), 2)
	write_byte(w, 'T')
	write_uint(w, u64(secs / 3600), 2)
	write_byte(w, ':')
	write_uint(w, u64(secs / 60 % 60), 2)
	write_byte(w, ':')
	write_uint(w, u64(secs % 60), 2)
	write_byte(w, 'Z')
}

// write_readable writes t as "Mon 2 Jan 2006, 15:04 UTC".
write_readable :: proc "contextless" (w: ^Writer, t: i64) {
	days := floor_div(t, 86400)
	secs := t - days * 86400
	y, m, d := civil_from_days(days)
	write_string(w, WEEKDAYS[(days % 7 + 11) % 7])
	write_byte(w, ' ')
	write_uint(w, u64(d))
	write_byte(w, ' ')
	write_string(w, MONTHS[m - 1])
	write_byte(w, ' ')
	write_uint(w, u64(max(y, 0)))
	write_string(w, ", ")
	write_uint(w, u64(secs / 3600), 2)
	write_byte(w, ':')
	write_uint(w, u64(secs / 60 % 60), 2)
	write_string(w, " UTC")
}

@(private)
Cursor :: struct {
	s: []u8,
	i: int,
}

@(private)
peek :: proc "contextless" (c: ^Cursor) -> u8 {
	return c.s[c.i] if c.i < len(c.s) else 0
}

@(private)
skip_spaces :: proc "contextless" (c: ^Cursor) {
	for c.i < len(c.s) && is_space(c.s[c.i]) {
		c.i += 1
	}
}

// digits reads between lo and hi decimal digits.
@(private)
digits :: proc "contextless" (c: ^Cursor, lo, hi: int) -> (v: i64, ok: bool) {
	n := 0
	for n < hi && c.i < len(c.s) && c.s[c.i] >= '0' && c.s[c.i] <= '9' {
		v = v * 10 + i64(c.s[c.i] - '0')
		c.i += 1
		n += 1
	}
	return v, n >= lo
}

@(private)
expect :: proc "contextless" (c: ^Cursor, b: u8) -> bool {
	if peek(c) == b {
		c.i += 1
		return true
	}
	return false
}

@(private)
alpha :: proc "contextless" (c: ^Cursor) -> []u8 {
	start := c.i
	for c.i < len(c.s) {
		b := c.s[c.i]
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')) {
			break
		}
		c.i += 1
	}
	return c.s[start:c.i]
}

// parse_date reads the date formats feeds use: RFC 3339 (Atom, Dublin
// Core) and RFC 822 with its many variants (RSS). A missing zone is UTC.
parse_date :: proc "contextless" (raw: []u8) -> (t: i64, ok: bool) {
	s := trim(raw)
	if len(s) >= 10 && s[4] == '-' {
		return parse_rfc3339(s)
	}
	return parse_rfc822(s)
}

@(private)
parse_rfc3339 :: proc "contextless" (s: []u8) -> (t: i64, ok: bool) {
	c := Cursor{s = s}
	y := digits(&c, 4, 4) or_return
	expect(&c, '-') or_return
	m := digits(&c, 2, 2) or_return
	expect(&c, '-') or_return
	d := digits(&c, 2, 2) or_return
	hh, mm, ss: i64
	offset: i64
	if c.i < len(s) {
		if !expect(&c, 'T') && !expect(&c, 't') && !expect(&c, ' ') {
			return 0, false
		}
		hh = digits(&c, 2, 2) or_return
		expect(&c, ':') or_return
		mm = digits(&c, 2, 2) or_return
		if expect(&c, ':') {
			ss = digits(&c, 2, 2) or_return
		}
		if expect(&c, '.') || expect(&c, ',') {
			digits(&c, 1, 9) or_return
		}
		offset = zone(&c) or_return
	}
	if c.i != len(s) {
		return 0, false
	}
	return assemble(y, m, d, hh, mm, ss, offset)
}

@(private)
parse_rfc822 :: proc "contextless" (s: []u8) -> (t: i64, ok: bool) {
	c := Cursor{s = s}
	// An optional weekday, which is ignored.
	if save := c.i; len(alpha(&c)) > 0 {
		if !expect(&c, ',') {
			skip_spaces(&c)
			if peek(&c) < '0' || peek(&c) > '9' {
				c.i = save
			}
		}
	}
	skip_spaces(&c)
	d := digits(&c, 1, 2) or_return
	skip_spaces(&c)
	expect(&c, '-')
	mon := alpha(&c)
	if len(mon) < 3 {
		return 0, false
	}
	m: i64 = 0
	for name, i in MONTHS {
		if equal_fold(mon[:3], lower3(name)) {
			m = i64(i + 1)
		}
	}
	if m == 0 {
		return 0, false
	}
	skip_spaces(&c)
	expect(&c, '-')
	start := c.i
	y := digits(&c, 2, 4) or_return
	if c.i - start == 2 {
		y += 2000 if y < 70 else 1900
	} else if c.i - start == 3 {
		return 0, false
	}
	skip_spaces(&c)
	hh, mm, ss, offset: i64
	if c.i < len(s) {
		hh = digits(&c, 1, 2) or_return
		expect(&c, ':') or_return
		mm = digits(&c, 2, 2) or_return
		if expect(&c, ':') {
			ss = digits(&c, 2, 2) or_return
		}
		skip_spaces(&c)
		offset = zone(&c) or_return
		skip_spaces(&c)
		// A trailing "(UTC)" or similar comment.
		if expect(&c, '(') {
			for c.i < len(s) && s[c.i] != ')' {
				c.i += 1
			}
			expect(&c, ')') or_return
		}
	}
	if c.i != len(s) {
		return 0, false
	}
	return assemble(y, m, d, hh, mm, ss, offset)
}

@(private)
lower3 :: proc "contextless" (name: string) -> string {
	switch name {
	case "Jan": return "jan"
	case "Feb": return "feb"
	case "Mar": return "mar"
	case "Apr": return "apr"
	case "May": return "may"
	case "Jun": return "jun"
	case "Jul": return "jul"
	case "Aug": return "aug"
	case "Sep": return "sep"
	case "Oct": return "oct"
	case "Nov": return "nov"
	}
	return "dec"
}

// zone reads a numeric offset (+0100, +01:00) or a named zone, in seconds
// east of UTC. A missing zone, or one it doesn't know, is UTC.
@(private)
zone :: proc "contextless" (c: ^Cursor) -> (offset: i64, ok: bool) {
	sign := peek(c)
	if sign == '+' || sign == '-' {
		c.i += 1
		h := digits(c, 2, 2) or_return
		expect(c, ':')
		m := digits(c, 2, 2) or_return
		offset = h * 3600 + m * 60
		return -offset if sign == '-' else offset, true
	}
	name := alpha(c)
	hours: i64 = 0
	switch {
	case equal_fold(name, "est"): hours = -5
	case equal_fold(name, "edt"): hours = -4
	case equal_fold(name, "cst"): hours = -6
	case equal_fold(name, "cdt"): hours = -5
	case equal_fold(name, "mst"): hours = -7
	case equal_fold(name, "mdt"): hours = -6
	case equal_fold(name, "pst"): hours = -8
	case equal_fold(name, "pdt"): hours = -7
	}
	return hours * 3600, true
}

@(private)
assemble :: proc "contextless" (y, m, d, hh, mm, ss, offset: i64) -> (t: i64, ok: bool) {
	if m < 1 || m > 12 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 60 {
		return 0, false
	}
	return days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss - offset, true
}
