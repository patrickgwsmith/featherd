// feed-state is one step of a feed's statechart: the state stored under
// mut/feeds/, and what just happened to the feed, give the state to store
// next.
//
// Input is the stored state's key=value lines (none for a New feed), a
// blank line, then the event's key=value lines:
//
//	event=fetched       etag=, last_modified=  every post from a 200 is stored
//	event=not_modified                         the origin answered 304
//	event=failed        error=, config=        the fetch or a store failed
//
// Each event also has url=. Output is the next state's lines, or nothing
// when there's nothing to write: a 304 for an Idle feed.
//
// Uniform `now_unix_seconds` (i64 Unix seconds) is the time of the event.
package feed_state

import "base:intrinsics"
import sh "../shared"

INPUT_CAP :: 64 << 10
OUTPUT_CAP :: INPUT_CAP + 1024

input_buf: [INPUT_CAP]u8
output_buf: [OUTPUT_CAP]u8

FIRST_BACKOFF :: 15 * 60
MAX_BACKOFF :: 24 * 3600
// A feed failing for longer than this is Dead: it's no longer fetched
// until config/subscriptions.opml changes.
DEAD_AFTER :: 7 * 24 * 3600

now_unix_seconds_default :: 0
now_unix_seconds: i64 = now_unix_seconds_default

@(export) input_ptr :: proc "contextless" () -> u32 { return u32(uintptr(&input_buf[0])) }
@(export) input_utf8_cap :: proc "contextless" () -> u32 { return INPUT_CAP }
@(export) output_utf8_cap :: proc "contextless" () -> u32 { return OUTPUT_CAP }
@(export) failure_modes_per_input_offset :: proc "contextless" () -> u32 { return 1 }

@(export)
uniform_set_now_unix_seconds :: proc "contextless" (v: i64) -> i64 {
	now_unix_seconds = v
	return now_unix_seconds
}

Time :: struct {
	t:   i64,
	set: bool,
}

State :: struct {
	state, url, etag, last_modified: []u8,
	last_ok:                         Time,
	n:                               i64,
	first_failed_at, last_failed_at: Time,
	error:                           []u8,
	retry_at:                        Time,
	config:                          []u8, // when Dead: the config ETag it died under
}

Event :: struct {
	event, url, etag, last_modified, error, config: []u8,
}

@(export)
render :: proc "contextless" (input_size: u32) -> u64 {
	if input_size > INPUT_CAP {
		intrinsics.trap()
	}
	input := input_buf[:input_size]
	t := now_unix_seconds
	now_unix_seconds = now_unix_seconds_default

	// A New feed has no state lines, so its input starts with the blank line.
	state_lines: []u8
	event_at := 1
	if !sh.has_prefix(input, "\n") {
		split := sh.index(input, "\n\n")
		if split < 0 {
			return reject(len(input))
		}
		state_lines, event_at = input[:split + 1], split + 2
	}

	s: State
	sl := Lines{rest = state_lines}
	for line in lines_next(&sl) {
		k, v := cut(line)
		switch string(k) {
		case "state":           s.state = v
		case "url":             s.url = v
		case "etag":            s.etag = v
		case "last_modified":   s.last_modified = v
		case "last_ok":         s.last_ok = time(v)
		case "n":               s.n = number(v)
		case "first_failed_at": s.first_failed_at = time(v)
		case "last_failed_at":  s.last_failed_at = time(v)
		case "error":           s.error = v
		case "retry_at":        s.retry_at = time(v)
		case "config":          s.config = v
		}
	}
	e: Event
	el := Lines{rest = input[event_at:]}
	for line in lines_next(&el) {
		k, v := cut(line)
		switch string(k) {
		case "event":         e.event = v
		case "url":           e.url = v
		case "etag":          e.etag = v
		case "last_modified": e.last_modified = v
		case "error":         e.error = v
		case "config":        e.config = v
		}
	}

	next: State
	switch string(e.event) {
	case "fetched":
		next = idle(e.url, e.etag, e.last_modified, t)
	case "not_modified":
		if sh.equal(s.state, "idle") {
			return result(0) // nothing changed and nothing to write
		}
		next = idle(e.url, s.etag, s.last_modified, t)
	case "failed":
		next = failed(s, e, t)
	case:
		return reject(event_at)
	}
	w := sh.Writer{buf = output_buf[:]}
	encode(&w, next)
	if w.overflow {
		intrinsics.trap() // the output capacity covers every input
	}
	return result(w.n)
}

result :: proc "contextless" (n: int) -> u64 {
	return (u64(uintptr(&output_buf[0])) << 32) | u64(n)
}

reject :: proc "contextless" (offset: int) -> u64 {
	return (u64(1) << 63) | u64(offset)
}

// idle is the state after a fetch whose posts are all stored, with the
// failure fields cleared.
idle :: proc "contextless" (url, etag, last_modified: []u8, t: i64) -> State {
	return State{state = transmute([]u8)string("idle"), url = url, etag = etag, last_modified = last_modified, last_ok = {t, true}}
}

// failed is the state after a failed poll. It keeps the last good
// validators, so the retry is still a conditional fetch, and backs off
// 15m, 30m, 1h … up to a day. Dead is decided by how long the feed has
// been failing, not by how often, so brief but frequent failures don't
// kill it.
failed :: proc "contextless" (s: State, e: Event, t: i64) -> State {
	next := s
	next.url = e.url
	if !sh.equal(s.state, "failed") && !sh.equal(s.state, "dead") {
		next.n = 0
		next.first_failed_at = {t, true}
	}
	next.n += 1
	next.last_failed_at = {t, true}
	next.error = e.error
	backoff: i64 = MAX_BACKOFF
	if next.n <= 7 {
		backoff = min(i64(FIRST_BACKOFF) << u64(next.n - 1), MAX_BACKOFF)
	}
	next.state = transmute([]u8)string("failed")
	next.retry_at = {t + backoff, true}
	next.config = nil
	if t - next.first_failed_at.t > DEAD_AFTER {
		next.state = transmute([]u8)string("dead")
		next.retry_at = {}
		next.config = e.config
	}
	return next
}

encode :: proc "contextless" (w: ^sh.Writer, s: State) {
	line :: proc "contextless" (w: ^sh.Writer, k: string, v: []u8) {
		if len(sh.trim(v)) == 0 {
			return
		}
		sh.write_string(w, k)
		sh.write_byte(w, '=')
		// One line per field: a newline in a value would start another.
		sh.write_collapsed(w, v)
		sh.write_byte(w, '\n')
	}
	tm :: proc "contextless" (w: ^sh.Writer, k: string, t: Time) {
		if t.set {
			sh.write_string(w, k)
			sh.write_byte(w, '=')
			sh.write_rfc3339(w, t.t)
			sh.write_byte(w, '\n')
		}
	}
	line(w, "state", s.state)
	line(w, "url", s.url)
	line(w, "etag", s.etag)
	line(w, "last_modified", s.last_modified)
	tm(w, "last_ok", s.last_ok)
	if s.n > 0 {
		sh.write_string(w, "n=")
		sh.write_uint(w, u64(s.n))
		sh.write_byte(w, '\n')
	}
	tm(w, "first_failed_at", s.first_failed_at)
	tm(w, "last_failed_at", s.last_failed_at)
	line(w, "error", s.error)
	tm(w, "retry_at", s.retry_at)
	line(w, "config", s.config)
}

Lines :: struct {
	rest: []u8,
}

// lines_next is an iterator: for line in lines_next(&l).
lines_next :: proc "contextless" (l: ^Lines) -> (line: []u8, i: int, ok: bool) {
	if len(l.rest) == 0 {
		return
	}
	nl := sh.index_byte(l.rest, '\n')
	if nl < 0 {
		line, l.rest = l.rest, nil
	} else {
		line, l.rest = l.rest[:nl], l.rest[nl + 1:]
	}
	if len(line) > 0 && line[len(line) - 1] == '\r' {
		line = line[:len(line) - 1]
	}
	return line, 0, true
}

cut :: proc "contextless" (line: []u8) -> (k, v: []u8) {
	eq := sh.index_byte(line, '=')
	if eq < 0 {
		return line, nil
	}
	return line[:eq], line[eq + 1:]
}

time :: proc "contextless" (v: []u8) -> Time {
	t, ok := sh.parse_date(v)
	return {t, ok}
}

number :: proc "contextless" (v: []u8) -> i64 {
	n: i64 = 0
	for c in v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n * 10 + i64(c - '0')
	}
	return n
}
