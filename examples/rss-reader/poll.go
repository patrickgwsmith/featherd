package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The bucket's prefixes, each with its own write rule:
//
//	config/  your input, edited by hand; the reader only reads it
//	mut/     per-feed state: created with If-None-Match: *, then replaced
//	         and deleted only with If-Match
//	const/   write-once: created with If-None-Match: *, never replaced or
//	         deleted
//	view/    projections, rebuilt from const/ by the one reader
const (
	subscriptionsKey = "config/subscriptions.opml"
	feedsPrefix      = "mut/feeds/"
	seenPrefix       = "const/seen/"
	itemsPrefix      = "const/items/"
	indexKey         = "view/index.html"
)

const (
	firstBackoff = 15 * time.Minute
	maxBackoff   = 24 * time.Hour
	// A feed failing for longer than this is Dead: it's no longer fetched
	// until config/subscriptions.opml changes.
	deadAfter    = 7 * 24 * time.Hour
	maxFeedBytes = 10 << 20
)

type reader struct {
	s3       *s3Client
	origins  *http.Client
	now      func() time.Time
	log      *log.Logger
	viewSize int
	parallel int
}

// feedState is the one object per feed, mut/feeds/{key}, stored as
// key=value lines. Only Idle, Failed and Dead are ever stored; Fetching,
// Storing and Committing exist only while a poll runs, so a crashed poll
// leaves the last stored state and is simply repeated. A feed with no
// object is New.
type feedState struct {
	State        string // idle, failed or dead
	URL          string
	ETag         string // the origin's validators, sent on the next fetch
	LastModified string
	LastOK       time.Time // the last fetch whose items were all stored

	N             int // failures in a row
	FirstFailedAt time.Time
	LastFailedAt  time.Time
	Error         string
	RetryAt       time.Time
	Config        string // when Dead: the config ETag it died under
}

func (s feedState) encode() []byte {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			// One line per field: a newline in a value would start another.
			fmt.Fprintf(&b, "%s=%s\n", k, strings.Join(strings.Fields(v), " "))
		}
	}
	tm := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	line("state", s.State)
	line("url", s.URL)
	line("etag", s.ETag)
	line("last_modified", s.LastModified)
	line("last_ok", tm(s.LastOK))
	if s.N > 0 {
		line("n", strconv.Itoa(s.N))
	}
	line("first_failed_at", tm(s.FirstFailedAt))
	line("last_failed_at", tm(s.LastFailedAt))
	line("error", s.Error)
	line("retry_at", tm(s.RetryAt))
	line("config", s.Config)
	return []byte(b.String())
}

func decodeState(data []byte) feedState {
	var s feedState
	tm := func(v string) time.Time {
		t, _ := time.Parse(time.RFC3339, v)
		return t
	}
	for _, l := range strings.Split(string(data), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "state":
			s.State = v
		case "url":
			s.URL = v
		case "etag":
			s.ETag = v
		case "last_modified":
			s.LastModified = v
		case "last_ok":
			s.LastOK = tm(v)
		case "n":
			s.N, _ = strconv.Atoi(v)
		case "first_failed_at":
			s.FirstFailedAt = tm(v)
		case "last_failed_at":
			s.LastFailedAt = tm(v)
		case "error":
			s.Error = v
		case "retry_at":
			s.RetryAt = tm(v)
		case "config":
			s.Config = v
		}
	}
	return s
}

// idle returns the state after a fetch whose items are all stored, with
// the failure fields cleared.
func (s feedState) idle(url, etag, lastModified string, now time.Time) feedState {
	return feedState{State: "idle", URL: url, ETag: etag, LastModified: lastModified, LastOK: now}
}

// failed returns the state after a failed poll. It keeps the last good
// validators, so the retry is still a conditional fetch, and backs off
// 15m, 30m, 1h … up to a day. Dead is decided by how long the feed has
// been failing, not by how often, so brief but frequent failures don't
// kill it.
func (s feedState) failed(url string, err error, configETag string, now time.Time) feedState {
	next := s
	next.URL = url
	if s.State != "failed" && s.State != "dead" {
		next.N, next.FirstFailedAt = 0, now
	}
	next.N++
	next.LastFailedAt, next.Error = now, err.Error()
	backoff := maxBackoff
	if next.N <= 7 {
		backoff = min(firstBackoff<<(next.N-1), maxBackoff)
	}
	next.State, next.RetryAt, next.Config = "failed", now.Add(backoff), ""
	if now.Sub(next.FirstFailedAt) > deadAfter {
		next.State, next.RetryAt, next.Config = "dead", time.Time{}, configETag
	}
	return next
}

// feedKey names a feed's state object: its host, to make listings
// readable, and a digest of the whole URL.
func feedKey(feedURL string) string {
	host := "feed"
	if u, err := url.Parse(feedURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return feedsPrefix + host + "-" + digest(feedURL)[:16]
}

// itemHash identifies a post. It includes the feed, so two feeds using the
// same GUID don't collide.
func itemHash(feedURL, id string) string {
	return digest(feedURL + "\n" + id)[:32]
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// invTS is an inverted timestamp, 9999999999 minus Unix seconds, so that
// const/items/ lists newest first.
func invTS(t time.Time) string {
	sec := min(max(t.Unix(), 0), 9999999999)
	return fmt.Sprintf("%010d", 9999999999-sec)
}

// pollResult summarises one pass, for the log and the tests.
type pollResult struct {
	Feeds, Fetched, NotModified, Failed, Skipped, Retired int
	Added                                                 int
}

// poll runs one pass: every subscribed feed that's due is fetched and its
// new posts stored, feeds no longer subscribed are retired, and the view is
// rebuilt if anything was added or it doesn't exist yet.
func (r *reader) poll(ctx context.Context) (pollResult, error) {
	var res pollResult
	if err := r.s3.createBucket(ctx); err != nil {
		return res, err
	}
	resp, err := r.s3.get(ctx, subscriptionsKey)
	if err != nil {
		return res, err
	}
	if resp.status == http.StatusNotFound {
		return res, fmt.Errorf("no %s in bucket %s; upload an OPML file there first", subscriptionsKey, r.s3.bucket)
	}
	urls, err := parseSubscriptions(resp.body)
	if err != nil {
		return res, fmt.Errorf("%s: %w", subscriptionsKey, err)
	}
	configETag := resp.etag
	res.Feeds = len(urls)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		added   atomic.Int64
		limiter = make(chan struct{}, r.parallel)
	)
	for _, u := range urls {
		wg.Add(1)
		limiter <- struct{}{}
		go func() {
			defer func() { <-limiter; wg.Done() }()
			outcome, n := r.pollFeed(ctx, u, configETag)
			added.Add(int64(n))
			mu.Lock()
			defer mu.Unlock()
			switch outcome {
			case "fetched":
				res.Fetched++
			case "not-modified":
				res.NotModified++
			case "failed":
				res.Failed++
			default:
				res.Skipped++
			}
		}()
	}
	wg.Wait()
	res.Added = int(added.Load())

	if res.Retired, err = r.retire(ctx, urls); err != nil {
		r.log.Printf("retiring feeds: %v", err)
	}

	rebuild := res.Added > 0
	if !rebuild {
		resp, err := r.s3.do(ctx, http.MethodHead, indexKey, nil, nil, nil)
		if err != nil {
			return res, err
		}
		rebuild = resp.status == http.StatusNotFound
	}
	if rebuild {
		if err := r.rebuildView(ctx); err != nil {
			return res, fmt.Errorf("rebuilding %s: %w", indexKey, err)
		}
	}
	return res, nil
}

// pollFeed takes one feed through the statechart and returns what happened
// and how many posts it added. The state object is the commit point: it
// moves to the origin's new ETag only after every post from that fetch is
// stored, so a failure partway leaves the old ETag and the next poll
// fetches the same content again.
func (r *reader) pollFeed(ctx context.Context, feedURL, configETag string) (string, int) {
	key := feedKey(feedURL)
	resp, err := r.s3.get(ctx, key)
	if err != nil {
		r.log.Printf("%s: reading state: %v", feedURL, err)
		return "failed", 0
	}
	var st feedState
	condition, value := "If-None-Match", "*" // New: no state object yet
	if resp.status == http.StatusOK {
		st = decodeState(resp.body)
		condition, value = "If-Match", resp.etag
	}

	now := r.now()
	switch st.State {
	case "failed":
		if now.Before(st.RetryAt) {
			return "skipped", 0
		}
	case "dead":
		if st.Config == configETag {
			return "skipped", 0
		}
		r.log.Printf("%s: %s changed, so retrying this dead feed once", feedURL, subscriptionsKey)
	}

	outcome, added, next, err := r.fetch(ctx, feedURL, st, now)
	if err != nil {
		r.log.Printf("%s: %v", feedURL, err)
		f := st.failed(feedURL, err, configETag, now)
		outcome, next = "failed", &f
	}
	if next == nil {
		return outcome, added // 304 while Idle: nothing to write
	}
	put, err := r.s3.put(ctx, key, "text/plain; charset=utf-8", next.encode(), condition, value)
	switch {
	case err != nil:
		r.log.Printf("%s: saving state: %v", feedURL, err)
	case put.status == http.StatusPreconditionFailed:
		// Another poller saved this feed's state first. Its posts are
		// stored either way; the next poll starts from its state.
		r.log.Printf("%s: state changed during this poll; leaving the other poller's", feedURL)
	case next.State == "dead":
		r.log.Printf("%s: dead after failing since %s; edit %s to retry it", feedURL, next.FirstFailedAt.Format(time.RFC3339), subscriptionsKey)
	}
	return outcome, added
}

// fetch makes a conditional GET of the feed and stores its posts. It
// returns the next state, or nil if nothing changed and nothing needs
// writing.
func (r *reader) fetch(ctx context.Context, feedURL string, st feedState, now time.Time) (string, int, *feedState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("User-Agent", "featherd-rss-reader/0.1")
	req.Header.Set("Accept", "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.1")
	if st.ETag != "" {
		req.Header.Set("If-None-Match", st.ETag)
	}
	if st.LastModified != "" {
		req.Header.Set("If-Modified-Since", st.LastModified)
	}
	resp, err := r.origins.Do(req)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if st.State == "idle" {
			return "not-modified", 0, nil, nil
		}
		next := st.idle(feedURL, st.ETag, st.LastModified, now)
		return "not-modified", 0, &next, nil
	case http.StatusOK:
	default:
		return "", 0, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return "", 0, nil, err
	}
	if len(body) > maxFeedBytes {
		return "", 0, nil, fmt.Errorf("feed larger than %d bytes", maxFeedBytes)
	}
	_, entries, err := parseFeed(body, feedURL, now)
	if err != nil {
		return "", 0, nil, err
	}
	added := 0
	for _, e := range entries {
		ok, err := r.storeEntry(ctx, feedURL, e)
		if err != nil {
			// The state keeps the old ETag, so these posts are fetched and
			// offered again next time.
			return "", added, nil, err
		}
		if ok {
			added++
		}
	}
	next := st.idle(feedURL, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), now)
	return "fetched", added, &next, nil
}

// storeEntry writes a post to const/ once, and reports whether this call
// added it.
//
// The item's key holds its date, so the log lists newest first, but a feed
// can re-date a post. So the first store also writes const/seen/{hash},
// holding the date part of the key, and every later fetch of the post reuses
// it: the post keeps one key for good. The seen object is written first; if
// the reader crashes before the item is written, the next fetch finds the
// seen object, writes the missing item at that key, and gets 412 for
// every item that's already there.
func (r *reader) storeEntry(ctx context.Context, feedURL string, e entry) (bool, error) {
	hash := itemHash(feedURL, e.ID)
	seenKey := seenPrefix + hash
	ts := invTS(e.sortTime)
	put, err := r.s3.put(ctx, seenKey, "text/plain; charset=utf-8", []byte(ts), "If-None-Match", "*")
	if err != nil {
		return false, err
	}
	if put.status == http.StatusPreconditionFailed {
		got, err := r.s3.get(ctx, seenKey)
		if err != nil {
			return false, err
		}
		if got.status != http.StatusOK {
			return false, fmt.Errorf("%s vanished", seenKey)
		}
		ts = strings.TrimSpace(string(got.body))
	}

	data, err := xml.MarshalIndent(e, "", "  ")
	if err != nil {
		return false, err
	}
	body := append([]byte(xml.Header), data...)
	put, err = r.s3.put(ctx, itemsPrefix+ts+"/"+hash, "application/atom+xml; type=entry", body, "If-None-Match", "*")
	if err != nil {
		return false, err
	}
	return put.status == http.StatusOK, nil
}

// retire deletes the state of every feed no longer in the subscriptions,
// with If-Match, so a state saved since it was read isn't lost. Its posts
// stay in const/ for good.
func (r *reader) retire(ctx context.Context, urls []string) (int, error) {
	keep := map[string]bool{}
	for _, u := range urls {
		keep[feedKey(u)] = true
	}
	keys, err := r.s3.list(ctx, feedsPrefix, 0)
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, key := range keys {
		if keep[key] {
			continue
		}
		head, err := r.s3.do(ctx, http.MethodHead, key, nil, nil, nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if head.status != http.StatusOK {
			continue
		}
		del, err := r.s3.do(ctx, http.MethodDelete, key, nil, nil, http.Header{"If-Match": {head.etag}})
		if err == nil {
			err = expect("DELETE", key, del, http.StatusNoContent, http.StatusOK, http.StatusPreconditionFailed)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if del.status != http.StatusPreconditionFailed {
			r.log.Printf("retired %s", key)
			n++
		}
	}
	return n, errors.Join(errs...)
}
