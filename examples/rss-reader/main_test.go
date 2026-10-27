package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// featherdBin is featherd built from the repository root. The reader
// doesn't import featherd's code; the test runs the real server, with
// SigV4 on, so the reader's signing and conditional writes are checked
// against what featherd actually enforces.
var featherdBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rss-reader-test")
	if err != nil {
		log.Fatal(err)
	}
	featherdBin = filepath.Join(dir, "featherd")
	build := exec.Command("go", "build", "-o", featherdBin, ".")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		log.Fatalf("building featherd: %v\n%s", err, out)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const (
	testKeyID  = "rss-reader"
	testSecret = "0123456789abcdef0123456789abcdef"
)

// startFeatherd runs featherd on a free port and returns its URL.
func startFeatherd(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cmd := exec.Command(featherdBin, "--addr", addr, "--dir", t.TempDir())
	cmd.Env = append(os.Environ(), "FEATHERD_AUTH=sigv4",
		"FEATHERD_ACCESS_KEY_ID="+testKeyID, "FEATHERD_SECRET_ACCESS_KEY="+testSecret)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return "http://" + addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("featherd didn't start")
	return ""
}

// origins serves fake feeds whose bodies the test changes, with ETags, as
// the real sites do.
type origins struct {
	mu     sync.Mutex
	feeds  map[string]string
	broken map[string]bool
}

func (o *origins) set(path, body string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.feeds[path] = body
}

func (o *origins) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	body, ok := o.feeds[r.URL.Path]
	broken := o.broken[r.URL.Path]
	o.mu.Unlock()
	if broken {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + digest(body)[:8] + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	io.WriteString(w, body)
}

func rss(items ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>
<title>MacRumors</title><link>https://www.macrumors.com</link>
<atom:link href="https://feeds.macrumors.com/MacRumors-All" rel="self"/>
` + strings.Join(items, "\n") + `</channel></rss>`
}

func post(guid, title, date string) string {
	return fmt.Sprintf(`<item><title>%s</title><link>https://www.macrumors.com/%s</link>
<guid isPermaLink="false">%s</guid><pubDate>%s</pubDate>
<description><![CDATA[<p>About <b>%s</b>.</p>]]></description></item>`, title, guid, guid, date, title)
}

const atomFeed = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>Daring Fireball</title>
<entry><title>Linked: Something</title><link rel="alternate" href="/linked/2026/10/25/something"/>
<id>tag:daringfireball.net,2026:/linked//6.1</id><published>2026-10-25T20:00:00Z</published>
<updated>2026-10-25T20:00:00Z</updated><content type="html">&lt;p&gt;A link.&lt;/p&gt;</content></entry>
<entry><title type="html">&lt;script&gt;alert(1)&lt;/script&gt; Escaped</title><link href="javascript:alert(1)"/>
<id>tag:daringfireball.net,2026:/2</id><published>2026-10-24T09:00:00Z</published>
<updated>2026-10-24T09:00:00Z</updated><summary>Plain &amp; simple.</summary></entry>
</feed>`

type testEnv struct {
	r       *reader
	origins *origins
	base    string
	now     time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	o := &origins{feeds: map[string]string{}, broken: map[string]bool{}}
	srv := httptest.NewServer(o)
	t.Cleanup(srv.Close)
	env := &testEnv{origins: o, base: srv.URL, now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	endpoint := startFeatherd(t)
	r, err := newReader(func(k string) string {
		return map[string]string{
			"FEATHERD": endpoint, "BUCKET": "rss",
			"AWS_ACCESS_KEY_ID": testKeyID, "AWS_SECRET_ACCESS_KEY": testSecret,
		}[k]
	}, 25, 4)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return env.now }
	r.log = log.New(io.Discard, "", 0)
	if testing.Verbose() {
		r.log = log.New(os.Stderr, "rss-reader: ", 0)
	}
	env.r = r
	return env
}

func (env *testEnv) subscribe(t *testing.T, paths ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><opml version="2.0"><head><title>` + time.Now().String() + `</title></head><body>`)
	for _, p := range paths {
		fmt.Fprintf(&b, `<outline type="rss" text="%s" xmlUrl="%s%s"/>`, p, env.base, p)
	}
	b.WriteString(`</body></opml>`)
	ctx := context.Background()
	if err := env.r.s3.createBucket(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := env.r.s3.put(ctx, subscriptionsKey, "text/x-opml", []byte(b.String()), "", ""); err != nil {
		t.Fatal(err)
	}
}

func (env *testEnv) poll(t *testing.T) pollResult {
	t.Helper()
	res, err := env.r.poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (env *testEnv) keys(t *testing.T, prefix string) []string {
	t.Helper()
	keys, err := env.r.s3.list(context.Background(), prefix, 0)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func (env *testEnv) get(t *testing.T, key string) (string, int) {
	t.Helper()
	resp, err := env.r.s3.get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(resp.body), resp.status
}

func (env *testEnv) state(t *testing.T, path string) feedState {
	t.Helper()
	body, status := env.get(t, feedKey(env.base+path))
	if status != http.StatusOK {
		t.Fatalf("no state for %s", path)
	}
	return decodeState([]byte(body))
}

// TestRefresh follows the README's walkthrough: a first poll of two feeds,
// then a refresh where MacRumors changed, Daring Fireball didn't and a
// third feed is down.
func TestRefresh(t *testing.T) {
	env := newTestEnv(t)
	mrItems := []string{
		post("mr-1", "iPhone 18 rumor", "Sun, 25 Oct 2026 18:00:00 +0000"),
		post("mr-2", "macOS 27.1 beta", "Sun, 25 Oct 2026 12:00:00 GMT"),
		post("mr-3", "Future dated", "Fri, 01 Jan 2027 00:00:00 +0000"),
	}
	env.origins.set("/mr", rss(mrItems...))
	env.origins.set("/df", atomFeed)
	env.subscribe(t, "/mr", "/df")

	// First poll: every post is new, and each feed goes from New to Idle.
	res := env.poll(t)
	if res.Fetched != 2 || res.Added != 5 {
		t.Fatalf("first poll = %+v", res)
	}
	if got := len(env.keys(t, itemsPrefix)); got != 5 {
		t.Fatalf("%d items after first poll", got)
	}
	if st := env.state(t, "/mr"); st.State != "idle" || st.ETag == "" || st.URL != env.base+"/mr" {
		t.Fatalf("MacRumors state = %+v", st)
	}
	page, _ := env.get(t, indexKey)
	// The future-dated post is capped at the poll's time, so it's first;
	// the rest follow by date across both feeds.
	order := []string{"Future dated", "Linked: Something", "iPhone 18 rumor", "macOS 27.1 beta", "Escaped"}
	last := -1
	for _, title := range order {
		i := strings.Index(page, title)
		if i < last {
			t.Fatalf("%q out of order in view:\n%s", title, page)
		}
		last = i
	}
	if !strings.Contains(page, "<p>About iPhone 18 rumor.</p>") {
		t.Fatalf("snippet not plain text:\n%s", page)
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, "javascript:") {
		t.Fatalf("view isn't escaped:\n%s", page)
	}
	if !strings.Contains(page, env.base+"/linked/2026/10/25/something") {
		t.Fatalf("relative Atom link not resolved:\n%s", page)
	}

	// Refresh: MacRumors adds two posts and re-dates an old one, Daring
	// Fireball answers 304 and a third feed is down.
	env.now = env.now.Add(time.Hour)
	env.origins.set("/mr", rss(append([]string{
		post("mr-5", "New post two", "Mon, 26 Oct 2026 09:30:00 +0000"),
		post("mr-4", "New post one", "Mon, 26 Oct 2026 09:10:00 +0000"),
		post("mr-1", "iPhone 18 rumor (updated)", "Mon, 26 Oct 2026 09:20:00 +0000"),
	}, mrItems[1:]...)...))
	env.origins.broken["/down"] = true
	env.subscribe(t, "/mr", "/df", "/down")
	dfBefore := env.state(t, "/df")
	res = env.poll(t)
	if res.Fetched != 1 || res.NotModified != 1 || res.Failed != 1 || res.Added != 2 {
		t.Fatalf("refresh = %+v", res)
	}
	// The re-dated post keeps the key it was first stored under.
	if got := len(env.keys(t, itemsPrefix)); got != 7 {
		t.Fatalf("%d items after refresh, want 7", got)
	}
	if st := env.state(t, "/df"); st != dfBefore {
		t.Fatalf("Daring Fireball's state changed on 304: %+v", st)
	}
	down := env.state(t, "/down")
	if down.State != "failed" || down.N != 1 || !down.FirstFailedAt.Equal(env.now) ||
		!down.RetryAt.Equal(env.now.Add(15*time.Minute)) || !strings.Contains(down.Error, "502") {
		t.Fatalf("down state = %+v", down)
	}
	page, _ = env.get(t, indexKey)
	if i, j := strings.Index(page, "New post two"), strings.Index(page, "New post one"); i < 0 || j < i {
		t.Fatalf("new posts missing or out of order:\n%s", page)
	}

	// Before retry_at the failed feed isn't fetched; after it, it backs off
	// further; a week after it first failed it's Dead.
	env.now = env.now.Add(time.Minute)
	if res := env.poll(t); res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("poll before retry_at = %+v", res)
	}
	env.now = env.now.Add(15 * time.Minute)
	env.poll(t)
	if down := env.state(t, "/down"); down.N != 2 || !down.RetryAt.Equal(env.now.Add(30*time.Minute)) {
		t.Fatalf("second failure = %+v", down)
	}
	env.now = env.now.Add(8 * 24 * time.Hour)
	env.poll(t)
	if down := env.state(t, "/down"); down.State != "dead" || down.Config == "" {
		t.Fatalf("after 8 days = %+v", down)
	}
	env.now = env.now.Add(48 * time.Hour)
	if res := env.poll(t); res.Skipped != 1 {
		t.Fatalf("dead feed polled: %+v", res)
	}
	// Editing the config retries it once; it recovers and is Idle again.
	env.origins.broken["/down"] = false
	env.origins.set("/down", rss(post("d-1", "Back up", "Mon, 02 Nov 2026 00:00:00 +0000")))
	env.subscribe(t, "/mr", "/df", "/down")
	if res := env.poll(t); res.Fetched != 1 || res.Added != 1 {
		t.Fatalf("revived = %+v", res)
	}
	if down := env.state(t, "/down"); down.State != "idle" || down.N != 0 || down.Error != "" {
		t.Fatalf("revived state = %+v", down)
	}

	// Unsubscribing deletes the feed's state but keeps its posts.
	items := len(env.keys(t, itemsPrefix))
	env.subscribe(t, "/mr", "/down")
	if res := env.poll(t); res.Retired != 1 {
		t.Fatalf("retire = %+v", res)
	}
	if _, status := env.get(t, feedKey(env.base+"/df")); status != http.StatusNotFound {
		t.Fatalf("Daring Fireball's state not retired")
	}
	if got := len(env.keys(t, itemsPrefix)); got != items {
		t.Fatalf("retiring changed items: %d → %d", items, got)
	}
}

// TestCrashBetweenSeenAndItem checks that a post whose const/seen/ object
// was written, but not its item, is stored at the seen object's key the
// next time the feed changes.
func TestCrashBetweenSeenAndItem(t *testing.T) {
	env := newTestEnv(t)
	first := post("mr-1", "Lost", "Sun, 25 Oct 2026 18:00:00 +0000")
	env.origins.set("/mr", rss(first))
	env.subscribe(t, "/mr")
	env.poll(t)
	keys := env.keys(t, itemsPrefix)
	if len(keys) != 1 {
		t.Fatalf("items = %v", keys)
	}
	// featherd doesn't stop this DELETE yet; it stands in for the crash.
	ctx := context.Background()
	if _, err := env.r.s3.do(ctx, http.MethodDelete, keys[0], nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// The post comes back re-dated, which mustn't move it.
	env.origins.set("/mr", rss(post("mr-1", "Lost", "Mon, 26 Oct 2026 08:00:00 +0000")))
	if res := env.poll(t); res.Added != 1 {
		t.Fatalf("repair = %+v", res)
	}
	if again := env.keys(t, itemsPrefix); len(again) != 1 || again[0] != keys[0] {
		t.Fatalf("repaired at %v, want %s", again, keys[0])
	}
}

func TestMissingSubscriptions(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.r.poll(context.Background()); err == nil || !strings.Contains(err.Error(), subscriptionsKey) {
		t.Fatalf("poll without config = %v", err)
	}
}

func TestParseFeedFormats(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	rdf := `<?xml version="1.0" encoding="ISO-8859-1"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Caf` + "\xe9" + `</title></channel>
<item><title>One</title><link>https://example.com/1</link><dc:date>2026-10-20T10:00:00Z</dc:date></item>
<item><title>No ID</title></item>
</rdf:RDF>`
	title, entries, err := parseFeed([]byte(rdf), "https://example.com/feed", now)
	if err != nil {
		t.Fatal(err)
	}
	if title != "Café" || len(entries) != 1 || entries[0].ID != "https://example.com/1" ||
		entries[0].Published != "2026-10-20T10:00:00Z" {
		t.Fatalf("RSS 1.0 = %q %+v", title, entries)
	}
	if _, _, err := parseFeed([]byte(`<html><body>not a feed</body></html>`), "https://example.com/", now); err == nil {
		t.Fatal("parsed HTML as a feed")
	}
}

func TestStateRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s := feedState{State: "idle", URL: "https://example.com/feed", ETag: `"mr-v1"`, LastOK: now}.
		failed("https://example.com/feed", fmt.Errorf("timeout\nafter 30s"), "", now)
	want := s
	want.Error = "timeout after 30s" // one line per field
	got := decodeState(s.encode())
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if got.ETag != `"mr-v1"` || got.N != 1 || !got.RetryAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("failed state = %+v", got)
	}
}

func TestAWSEscape(t *testing.T) {
	q := canonicalQuery(url.Values{"prefix": {"const/items/"}, "list-type": {"2"}})
	if q != "list-type=2&prefix=const%2Fitems%2F" {
		t.Fatalf("canonical query = %s", q)
	}
	if got := awsEscape("a b/c~", true); got != "a%20b/c~" {
		t.Fatalf("escaped key = %s", got)
	}
}
