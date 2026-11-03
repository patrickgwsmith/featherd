package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// featherdBin is featherd built from the repository root, run with SigV4
// on, so cve-sync's PUTs are checked against what featherd enforces.
var featherdBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cve-sync-test")
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
	testKeyID  = "cve-sync"
	testSecret = "0123456789abcdef0123456789abcdef"
)

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

// fakeGitHub serves info/refs and raw files at commits, and counts the raw
// requests per path.
type fakeGitHub struct {
	mu      sync.Mutex
	head    string
	files   map[string]map[string]string // commit → path → body
	broken  map[string]bool
	fetched map[string]int
	onRefs  func() // called before answering info/refs
	// web serves the vendor pages and OSV, by host and path, through
	// webTransport.
	web map[string]webPage
}

type webPage struct {
	contentType, etag, body string
}

// webTransport sends every request to the fake, under /web/<host><path>.
type webTransport struct{ base string }

func (t webTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	u := *r.URL
	r.URL, r.Host = &u, ""
	u.Path = "/web/" + r.URL.Host + u.Path
	base, _ := http.NewRequest("GET", t.base, nil)
	u.Scheme, u.Host = base.URL.Scheme, base.URL.Host
	return http.DefaultTransport.RoundTrip(r)
}

func (g *fakeGitHub) commit(sha string, files map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.head = sha
	g.files[sha] = files
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/info/refs" && g.onRefs != nil {
		g.onRefs()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if hostPath, ok := strings.CutPrefix(r.URL.Path, "/web/"); ok {
		g.fetched[hostPath]++
		p, ok := g.web[hostPath]
		if !ok || g.broken[hostPath] {
			http.NotFound(w, r)
			return
		}
		if p.etag != "" {
			if r.Header.Get("If-None-Match") == p.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", p.etag)
		}
		w.Header().Set("Content-Type", p.contentType)
		io.WriteString(w, p.body)
		return
	}
	if r.URL.Path == "/info/refs" {
		pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
		io.WriteString(w, pkt("# service=git-upload-pack\n")+"0000"+
			pkt(g.head+" HEAD\x00multi_ack symref=HEAD:refs/heads/main\n")+
			pkt(g.head+" refs/heads/main\n")+"0000")
		return
	}
	commit, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/raw/"), "/")
	g.fetched[path]++
	if g.broken[path] {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	body, ok := g.files[commit][path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	io.WriteString(w, body)
}

func record(id, title string) string {
	return fmt.Sprintf(`{"dataType":"CVE_RECORD","cveMetadata":{"cveId":%q},"containers":{"cna":{"title":%q}}}`, id, title)
}

// deltaLog builds cves/deltaLog.json, newest first as cvelistV5 writes it.
func deltaLog(entries ...delta) string {
	type c struct {
		CVEID       string `json:"cveId"`
		GitHubLink  string `json:"githubLink"`
		DateUpdated string `json:"dateUpdated"`
	}
	type d struct {
		FetchTime string `json:"fetchTime"`
		New       []c    `json:"new"`
		Updated   []c    `json:"updated"`
		Error     []c    `json:"error"`
	}
	conv := func(cs []change) []c {
		out := []c{}
		for _, x := range cs {
			out = append(out, c(x))
		}
		return out
	}
	out := []d{}
	for _, e := range entries {
		out = append(out, d{e.FetchTime, conv(e.New), conv(e.Updated), conv(e.Error)})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func ch(id string) change {
	p, _ := recordPath(change{CVEID: id})
	return change{CVEID: id, GitHubLink: "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/" + p}
}

type testEnv struct {
	s  *syncer
	gh *fakeGitHub
}

func newTestEnv(t *testing.T) *testEnv {
	base := startFeatherd(t)
	gh := &fakeGitHub{files: map[string]map[string]string{}, broken: map[string]bool{}, fetched: map[string]int{}, web: map[string]webPage{}}
	srv := httptest.NewServer(gh)
	t.Cleanup(srv.Close)
	env := map[string]string{"FEATHERD": base, "AWS_ACCESS_KEY_ID": testKeyID, "AWS_SECRET_ACCESS_KEY": testSecret}
	s, err := newSyncer(func(k string) string { return env[k] }, 4)
	if err != nil {
		t.Fatal(err)
	}
	s.refsURL, s.rawBase = srv.URL+"/info/refs", srv.URL+"/raw/"
	s.web = &http.Client{Transport: webTransport{srv.URL}}
	s.log = log.New(io.Discard, "", 0)
	if err := s.s3.createBucket(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &testEnv{s: s, gh: gh}
}

func (env *testEnv) sync(t *testing.T) syncResult {
	t.Helper()
	res, err := env.s.sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return res
}

// object GETs key through featherd, returning its body, ETag and
// Content-Type, or a status of 404.
func (env *testEnv) object(t *testing.T, key string) (body, etag, contentType string, status int) {
	t.Helper()
	c := env.s.s3
	path := "/" + c.bucket + "/" + key
	req, _ := http.NewRequest(http.MethodGet, c.endpoint.Scheme+"://"+c.endpoint.Host+path, nil)
	c.sign(req, path, "", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.Header.Get("ETag"), resp.Header.Get("Content-Type"), resp.StatusCode
}

func (env *testEnv) state(t *testing.T) syncState {
	t.Helper()
	body, _, _, status := env.object(t, stateKey)
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d", stateKey, status)
	}
	return decodeState([]byte(body))
}

const (
	sha1 = "1111111111111111111111111111111111111111"
	sha2 = "2222222222222222222222222222222222222222"
	sha3 = "3333333333333333333333333333333333333333"
	sha4 = "4444444444444444444444444444444444444444"
)

func TestSync(t *testing.T) {
	env := newTestEnv(t)
	a, b, c := ch("CVE-2026-0001"), ch("CVE-2026-120339"), ch("CVE-2025-31337")
	// a is new then updated: fetched once, at HEAD's version.
	env.gh.commit(sha1, map[string]string{
		"cves/deltaLog.json": deltaLog(
			delta{FetchTime: "2026-11-02T02:00:00.000Z", Updated: []change{a}, Error: []change{c}},
			delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{a, b}},
		),
		"cves/2026/0xxx/CVE-2026-0001.json":     record("CVE-2026-0001", "a v2"),
		"cves/2026/120xxx/CVE-2026-120339.json": record("CVE-2026-120339", "b"),
	})

	res := env.sync(t)
	if res.Deltas != 2 || res.Stored != 2 || res.Errors != 1 || !res.First || res.Gap {
		t.Fatalf("first sync: %+v", res)
	}
	body, etag, ct, _ := env.object(t, "cves/2026/0xxx/CVE-2026-0001.json")
	sum := sha256.Sum256([]byte(body))
	if body != record("CVE-2026-0001", "a v2") || ct != "application/json" || etag != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Fatalf("record: %q %q %q", body, ct, etag)
	}
	if n := env.gh.fetched["cves/2026/0xxx/CVE-2026-0001.json"]; n != 1 {
		t.Fatalf("a fetched %d times", n)
	}
	st := env.state(t)
	if st.Commit != sha1 || st.FetchTime.Format(time.RFC3339) != "2026-11-02T02:00:00Z" {
		t.Fatalf("state: %+v", st)
	}

	// Same HEAD: only info/refs is read. (A sync reads deltaLog.json once
	// for the deltas and once for the views, after storing.)
	logReads := env.gh.fetched["cves/deltaLog.json"]
	if res := env.sync(t); !res.UpToDate {
		t.Fatalf("second sync: %+v", res)
	}
	if n := env.gh.fetched["cves/deltaLog.json"]; n != logReads {
		t.Fatalf("deltaLog fetched %d more times", n-logReads)
	}

	// A new delta: only its record is fetched; b is left alone.
	files := map[string]string{
		"cves/2026/0xxx/CVE-2026-0001.json":     record("CVE-2026-0001", "a v2"),
		"cves/2026/120xxx/CVE-2026-120339.json": record("CVE-2026-120339", "b"),
		"cves/2025/31xxx/CVE-2025-31337.json":   record("CVE-2025-31337", "c"),
	}
	files["cves/deltaLog.json"] = deltaLog(
		delta{FetchTime: "2026-11-02T03:00:00.000Z", New: []change{c}},
		delta{FetchTime: "2026-11-02T02:00:00.000Z", Updated: []change{a}, Error: []change{c}},
		delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{a, b}},
	)
	env.gh.commit(sha2, files)
	env.gh.broken["cves/2025/31xxx/CVE-2025-31337.json"] = true
	// A failure leaves the state where it was.
	if _, err := env.s.sync(context.Background()); err == nil {
		t.Fatal("sync with a broken record succeeded")
	}
	if st := env.state(t); st.Commit != sha1 {
		t.Fatalf("state moved after a failure: %+v", st)
	}
	delete(env.gh.broken, "cves/2025/31xxx/CVE-2025-31337.json")
	res = env.sync(t)
	if res.Deltas != 1 || res.Stored != 1 || res.First || res.Gap {
		t.Fatalf("third sync: %+v", res)
	}
	if n := env.gh.fetched["cves/2026/120xxx/CVE-2026-120339.json"]; n != 1 {
		t.Fatalf("b fetched %d times", n)
	}
	if body, _, _, _ := env.object(t, "cves/2025/31xxx/CVE-2025-31337.json"); body != record("CVE-2025-31337", "c") {
		t.Fatalf("c: %q", body)
	}

	// A record listed but gone from the commit is skipped, not fatal.
	gone := ch("CVE-2026-0404")
	files["cves/deltaLog.json"] = deltaLog(delta{FetchTime: "2026-11-02T04:00:00.000Z", New: []change{gone}},
		delta{FetchTime: "2026-11-02T03:00:00.000Z", New: []change{c}})
	env.gh.commit(sha3, files)
	if res := env.sync(t); res.Missing != 1 || res.Stored != 0 {
		t.Fatalf("missing: %+v", res)
	}

	// The log has moved past the last sync: a gap, reported, and the state
	// still moves on.
	files["cves/deltaLog.json"] = deltaLog(delta{FetchTime: "2026-12-10T00:00:00.000Z", Updated: []change{b}})
	env.gh.commit(sha4, files)
	if res := env.sync(t); !res.Gap || res.Stored != 1 {
		t.Fatalf("gap: %+v", res)
	}
	if st := env.state(t); st.Commit != sha4 {
		t.Fatalf("state after gap: %+v", st)
	}
}

func TestConcurrentSync(t *testing.T) {
	env := newTestEnv(t)
	env.gh.commit(sha1, map[string]string{"cves/deltaLog.json": deltaLog()})
	env.sync(t)
	// Another cve-sync commits after this one read the state.
	env.gh.commit(sha2, map[string]string{"cves/deltaLog.json": deltaLog()})
	env.gh.onRefs = func() {
		resp, err := env.s.s3.get(context.Background(), stateKey)
		if err != nil {
			t.Error(err)
			return
		}
		env.s.s3.put(context.Background(), stateKey, "text/plain", []byte("commit="+sha2+"\n"), "If-Match", resp.etag)
	}
	if _, err := env.s.sync(context.Background()); err == nil || !strings.Contains(err.Error(), "another cve-sync") {
		t.Fatalf("sync = %v; want a conflict", err)
	}
}

func TestHeadFromRefs(t *testing.T) {
	// The start of the real advertisement for cvelistV5.
	adv := "001e# service=git-upload-pack\n0000" +
		"0159bd8b4c666ccbda6ab00069450b783e5498d33507 HEAD\x00multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/main filter object-format=sha1 agent=git/github-f6e509caf74d-Linux\n"
	got, err := headFromRefs([]byte(adv))
	if err != nil || got != "bd8b4c666ccbda6ab00069450b783e5498d33507" {
		t.Fatalf("headFromRefs = %q, %v", got, err)
	}
	if _, err := headFromRefs([]byte("0000")); err == nil {
		t.Fatal("no HEAD: want an error")
	}
}

func TestRecordPath(t *testing.T) {
	for _, tc := range []struct {
		c    change
		want string
		ok   bool
	}{
		{change{CVEID: "CVE-2026-120339"}, "cves/2026/120xxx/CVE-2026-120339.json", true},
		{change{CVEID: "CVE-1999-0001"}, "cves/1999/0xxx/CVE-1999-0001.json", true},
		{change{CVEID: "CVE-2024-21413"}, "cves/2024/21xxx/CVE-2024-21413.json", true},
		{change{GitHubLink: "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/21xxx/CVE-2024-21413.json"}, "cves/2024/21xxx/CVE-2024-21413.json", true},
		{change{CVEID: "CVE-2024-1", GitHubLink: "https://x/cves/../mut/sync"}, "", false},
		{change{CVEID: "../mut/sync"}, "", false},
	} {
		got, ok := recordPath(tc.c)
		if got != tc.want || ok != tc.ok {
			t.Errorf("recordPath(%+v) = %q, %v; want %q, %v", tc.c, got, ok, tc.want, tc.ok)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	st := syncState{Commit: sha1, FetchTime: time.Date(2026, 11, 2, 3, 48, 26, 322e6, time.UTC), SyncedAt: time.Date(2026, 11, 2, 4, 0, 0, 0, time.UTC)}
	if got := decodeState(st.encode()); got != st {
		t.Fatalf("round trip: %+v", got)
	}
}
