package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func fullRecord(id, state, title, desc, metrics, updated string) string {
	return fmt.Sprintf(`{"dataType":"CVE_RECORD","cveMetadata":{"cveId":%q,"state":%q,"assignerShortName":"acme","datePublished":"2026-11-01T09:00:00","dateUpdated":%q},
"containers":{"cna":{"title":%q,"descriptions":[{"lang":"de","value":"nein"},{"lang":"en","value":%q}],"rejectedReasons":[{"lang":"en","value":"duplicate of CVE-2026-0001"}],"metrics":%s}}}`,
		id, state, updated, title, desc, metrics)
}

type atomFeed struct {
	XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	ID      string   `xml:"id"`
	Updated string   `xml:"updated"`
	Entries []struct {
		ID         string `xml:"id"`
		Title      string `xml:"title"`
		Updated    string `xml:"updated"`
		Published  string `xml:"published"`
		Author     string `xml:"author>name"`
		Summary    string `xml:"summary"`
		Categories []struct {
			Term string `xml:"term,attr"`
		} `xml:"category"`
	} `xml:"entry"`
}

func (env *testEnv) feed(t *testing.T) atomFeed {
	t.Helper()
	body, _, ct, status := env.object(t, feedKey)
	if status != http.StatusOK || ct != "application/atom+xml; charset=utf-8" {
		t.Fatalf("GET %s: %d %q", feedKey, status, ct)
	}
	var f atomFeed
	if err := xml.Unmarshal([]byte(body), &f); err != nil {
		t.Fatalf("feed.xml: %v\n%s", err, body)
	}
	return f
}

func TestView(t *testing.T) {
	env := newTestEnv(t)
	a, b, c, gone := ch("CVE-2026-0001"), ch("CVE-2026-0002"), ch("CVE-2026-0003"), ch("CVE-2026-0404")
	env.gh.commit(sha1, map[string]string{
		"cves/deltaLog.json": deltaLog(
			// a was new, then updated: the newer listing wins.
			delta{FetchTime: "2026-11-02T02:00:00.000Z", Updated: []change{a}, New: []change{c, gone}},
			delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{a, b}},
		),
		"cves/2026/0xxx/CVE-2026-0001.json": fullRecord("CVE-2026-0001", "PUBLISHED", "<script>alert(1)</script> overflow", "A heap overflow.",
			`[{"cvssV3_1":{"baseScore":9.8,"baseSeverity":"CRITICAL"}},{"cvssV4_0":{"baseScore":9.3,"baseSeverity":"CRITICAL"}}]`, "2026-11-02T01:30:00.000Z"),
		"cves/2026/0xxx/CVE-2026-0002.json": fullRecord("CVE-2026-0002", "PUBLISHED", "", "Path traversal in the uploader.\nMore detail.", `[]`, "2026-11-01T00:30:00.000Z"),
		"cves/2026/0xxx/CVE-2026-0003.json": fullRecord("CVE-2026-0003", "REJECTED", "", "", `[]`, "2026-11-02T01:45:00Z"),
	})
	env.sync(t)

	f := env.feed(t)
	if len(f.Entries) != 3 {
		t.Fatalf("feed has %d entries; want 3 (the missing record left out)", len(f.Entries))
	}
	// Newest dateUpdated first.
	e0, e1, e2 := f.Entries[0], f.Entries[1], f.Entries[2]
	if e0.ID != "https://www.cve.org/CVERecord?id=CVE-2026-0003" || e1.ID != "https://www.cve.org/CVERecord?id=CVE-2026-0001" || e2.ID != "https://www.cve.org/CVERecord?id=CVE-2026-0002" {
		t.Fatalf("order: %s, %s, %s", e0.ID, e1.ID, e2.ID)
	}
	if f.Updated != "2026-11-02T01:45:00Z" {
		t.Errorf("feed updated %q", f.Updated)
	}
	if e1.Title != "CVE-2026-0001: <script>alert(1)</script> overflow" || e1.Updated != "2026-11-02T01:30:00Z" ||
		e1.Published != "2026-11-01T09:00:00Z" || e1.Author != "acme" ||
		e1.Summary != "CRITICAL 9.3 (CVSS 4.0)\n\nA heap overflow." ||
		len(e1.Categories) != 1 || e1.Categories[0].Term != "updated" {
		t.Errorf("a: %+v", e1)
	}
	if e2.Title != "CVE-2026-0002: Path traversal in the uploader." || e2.Categories[0].Term != "new" {
		t.Errorf("b: %+v", e2)
	}
	if e0.Summary != "duplicate of CVE-2026-0001" || len(e0.Categories) != 2 || e0.Categories[1].Term != "rejected" {
		t.Errorf("c: %+v", e0)
	}

	page, _, ct, _ := env.object(t, indexKey)
	if ct != "text/html; charset=utf-8" {
		t.Errorf("index.html: %q", ct)
	}
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
		t.Error("index.html doesn't escape a record's title")
	}
	for _, want := range []string{`href="feed.xml"`, "CVE-2026-0003", `class="tag critical">CRITICAL 9.3 (CVSS 4.0)`, "rejected", "Path traversal"} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
}

// A sync reads past the last sync's delta to fill the view, but stores only
// the records changed since.
func TestViewReadsPastSince(t *testing.T) {
	env := newTestEnv(t)
	env.s.viewSize = 2
	a, b, c := ch("CVE-2026-0001"), ch("CVE-2026-0002"), ch("CVE-2026-0003")
	files := map[string]string{
		"cves/2026/0xxx/CVE-2026-0001.json": record("CVE-2026-0001", "a"),
		"cves/2026/0xxx/CVE-2026-0002.json": record("CVE-2026-0002", "b"),
		"cves/2026/0xxx/CVE-2026-0003.json": record("CVE-2026-0003", "c"),
		"cves/deltaLog.json": deltaLog(
			delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{b, c}},
			delta{FetchTime: "2026-11-02T00:00:00.000Z", New: []change{a}},
		),
	}
	env.gh.commit(sha1, files)
	env.sync(t)
	if got := env.feed(t).Entries; len(got) != 2 {
		t.Fatalf("view of 2 has %d entries", len(got))
	}

	files["cves/deltaLog.json"] = deltaLog(
		delta{FetchTime: "2026-11-02T02:00:00.000Z", Updated: []change{a}},
		delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{b, c}},
		delta{FetchTime: "2026-11-02T00:00:00.000Z", New: []change{a}},
	)
	env.gh.commit(sha2, files)
	if res := env.sync(t); res.Stored != 1 || res.Deltas != 1 {
		t.Fatalf("sync: %+v", res)
	}
	got := env.feed(t).Entries
	if len(got) != 2 || !strings.HasSuffix(got[0].Title, ": a") && !strings.HasSuffix(got[1].Title, ": a") {
		t.Fatalf("view: %+v", got)
	}
}

// A bucket synced without a view, as after a seed or an older cve-sync,
// gets one on an up-to-date run, once.
func TestEnsureView(t *testing.T) {
	env := newTestEnv(t)
	a := ch("CVE-2026-0001")
	env.gh.commit(sha1, map[string]string{
		"cves/deltaLog.json":                deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{a}}),
		"cves/2026/0xxx/CVE-2026-0001.json": record("CVE-2026-0001", "a"),
	})
	ctx := context.Background()
	env.s.s3.put(ctx, a.GitHubLink[strings.Index(a.GitHubLink, "cves/"):], "application/json", []byte(record("CVE-2026-0001", "a")), "", "")
	env.s.s3.put(ctx, stateKey, "text/plain", []byte("commit="+sha1+"\n"), "", "")

	for range 2 {
		if res := env.sync(t); !res.UpToDate {
			t.Fatalf("sync: %+v", res)
		}
	}
	if n := env.gh.fetched["cves/deltaLog.json"]; n != 1 {
		t.Fatalf("deltaLog fetched %d times; want 1", n)
	}
	if got := env.feed(t).Entries; len(got) != 1 || got[0].Title != "CVE-2026-0001: a" {
		t.Fatalf("view: %+v", got)
	}
	if _, _, _, status := env.object(t, indexKey); status != http.StatusOK {
		t.Fatalf("index.html: %d", status)
	}
}
