package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// publishedRecord is a record published at published, with metrics.
func publishedRecord(id, state, assigner, published, metrics string) string {
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":%q,"assignerShortName":%q,"datePublished":%q,"dateUpdated":%q},"containers":{"cna":{"title":"t","metrics":%s}}}`,
		id, state, assigner, published, published, metrics)
}

const (
	critical = `[{"cvssV3_1":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]`
	high     = `[{"cvssV3_1":{"baseScore":7.5}}]`
)

func page(t *testing.T, env *testEnv, key string) string {
	t.Helper()
	body, _, _, status := env.object(t, key)
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d", key, status)
	}
	return body
}

func TestChart(t *testing.T) {
	env := newTestEnv(t)
	env.s.now = func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }
	a, b, c, old, today := ch("CVE-2026-0001"), ch("CVE-2026-0002"), ch("CVE-2026-0003"), ch("CVE-2026-0004"), ch("CVE-2026-0005")
	files := map[string]string{
		"cves/deltaLog.json":                deltaLog(delta{FetchTime: "2026-11-24T01:00:00.000Z", New: []change{a, b, c, old, today}}),
		"cves/2026/0xxx/CVE-2026-0001.json": publishedRecord("CVE-2026-0001", "PUBLISHED", "apple", "2026-11-23T09:00:00Z", critical),
		"cves/2026/0xxx/CVE-2026-0002.json": publishedRecord("CVE-2026-0002", "PUBLISHED", "Linux", "2026-11-20T09:00:00", `[]`),
		"cves/2026/0xxx/CVE-2026-0003.json": publishedRecord("CVE-2026-0003", "REJECTED", "apple", "2026-11-20T09:00:00Z", critical),
		// Before the chart's days, and on today, which isn't complete.
		"cves/2026/0xxx/CVE-2026-0004.json": publishedRecord("CVE-2026-0004", "PUBLISHED", "apple", "2026-09-01T09:00:00Z", critical),
		"cves/2026/0xxx/CVE-2026-0005.json": publishedRecord("CVE-2026-0005", "PUBLISHED", "apple", "2026-11-24T09:00:00Z", critical),
	}
	env.gh.commit(sha1, files)
	env.gh.web[kevCISAWeb] = webPage{"application/json", `"c1"`, kevJSON("2026.11.24", "2026-11-24T00:00:00.000Z",
		kevEntryJSON("CVE-2026-0001", "2026-11-23", "Unknown"), kevEntryJSON("CVE-2020-0002", "2026-11-23", "Unknown"), kevEntryJSON("CVE-2020-0003", "2026-09-01", "Unknown"))}
	env.sync(t)

	idx, _, _, _ := env.object(t, chartKey)
	if idx != "2026-11-24T09:00:00Z CVE-2026-0005 critical apple\n2026-11-23T09:00:00Z CVE-2026-0001 critical apple\n2026-11-20T09:00:00Z CVE-2026-0002 - linux\n" {
		t.Fatalf("chart index:\n%s", idx)
	}

	all := page(t, env, allPageKey)
	for _, want := range []string{
		`<figcaption>CVEs published each day, 25 Oct to 23 Nov (UTC)</figcaption>`,
		`<li><span class="key s-total"></span>total 2</li><li><span class="key s-critical"></span>CRITICAL 1</li><li><span class="key s-unscored"></span>unscored 1</li>`,
		`<title>Mon 23 Nov 2026: 1 total, 1 CRITICAL, 0 unscored</title>`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("all.html lacks %q:\n%s", want, all)
		}
	}
	// One series, so no total.
	home := page(t, env, indexKey)
	if !strings.Contains(home, `HIGH and CRITICAL CVEs published each day`) || !strings.Contains(home, `<ul class="legend"><li><span class="key s-critical"></span>CRITICAL 1</li></ul>`) {
		t.Errorf("index.html chart:\n%s", home)
	}
	// Linux's page is HIGH and CRITICAL only, and its one CVE is unscored.
	linux := page(t, env, "view/linux.html")
	if !strings.Contains(linux, `<ul class="legend"><li><span class="key s-total"></span>total 0</li></ul>`) {
		t.Errorf("linux.html chart:\n%s", linux)
	}
	if apple := page(t, env, "view/apple.html"); !strings.Contains(apple, `Apple CVEs published each day`) || !strings.Contains(apple, `CRITICAL 1</li></ul>`) {
		t.Errorf("apple.html chart:\n%s", apple)
	}
	if kev := page(t, env, kevPageKey); !strings.Contains(kev, `<li><span class="key s-kev"></span>added 2</li>`) {
		t.Errorf("kev.html chart:\n%s", kev)
	}

	// b is scored HIGH by an update: it moves, rather than counting twice.
	files["cves/deltaLog.json"] = deltaLog(
		delta{FetchTime: "2026-11-24T02:00:00.000Z", Updated: []change{b}},
		delta{FetchTime: "2026-11-24T01:00:00.000Z", New: []change{a, b, c, old, today}})
	files["cves/2026/0xxx/CVE-2026-0002.json"] = publishedRecord("CVE-2026-0002", "PUBLISHED", "Linux", "2026-11-20T09:00:00", high)
	env.gh.commit(sha2, files)
	env.sync(t)
	if all := page(t, env, allPageKey); !strings.Contains(all, `total 2</li><li><span class="key s-critical"></span>CRITICAL 1</li><li><span class="key s-high"></span>HIGH 1</li></ul>`) {
		t.Errorf("all.html after the update:\n%s", all)
	}
	if linux := page(t, env, "view/linux.html"); !strings.Contains(linux, `<ul class="legend"><li><span class="key s-high"></span>HIGH 1</li></ul>`) {
		t.Errorf("linux.html after the update:\n%s", linux)
	}
}

// A bucket from before the charts gets its chart index backfilled, and
// every page redrawn, on an up-to-date run.
func TestEnsureChart(t *testing.T) {
	env := newTestEnv(t)
	env.s.now = func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }
	a := ch("CVE-2026-0001")
	env.gh.commit(sha1, map[string]string{
		"cves/deltaLog.json":                deltaLog(delta{FetchTime: "2026-11-24T01:00:00.000Z", New: []change{a}}),
		"cves/2026/0xxx/CVE-2026-0001.json": publishedRecord("CVE-2026-0001", "PUBLISHED", "apple", "2026-11-23T09:00:00Z", critical),
	})
	env.sync(t)
	ctx := context.Background()
	if _, err := env.s.s3.do(ctx, http.MethodDelete, chartKey, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{indexKey, "view/apple.html"} {
		if _, err := env.s.s3.put(ctx, key, "text/html; charset=utf-8", []byte("old"), "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if res := env.sync(t); !res.UpToDate {
		t.Fatalf("sync: %+v", res)
	}
	if idx, _, _, _ := env.object(t, chartKey); idx != "2026-11-23T09:00:00Z CVE-2026-0001 critical apple\n" {
		t.Fatalf("chart index: %q", idx)
	}
	for _, key := range []string{indexKey, "view/apple.html"} {
		if !strings.Contains(page(t, env, key), "CRITICAL 1</li>") {
			t.Errorf("%s not redrawn", key)
		}
	}
	// Once backfilled, an up-to-date run doesn't read deltaLog again.
	n := env.gh.fetched["cves/deltaLog.json"]
	env.sync(t)
	if m := env.gh.fetched["cves/deltaLog.json"]; m != n {
		t.Fatalf("deltaLog fetched %d more times", m-n)
	}
}

func TestNiceStep(t *testing.T) {
	for peak, want := range map[int]int{1: 1, 4: 1, 5: 2, 8: 2, 9: 5, 20: 5, 21: 10, 150: 50, 201: 100} {
		if got := niceStep(peak); got != want {
			t.Errorf("niceStep(%d) = %d; want %d", peak, got, want)
		}
	}
}

func TestChartHTMLEscapes(t *testing.T) {
	c := severityChart(`<b>"x"</b>`, nil, time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC), func(chartEntry) bool { return true })
	h := string(c.HTML())
	if strings.Contains(h, "<b>") || !strings.Contains(h, "&lt;b&gt;") {
		t.Fatalf("not escaped: %s", h)
	}
	if strings.Count(h, `<rect class="day"`) != chartDays || strings.Count(h, "<polyline") != 1 {
		t.Fatalf("days or series: %s", h)
	}
}
