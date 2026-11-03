package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// vendorRecord is a record a vendor's CNA assigned, citing refs.
func vendorRecord(id, assigner, title, updated string, refs ...string) string {
	var rs []string
	for _, r := range refs {
		rs = append(rs, fmt.Sprintf(`{"url":%q}`, r))
	}
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"PUBLISHED","assignerShortName":%q,"datePublished":"2026-10-01T00:00:00Z","dateUpdated":%q},"containers":{"cna":{"title":%q,"references":[%s]}}}`,
		id, assigner, updated, title, strings.Join(rs, ","))
}

const (
	applePage   = `<html><head><title lang="en">About the security content of macOS Sequoia 15.5 - Apple Support</title></head><body>CVE-2026-0001</body></html>`
	androidPage = `<html><head><title>Android Security Bulletin—June 2026 &nbsp;|&nbsp; Android Open Source Project</title></head></html>`
)

func osvJSON(id, modified string, aliases ...string) string {
	return fmt.Sprintf(`{"id":%q,"modified":%q,"aliases":["A-1","%s"]}`, id, modified, strings.Join(aliases, `","`))
}

func TestVendorViews(t *testing.T) {
	env := newTestEnv(t)
	gh := env.gh
	apple, android, other := ch("CVE-2026-0001"), ch("CVE-2026-0002"), ch("CVE-2026-0003")
	files := map[string]string{
		"cves/deltaLog.json": deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{apple, android, other}}),
		"cves/2026/0xxx/CVE-2026-0001.json": vendorRecord("CVE-2026-0001", "apple", "Kernel overflow", "2026-11-02T00:30:00Z",
			"https://support.apple.com/en-us/122716", "https://support.apple.com/en-us/122716/", "https://example.com/elsewhere"),
		// The old bulletin URL maps to the one under /docs/.
		"cves/2026/0xxx/CVE-2026-0002.json": vendorRecord("CVE-2026-0002", "google_android", "Car EoP", "2026-11-02T00:20:00Z",
			"https://source.android.com/security/bulletin/2026-06-01"),
		"cves/2026/0xxx/CVE-2026-0003.json": vendorRecord("CVE-2026-0003", "acme", "Not a vendor's", "2026-11-02T00:10:00Z",
			"https://support.apple.com/en-us/999999"),
	}
	gh.commit(sha1, files)
	gh.web["support.apple.com/en-us/122716"] = webPage{"text/html;charset=utf-8", "", applePage}
	gh.web["source.android.com/docs/security/bulletin/2026-06-01"] = webPage{"text/html; charset=utf-8", "", androidPage}
	gh.web["osv-vulnerabilities.storage.googleapis.com/Android/all.zip"] = webPage{"application/zip", "", string(zipOf(t, map[string]string{
		"ASB-A-351830787.json": osvJSON("ASB-A-351830787", "2026-11-02T17:00:00Z", "CVE-2026-0002"),
		"PUB-A-1.json":         osvJSON("PUB-A-1", "2026-11-01T00:00:00Z", "CVE-2025-9999"),
	}))}

	res := env.sync(t)
	if res.RefsFetched != 2 || res.RefsStored != 2 || res.RefsFailed != 0 || res.OSVStored != 2 || res.OSVErr != nil {
		t.Fatalf("first sync: %+v", res)
	}
	// Mirrored raw.
	if body, _, ct, _ := env.object(t, "refs/support.apple.com/en-us/122716.html"); body != applePage || ct != "text/html; charset=utf-8" {
		t.Fatalf("apple page: %q %q", body, ct)
	}
	if _, _, _, status := env.object(t, "refs/source.android.com/docs/security/bulletin/2026-06-01.html"); status != http.StatusOK {
		t.Fatalf("android bulletin: %d", status)
	}
	if _, _, _, status := env.object(t, "refs/support.apple.com/en-us/999999.html"); status != http.StatusNotFound {
		t.Fatal("a page cited by another CNA's record was mirrored")
	}
	if body, _, ct, _ := env.object(t, "refs/osv/Android/ASB-A-351830787.json"); !strings.Contains(body, "CVE-2026-0002") || ct != "application/json" {
		t.Fatalf("OSV entry: %q %q", body, ct)
	}

	if got := entryIDs(env.feedAt(t, "view/apple.xml")); strings.Join(got, " ") != "CVE-2026-0001" {
		t.Fatalf("apple.xml: %v", got)
	}
	page, _, _, _ := env.object(t, "view/apple.html")
	for _, want := range []string{`<a href="https://support.apple.com/en-us/122716">About the security content of macOS Sequoia 15.5</a>`, `<strong>Apple</strong>`, `href="android.html"`} {
		if !strings.Contains(page, want) {
			t.Errorf("apple.html lacks %q", want)
		}
	}
	if strings.Count(page, "support.apple.com/en-us/122716") != 1 || strings.Contains(page, "example.com") {
		t.Error("apple.html should list the note once, and no other references")
	}
	page, _, _, _ = env.object(t, "view/android.html")
	for _, want := range []string{"Android Security Bulletin—June 2026<", `href="https://osv.dev/vulnerability/ASB-A-351830787">ASB-A-351830787 on OSV`, "CVE-2026-0002"} {
		if !strings.Contains(page, want) {
			t.Errorf("android.html lacks %q", want)
		}
	}
	if strings.Contains(page, "CVE-2026-0001") || strings.Contains(page, "PUB-A-1") {
		t.Error("android.html has another vendor's CVE or an unrelated OSV entry")
	}
	if index, _, _, _ := env.object(t, indexKey); !strings.Contains(index, `href="apple.html"`) {
		t.Error("index.html doesn't link apple.html")
	}

	// Up to date: modified_id.csv is revalidated, and no page fetched.
	gh.web["osv-vulnerabilities.storage.googleapis.com/Android/modified_id.csv"] = webPage{"text/csv", `"v1"`,
		"2026-11-02T17:00:00Z,ASB-A-351830787\n2026-11-01T00:00:00Z,PUB-A-1\n"}
	res = env.sync(t)
	if !res.UpToDate || res.RefsFetched != 0 || res.OSVStored != 0 || res.OSVErr != nil {
		t.Fatalf("up to date: %+v", res)
	}
	csv := "osv-vulnerabilities.storage.googleapis.com/Android/modified_id.csv"
	env.sync(t)
	if n := gh.fetched[csv]; n != 2 {
		t.Fatalf("modified_id.csv fetched %d times", n)
	}
	if body, _, _, _ := env.object(t, osvStateKey); !strings.Contains(body, `csv_etag="v1"`) {
		t.Fatalf("OSV state: %q", body)
	}

	// The Apple record is updated: the note it cites is fetched again, but
	// it's unchanged, so not stored. OSV revises an entry: just it is fetched.
	files["cves/2026/0xxx/CVE-2026-0001.json"] = vendorRecord("CVE-2026-0001", "apple", "Kernel overflow", "2026-11-02T02:30:00Z",
		"https://support.apple.com/en-us/122716")
	files["cves/deltaLog.json"] = deltaLog(delta{FetchTime: "2026-11-02T03:00:00.000Z", Updated: []change{apple}},
		delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{apple, android, other}})
	gh.commit(sha2, files)
	gh.web[csv] = webPage{"text/csv", `"v2"`, "2026-11-03T09:00:00Z,ASB-A-351830787\n2026-11-02T17:00:00Z,ASB-A-351830787\n2026-11-01T00:00:00Z,PUB-A-1\n"}
	gh.web["osv-vulnerabilities.storage.googleapis.com/Android/ASB-A-351830787.json"] = webPage{"application/json", "",
		osvJSON("ASB-A-351830787", "2026-11-03T09:00:00Z", "CVE-2026-0002", "CVE-2026-0004")}
	before := gh.fetched["source.android.com/docs/security/bulletin/2026-06-01"]
	res = env.sync(t)
	if res.RefsFetched != 1 || res.RefsStored != 0 || res.OSVStored != 1 {
		t.Fatalf("update: %+v", res)
	}
	if n := gh.fetched["support.apple.com/en-us/122716"]; n != 2 {
		t.Fatalf("apple note fetched %d times", n)
	}
	if n := gh.fetched["source.android.com/docs/security/bulletin/2026-06-01"]; n != before {
		t.Fatal("android bulletin fetched again though no record citing it changed")
	}
	if body, _, _, _ := env.object(t, osvStateKey); !strings.Contains(body, "ASB-A-351830787 CVE-2026-0002 CVE-2026-0004") {
		t.Fatalf("OSV state: %q", body)
	}
	if idx, _, _, _ := env.object(t, "mut/vendor/apple"); strings.Count(idx, "\n") != 1 || !strings.HasPrefix(idx, "2026-11-02T02:30:00Z") {
		t.Fatalf("apple index: %q", idx)
	}
}

// A vendor site failing doesn't fail the sync; the page is fetched by the
// next sync whose view shows it.
func TestVendorPageFailure(t *testing.T) {
	env := newTestEnv(t)
	apple := ch("CVE-2026-0001")
	files := map[string]string{
		"cves/deltaLog.json": deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{apple}}),
		"cves/2026/0xxx/CVE-2026-0001.json": vendorRecord("CVE-2026-0001", "apple", "a", "2026-11-02T00:30:00Z",
			"https://support.apple.com/en-us/122716"),
	}
	env.gh.commit(sha1, files)
	res := env.sync(t)
	if res.RefsFailed != 1 || res.OSVErr == nil {
		t.Fatalf("sync: %+v", res)
	}
	if st := env.state(t); st.Commit != sha1 {
		t.Fatalf("state: %+v", st)
	}
	page, _, _, _ := env.object(t, "view/apple.html")
	if !strings.Contains(page, `>support.apple.com/en-us/122716</a>`) {
		t.Errorf("apple.html without the note's title: %s", page)
	}

	env.gh.web["support.apple.com/en-us/122716"] = webPage{"text/html", "", applePage}
	files["cves/deltaLog.json"] = deltaLog(delta{FetchTime: "2026-11-02T02:00:00.000Z"},
		delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{apple}})
	env.gh.commit(sha2, files)
	if res := env.sync(t); res.RefsStored != 1 {
		t.Fatalf("retry: %+v", res)
	}
}

// A seed builds the vendor indexes from every record, so the views reach
// back past deltaLog's 30 days.
func TestSeedVendorIndex(t *testing.T) {
	env := newTestEnv(t)
	zipName := midnightZip(t, map[string]string{
		"cves/2019/8xxx/CVE-2019-8000.json": vendorRecord("CVE-2019-8000", "apple", "old", "2019-05-01T00:00:00Z"),
		"cves/2026/0xxx/CVE-2026-0002.json": vendorRecord("CVE-2026-0002", "google_android", "new", "2026-11-01T00:00:00Z"),
		"cves/2026/0xxx/CVE-2026-0003.json": vendorRecord("CVE-2026-0003", "acme", "other", "2026-11-01T00:00:00Z"),
	})
	if _, err := env.s.seed(context.Background(), zipName); err != nil {
		t.Fatal(err)
	}
	if idx, _, _, _ := env.object(t, "mut/vendor/apple"); idx != "2019-05-01T00:00:00Z CVE-2019-8000 cves/2019/8xxx/CVE-2019-8000.json\n" {
		t.Fatalf("apple index: %q", idx)
	}
	env.gh.commit(sha1, map[string]string{"cves/deltaLog.json": deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z"})})
	env.sync(t)
	// Not backfilled: deltaLog was read for the deltas and the views only.
	if n := env.gh.fetched["cves/deltaLog.json"]; n != 2 {
		t.Fatalf("deltaLog read %d times", n)
	}
	if got := entryIDs(env.feedAt(t, "view/apple.xml")); strings.Join(got, " ") != "CVE-2019-8000" {
		t.Fatalf("apple.xml: %v", got)
	}
}

func TestRefKey(t *testing.T) {
	for _, tc := range []struct{ url, key, fetch string }{
		{"https://support.apple.com/en-us/122716", "refs/support.apple.com/en-us/122716.html", "https://support.apple.com/en-us/122716"},
		{"https://support.apple.com/kb/HT213670", "refs/support.apple.com/kb/HT213670.html", "https://support.apple.com/kb/HT213670"},
		{"http://source.android.com/security/bulletin/2016-07-01.html", "refs/source.android.com/docs/security/bulletin/2016-07-01.html", "https://source.android.com/docs/security/bulletin/2016-07-01"},
		{"https://source.android.com/docs/security/bulletin/pixel/2026/2026-03-01", "refs/source.android.com/docs/security/bulletin/pixel/2026/2026-03-01.html", "https://source.android.com/docs/security/bulletin/pixel/2026/2026-03-01"},
		{"https://source.android.com/security/bulletin/android-12l", "refs/source.android.com/docs/security/bulletin/android-12l.html", "https://source.android.com/docs/security/bulletin/android-12l"},
		{"https://source.android.com/docs/security/bulletin/android-16-qpr2", "refs/source.android.com/docs/security/bulletin/android-16-qpr2.html", "https://source.android.com/docs/security/bulletin/android-16-qpr2"},
		{"https://support.apple.com/en-us/../../mut/sync", "", ""},
		{"https://support.apple.com/downloads", "", ""},
		{"https://android.googlesource.com/platform/art/+/1aedae6e", "", ""},
		{"https://support.claris.com/s/answerview?anum=1", "", ""},
		{"file:///etc/passwd", "", ""},
	} {
		key, fetch, ok := refKey(tc.url)
		if key != tc.key || fetch != tc.fetch || ok != (tc.key != "") {
			t.Errorf("refKey(%q) = %q, %q, %v", tc.url, key, fetch, ok)
		}
	}
}

func TestPageTitle(t *testing.T) {
	for page, want := range map[string]string{
		applePage:   "About the security content of macOS Sequoia 15.5",
		androidPage: "Android Security Bulletin—June 2026",
		`<TITLE>Pixel Update Bulletin—March 2026 &nbsp;|&nbsp; Security</TITLE>`: "Pixel Update Bulletin—March 2026",
		`<p>no title</p>`: "",
	} {
		if got := pageTitle([]byte(page)); got != want {
			t.Errorf("pageTitle = %q; want %q", got, want)
		}
	}
}
