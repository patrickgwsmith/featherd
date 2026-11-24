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
	for _, want := range []string{`<a href="https://support.apple.com/en-us/122716">About the security content of macOS Sequoia 15.5</a>`, `<strong aria-current="page">Apple</strong>`, `href="android.html"`} {
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

// The Linux kernel view shows just its HIGH and CRITICAL CVEs, reading past
// the first batch of the index to find them; Microsoft's, Chrome's, Go's,
// Apache's, OpenSSL's, SQLite's, nginx's and PostgreSQL's show them all.
func TestHighOnlyVendorView(t *testing.T) {
	env := newTestEnv(t)
	env.s.viewSize = 2
	const (
		high   = `[{"cvssV3_1":{"version":"3.1","baseScore":7.8,"baseSeverity":"HIGH"}}]`
		medium = `[{"cvssV3_1":{"version":"3.1","baseScore":5.5,"baseSeverity":"MEDIUM"}}]`
	)
	assigned := func(assigner, rec string) string {
		return strings.Replace(rec, `"assignerShortName":"acme"`, fmt.Sprintf(`"assignerShortName":%q`, assigner), 1)
	}
	files := map[string]string{}
	var cs []change
	// Linux, newest first: unscored past the first batch, then two HIGHs
	// and a third, older, that the view of 2 doesn't reach.
	n := viewBatch + 3
	for i := range n {
		id := fmt.Sprintf("CVE-2026-%04d", 1000+i)
		metrics := "[]"
		if i >= viewBatch {
			metrics = high
		}
		updated := fmt.Sprintf("2026-11-02T00:%02d:%02dZ", 59-i/60, 59-i%60)
		p, _ := recordPath(change{CVEID: id})
		files[p] = assigned("Linux", fullRecord(id, "PUBLISHED", "linux "+id, "d", metrics, updated))
		cs = append(cs, ch(id))
	}
	ms1, ms2 := ch("CVE-2026-2001"), ch("CVE-2026-2002")
	files["cves/2026/2xxx/CVE-2026-2001.json"] = assigned("microsoft", fullRecord("CVE-2026-2001", "PUBLISHED", "Windows info disclosure", "d", medium, "2026-11-02T00:50:00Z"))
	files["cves/2026/2xxx/CVE-2026-2002.json"] = assigned("microsoft", fullRecord("CVE-2026-2002", "PUBLISHED", "Windows EoP", "d", high, "2026-11-02T00:40:00Z"))
	chrome := ch("CVE-2026-3001")
	files["cves/2026/3xxx/CVE-2026-3001.json"] = assigned("Chrome", fullRecord("CVE-2026-3001", "PUBLISHED", "Use after free in V8", "d", "[]", "2026-11-02T00:30:00Z"))
	golang := ch("CVE-2026-4001")
	files["cves/2026/4xxx/CVE-2026-4001.json"] = assigned("Go", fullRecord("CVE-2026-4001", "PUBLISHED", "Excessive memory use in net/http", "d", "[]", "2026-11-02T00:20:00Z"))
	apache := ch("CVE-2026-5001")
	files["cves/2026/5xxx/CVE-2026-5001.json"] = assigned("apache", fullRecord("CVE-2026-5001", "PUBLISHED", "Apache HTTP Server: mod_proxy request smuggling", "d", "[]", "2026-11-02T00:10:00Z"))
	openssl := ch("CVE-2026-6001")
	files["cves/2026/6xxx/CVE-2026-6001.json"] = assigned("openssl", fullRecord("CVE-2026-6001", "PUBLISHED", "Out-of-bounds read in X.509 name checking", "d", "[]", "2026-11-02T00:05:00Z"))
	// SQLite's, from MITRE, says so only in its description; nginx's names
	// F5's product in its affected entries.
	sqlite := ch("CVE-2026-7001")
	files["cves/2026/7xxx/CVE-2026-7001.json"] = assigned("mitre", fullRecord("CVE-2026-7001", "PUBLISHED", "", "In SQLite before 3.51.2, a crafted query can crash the shell.", "[]", "2026-11-02T00:04:00Z"))
	nginx := ch("CVE-2026-8001")
	files["cves/2026/8xxx/CVE-2026-8001.json"] = strings.Replace(assigned("f5", fullRecord("CVE-2026-8001", "PUBLISHED", "NGINX HTTP/3 QUIC vulnerability", "d", "[]", "2026-11-02T00:03:00Z")),
		`"metrics":`, `"affected":[{"vendor":"F5","product":"NGINX Open Source"}],"metrics":`, 1)
	postgres := ch("CVE-2026-9001")
	files["cves/2026/9xxx/CVE-2026-9001.json"] = assigned("PostgreSQL", fullRecord("CVE-2026-9001", "PUBLISHED", "PostgreSQL row security bypass in MERGE", "d", "[]", "2026-11-02T00:02:00Z"))
	files["cves/deltaLog.json"] = deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z", New: append(cs, ms1, ms2, chrome, golang, apache, openssl, sqlite, nginx, postgres)})
	env.gh.commit(sha1, files)
	env.sync(t)

	if idx, _, _, _ := env.object(t, "mut/vendor/linux"); strings.Count(idx, "\n") != n {
		t.Fatalf("linux index has %d entries, want every record", strings.Count(idx, "\n"))
	}
	want := fmt.Sprintf("CVE-2026-%04d CVE-2026-%04d", 1000+viewBatch, 1001+viewBatch)
	if got := entryIDs(env.feedAt(t, "view/linux.xml")); strings.Join(got, " ") != want {
		t.Fatalf("linux.xml: %v; want %s", got, want)
	}
	page, _, _, _ := env.object(t, "view/linux.html")
	if !strings.Contains(page, "Linux kernel HIGH and CRITICAL CVEs") {
		t.Error("linux.html doesn't say it's HIGH and CRITICAL only")
	}
	if got := entryIDs(env.feedAt(t, "view/microsoft.xml")); strings.Join(got, " ") != "CVE-2026-2001 CVE-2026-2002" {
		t.Fatalf("microsoft.xml: %v", got)
	}
	if got := entryIDs(env.feedAt(t, "view/chrome.xml")); strings.Join(got, " ") != "CVE-2026-3001" {
		t.Fatalf("chrome.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/chrome.html"); !strings.Contains(page, "Use after free in V8") {
		t.Error("chrome.html doesn't list Chrome's CVE")
	}
	if got := entryIDs(env.feedAt(t, "view/go.xml")); strings.Join(got, " ") != "CVE-2026-4001" {
		t.Fatalf("go.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/go.html"); !strings.Contains(page, "Excessive memory use in net/http") {
		t.Error("go.html doesn't list Go's CVE")
	}
	if got := entryIDs(env.feedAt(t, "view/apache.xml")); strings.Join(got, " ") != "CVE-2026-5001" {
		t.Fatalf("apache.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/apache.html"); !strings.Contains(page, "mod_proxy request smuggling") {
		t.Error("apache.html doesn't list Apache's CVE")
	}
	if got := entryIDs(env.feedAt(t, "view/openssl.xml")); strings.Join(got, " ") != "CVE-2026-6001" {
		t.Fatalf("openssl.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/openssl.html"); !strings.Contains(page, "X.509 name checking") {
		t.Error("openssl.html doesn't list OpenSSL's CVE")
	}
	if got := entryIDs(env.feedAt(t, "view/sqlite.xml")); strings.Join(got, " ") != "CVE-2026-7001" {
		t.Fatalf("sqlite.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/sqlite.html"); !strings.Contains(page, "crafted query can crash") || !strings.Contains(page, "affecting SQLite") {
		t.Error("sqlite.html doesn't list SQLite's CVE as affecting SQLite")
	}
	if got := entryIDs(env.feedAt(t, "view/nginx.xml")); strings.Join(got, " ") != "CVE-2026-8001" {
		t.Fatalf("nginx.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/nginx.html"); !strings.Contains(page, "HTTP/3 QUIC") {
		t.Error("nginx.html doesn't list nginx's CVE")
	}
	if got := entryIDs(env.feedAt(t, "view/postgresql.xml")); strings.Join(got, " ") != "CVE-2026-9001" {
		t.Fatalf("postgresql.xml: %v", got)
	}
	if page, _, _, _ := env.object(t, "view/postgresql.html"); !strings.Contains(page, "row security bypass in MERGE") {
		t.Error("postgresql.html doesn't list PostgreSQL's CVE")
	}
	if index, _, _, _ := env.object(t, indexKey); !strings.Contains(index, `href="sqlite.html"`) || !strings.Contains(index, `href="nginx.html"`) {
		t.Error("index.html doesn't link the product pages")
	}
	if index, _, _, _ := env.object(t, indexKey); !strings.Contains(index, `href="linux.html"`) || !strings.Contains(index, `href="microsoft.html"`) || !strings.Contains(index, `href="chrome.html"`) || !strings.Contains(index, `href="go.html"`) || !strings.Contains(index, `href="apache.html"`) || !strings.Contains(index, `href="openssl.html"`) || !strings.Contains(index, `href="postgresql.html"`) {
		t.Error("index.html doesn't link the new vendor pages")
	}
}

// The product views match a record's affected entries, the ADPs' CPEs, or
// for a record whose CNA names nothing, its description; not tools merely
// named for the product, nor a passing mention.
func TestProductMatch(t *testing.T) {
	rec := func(assigner, cna, adp string) string {
		return fmt.Sprintf(`{"cveMetadata":{"cveId":"CVE-2026-1","assignerShortName":%q},"containers":{"cna":%s,"adp":[%s]}}`, assigner, cna, adp)
	}
	desc := func(affected, d string) string {
		return fmt.Sprintf(`{"affected":%s,"descriptions":[{"lang":"en","value":%q}]}`, affected, d)
	}
	const na = `[{"vendor":"n/a","product":"n/a"}]`
	for _, tc := range []struct {
		name, data string
		want       string // the product views it's in
	}{
		{"sqlite affected", rec("VulnCheck", desc(`[{"vendor":"SQLite","product":"SQLite"}]`, "d"), ""), "sqlite"},
		{"sqlite cpe", rec("GitHub_M", desc(`[{"vendor":"x","product":"y"}]`, "d"), `{"affected":[{"cpes":["cpe:2.3:a:sqlite:sqlite:3.30.1:*:*:*:*:*:*:*"]}]}`), "sqlite"},
		{"sqlite described", rec("mitre", desc(na, "SQLite 3.30.1 mishandles pExpr->y.pTab."), ""), "sqlite"},
		{"sqlite through", rec("mitre", desc(`[]`, "pragma.c in SQLite through 3.30.1 mishandles NOT NULL."), ""), "sqlite"},
		{"sqlite wrapper", rec("GitHub_M", desc(`[{"vendor":"sparklemotion","product":"sqlite3-ruby"}]`, "d"), ""), ""},
		{"sqlite named elsewhere", rec("GitHub_M", desc(`[{"vendor":"acme","product":"app"}]`, "SQLite 3.30.1 is bundled."), ""), ""},
		{"sqlite mentioned", rec("mitre", desc(na, "Stores passwords in a SQLite database."), ""), ""},
		{"nginx plus", rec("f5", desc(`[{"vendor":"F5","product":"NGINX Plus"}]`, "d"), ""), "nginx"},
		{"nginx controller", rec("f5", desc(`[{"vendor":"n/a","product":"NGINX Controller"}]`, "d"), ""), "nginx"},
		{"nginx cpe", rec("f5", desc(`[]`, "d"), `{"affected":[{"cpes":["cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*"]}]}`), "nginx"},
		{"nginx described", rec("redhat", desc(`[]`, "The resolver in nginx before 1.8.1 allows remote attackers..."), ""), "nginx"},
		{"njs described", rec("mitre", desc(na, "Nginx NJS v0.7.2 was discovered to contain..."), ""), "nginx"},
		{"nginx-ui", rec("GitHub_M", desc(`[{"vendor":"0xJacky","product":"nginx-ui"}]`, "d"), ""), ""},
		{"ingress-nginx", rec("kubernetes", desc(`[{"vendor":"Kubernetes","product":"ingress-nginx"}]`, "d"), ""), ""},
		{"proxy manager", rec("mitre", desc(na, "jc21 Nginx Proxy Manager before 2.0.13 allows traversal."), ""), ""},
	} {
		info, err := parseRecordInfo([]byte(tc.data))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var got []string
		for _, v := range vendorsFor(info) {
			if v.Product != nil {
				got = append(got, v.Name)
			}
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s: in %q; want %q", tc.name, got, tc.want)
		}
	}
}
