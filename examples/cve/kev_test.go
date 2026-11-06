package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const (
	kevCISAWeb = "www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevRefsWeb = "github.com/cisagov/kev-data.git/info/refs"
)

func kevJSON(version, released string, entries ...string) string {
	return fmt.Sprintf(`{"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":%q,"dateReleased":%q,"count":%d,"vulnerabilities":[%s]}`,
		version, released, len(entries), strings.Join(entries, ","))
}

func kevEntryJSON(id, added, ransomware string) string {
	return fmt.Sprintf(`{"cveID":%q,"vendorProject":"Acme","product":"Widget","vulnerabilityName":"Acme Widget <b>Bug</b>","dateAdded":%q,"shortDescription":"Widget lets attackers in.","requiredAction":"Apply the update.","dueDate":"2026-11-18","knownRansomwareCampaignUse":%q,"notes":"https://acme.example/advisory/1 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04 ; https://nvd.nist.gov/vuln/detail/%s","cwes":["CWE-287"]}`,
		id, added, ransomware, id)
}

func refsAdvert(sha string) string {
	pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
	return pkt("# service=git-upload-pack\n") + "0000" + pkt(sha+" HEAD\x00symref=HEAD:refs/heads/develop\n") + "0000"
}

func TestKEV(t *testing.T) {
	env := newTestEnv(t)
	gh := env.gh
	gh.commit(sha1, map[string]string{"cves/deltaLog.json": deltaLog(delta{FetchTime: "2026-11-02T01:00:00.000Z", New: []change{ch("CVE-2026-0001")}}),
		"cves/2026/0xxx/CVE-2026-0001.json": `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED","assignerShortName":"acme","dateUpdated":"2026-11-02T00:30:00Z"},"containers":{"cna":{"title":"Record title","metrics":[{"cvssV3_1":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}`,
	})

	older := kevJSON("2026.11.03", "2026-11-03T20:00:00.000Z",
		kevEntryJSON("CVE-2020-0002", "2026-10-01", "Unknown"))
	newer := kevJSON("2026.11.04", "2026-11-04T20:00:00.000Z",
		kevEntryJSON("CVE-2026-0001", "2026-11-04", "Known"),
		kevEntryJSON("CVE-2020-0002", "2026-10-01", "Unknown"),
		kevEntryJSON("not-a-cve", "2026-11-04", "Unknown"))

	// cisa.gov is behind GitHub: the view is built from GitHub's.
	gh.web[kevCISAWeb] = webPage{"application/json", `"c1"`, older}
	gh.web[kevRefsWeb] = webPage{"application/x-git-upload-pack-advertisement", "", refsAdvert(sha3)}
	gh.web["raw.githubusercontent.com/cisagov/kev-data/"+sha3+"/"+kevFile] = webPage{"text/plain", "", newer}

	res := env.sync(t)
	if res.KEVStored != 2 || res.KEVErr != nil {
		t.Fatalf("first sync: %+v", res)
	}
	if body, _, ct, _ := env.object(t, kevCISAKey); body != older || ct != "application/json" {
		t.Fatalf("cisa copy: %q %q", body, ct)
	}
	if body, _, _, _ := env.object(t, kevGHKey); body != newer {
		t.Fatalf("github copy: %q", body)
	}
	if got := entryIDs(env.feedAt(t, kevFeedKey)); strings.Join(got, " ") != "CVE-2026-0001#kev CVE-2020-0002#kev" {
		t.Fatalf("kev.xml: %v", got)
	}
	page, _, _, _ := env.object(t, kevPageKey)
	for _, want := range []string{
		"Acme Widget &lt;b&gt;Bug&lt;/b&gt;", "Widget lets attackers in.", "CRITICAL 9.8", `<span class="tag ransomware">`,
		"added <time", "2026.11.04", `href="https://acme.example/advisory/1"`, "nvd.nist.gov", "<strong>Known exploited</strong>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("kev.html lacks %q", want)
		}
	}
	if strings.Contains(page, "bod-26-04") || strings.Contains(page, "not-a-cve") {
		t.Error("kev.html has CISA's directive or a malformed ID")
	}
	feed, _, _, _ := env.object(t, kevFeedKey)
	if !strings.Contains(feed, `term="known-exploited"`) || !strings.Contains(feed, "due 2026-11-18. Apply the update.") {
		t.Errorf("kev.xml: %s", feed)
	}

	// Up to date: cisa.gov answers 304, GitHub's HEAD hasn't moved, and
	// the view isn't rewritten.
	_, viewETag, _, _ := env.object(t, kevPageKey)
	rawFetched := gh.fetched["raw.githubusercontent.com/cisagov/kev-data/"+sha3+"/"+kevFile]
	res = env.sync(t)
	if res.KEVStored != 0 || res.KEVErr != nil {
		t.Fatalf("up to date: %+v", res)
	}
	if n := gh.fetched["raw.githubusercontent.com/cisagov/kev-data/"+sha3+"/"+kevFile]; n != rawFetched {
		t.Fatal("kev-data's file fetched again though HEAD didn't move")
	}
	if state, _, _, _ := env.object(t, kevStateKey); !strings.Contains(state, `cisa_etag="c1"`) || !strings.Contains(state, "github_commit="+sha3) {
		t.Fatalf("state: %q", state)
	}

	// GitHub goes down and cisa.gov catches up: the sync still completes,
	// and the copies are the same release, so the view stands.
	delete(gh.web, kevRefsWeb)
	gh.web[kevCISAWeb] = webPage{"application/json", `"c2"`, newer}
	res = env.sync(t)
	if res.KEVStored != 1 || res.KEVErr == nil || !strings.Contains(res.String(), "KEV not fetched from kev-data") {
		t.Fatalf("github down: %+v %s", res, res)
	}
	if _, etag, _, _ := env.object(t, kevPageKey); etag != viewETag {
		t.Error("kev.html rewritten though the newest release didn't change")
	}

	// cisa.gov releases one GitHub doesn't have yet: the view follows it.
	gh.web[kevCISAWeb] = webPage{"application/json", `"c3"`, kevJSON("2026.11.05", "2026-11-05T20:00:00.000Z",
		kevEntryJSON("CVE-2026-0003", "2026-11-05", "Unknown"), kevEntryJSON("CVE-2026-0001", "2026-11-04", "Known"))}
	env.sync(t)
	if got := entryIDs(env.feedAt(t, kevFeedKey)); len(got) != 2 || !strings.Contains(got[0], "CVE-2026-0003") {
		t.Fatalf("kev.xml after cisa.gov's release: %v", got)
	}

	// A broken copy isn't stored.
	gh.web[kevCISAWeb] = webPage{"application/json", `"c4"`, `{"vulnerabilities":[]}`}
	res = env.sync(t)
	if res.KEVErr == nil || !strings.Contains(res.KEVErr.Error(), "not a KEV catalog") {
		t.Fatalf("broken copy: %v", res.KEVErr)
	}
	if body, _, _, status := env.object(t, kevCISAKey); status != http.StatusOK || !strings.Contains(body, "2026.11.05") {
		t.Fatal("broken copy replaced the stored one")
	}
}

func TestKEVRefs(t *testing.T) {
	got := kevRefs("https://support.apple.com/en-us/120896 ; BOD 26-04: https://www.cisa.gov/x ; Forensics: https://cisa.gov/y ; ftp://x ; https://nvd.nist.gov/vuln/detail/CVE-1/")
	if len(got) != 2 || got[0].Title != "support.apple.com/en-us/120896" || got[1].Title != "nvd.nist.gov/vuln/detail/CVE-1" {
		t.Fatalf("%+v", got)
	}
}
