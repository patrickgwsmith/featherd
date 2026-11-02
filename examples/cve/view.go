package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// The view: the newest CVEs that deltaLog.json lists as new or updated, as
// a page and an Atom feed. It's a projection of deltaLog.json at the commit
// synced and the records in the bucket, so it's simply rewritten with
// plain PUTs on each sync.
const (
	indexKey = "view/index.html"
	feedKey  = "view/feed.xml"
)

// recentChanges collects the newest distinct CVEs from deltaLog entries
// given newest first, so each CVE keeps its newest listing.
type recentChanges struct {
	max   int
	seen  map[string]bool
	items []recentChange
}

type recentChange struct {
	CVEID, Path string
	New         bool      // listed under "new", not "updated"
	DateUpdated time.Time // from deltaLog, if the record has none
}

func newRecentChanges(max int) *recentChanges {
	return &recentChanges{max: max, seen: map[string]bool{}}
}

func (r *recentChanges) full() bool { return len(r.items) >= r.max }

func (r *recentChanges) add(e delta) {
	for i, list := range [][]change{e.New, e.Updated} {
		for _, c := range list {
			if r.full() {
				return
			}
			p, ok := recordPath(c)
			if !ok || r.seen[p] {
				continue
			}
			r.seen[p] = true
			r.items = append(r.items, recentChange{CVEID: c.CVEID, Path: p, New: i == 0, DateUpdated: parseCVETime(c.DateUpdated)})
		}
	}
}

// ensureView writes the view from deltaLog.json at commit if it's missing.
func (s *syncer) ensureView(ctx context.Context, commit string) error {
	resp, err := s.s3.get(ctx, feedKey)
	if err != nil || resp.status == http.StatusOK {
		return err
	}
	recent := newRecentChanges(s.viewSize)
	err = s.scanDeltaLog(ctx, commit, func(e delta, _ time.Time) bool {
		recent.add(e)
		return !recent.full()
	})
	if err != nil {
		return err
	}
	return s.writeView(ctx, commit, recent)
}

// writeView reads each recent CVE's record back from the bucket and writes
// view/index.html and view/feed.xml. A record that isn't in the bucket,
// such as one missing at the commit, is left out.
func (s *syncer) writeView(ctx context.Context, commit string, recent *recentChanges) error {
	cves := make([]viewCVE, len(recent.items))
	errs := make([]error, len(recent.items))
	sem := make(chan struct{}, s.parallel)
	var wg sync.WaitGroup
	for i, rc := range recent.items {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := s.s3.get(ctx, rc.Path)
			if err != nil {
				errs[i] = err
				return
			}
			if resp.status != http.StatusOK {
				return
			}
			v, err := newViewCVE(rc, resp.body)
			if err != nil {
				s.log.Printf("view: %s: %v; left out", rc.Path, err)
				return
			}
			cves[i] = v
		})
	}
	wg.Wait()

	page := viewPage{Commit: commit, Generated: s.now().UTC()}
	for i, v := range cves {
		if errs[i] != nil {
			return errs[i]
		}
		if v.ID != "" {
			page.CVEs = append(page.CVEs, v)
		}
	}
	sort.SliceStable(page.CVEs, func(i, j int) bool {
		a, b := page.CVEs[i], page.CVEs[j]
		if !a.Updated.Equal(b.Updated) {
			return a.Updated.After(b.Updated)
		}
		return a.ID > b.ID
	})

	var html bytes.Buffer
	if err := indexTemplate.Execute(&html, page); err != nil {
		return err
	}
	feed, err := page.atom()
	if err != nil {
		return err
	}
	// The feed is written last: ensureView takes it as the whole view.
	for _, f := range []struct {
		key, contentType string
		body             []byte
	}{
		{indexKey, "text/html; charset=utf-8", html.Bytes()},
		{feedKey, "application/atom+xml; charset=utf-8", feed},
	} {
		if _, err := s.s3.put(ctx, f.key, f.contentType, f.body, "", ""); err != nil {
			return err
		}
	}
	return nil
}

type viewPage struct {
	Commit    string
	Generated time.Time
	CVEs      []viewCVE
}

// viewCVE is what the view shows of one record.
type viewCVE struct {
	ID, Title, Description, Assigner, Severity, Path string
	New, Rejected                                    bool
	Published, Updated                               time.Time
}

func (v viewCVE) Link() string { return "https://www.cve.org/CVERecord?id=" + v.ID }

// cveRecord is the part of a CVE JSON 5 record the view reads.
// https://github.com/CVEProject/cve-schema
type cveRecord struct {
	CVEMetadata struct {
		CVEID             string `json:"cveId"`
		State             string `json:"state"`
		AssignerShortName string `json:"assignerShortName"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveContainer   `json:"cna"`
		ADP []cveContainer `json:"adp"`
	} `json:"containers"`
}

type cveContainer struct {
	Title           string                       `json:"title"`
	Descriptions    []langValue                  `json:"descriptions"`
	RejectedReasons []langValue                  `json:"rejectedReasons"`
	Metrics         []map[string]json.RawMessage `json:"metrics"`
}

type langValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func newViewCVE(rc recentChange, data []byte) (viewCVE, error) {
	var rec cveRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return viewCVE{}, err
	}
	m, cna := rec.CVEMetadata, rec.Containers.CNA
	v := viewCVE{
		ID: m.CVEID, Title: cna.Title, Assigner: m.AssignerShortName, Path: rc.Path,
		New: rc.New, Rejected: m.State == "REJECTED",
		Published: parseCVETime(m.DatePublished), Updated: parseCVETime(m.DateUpdated),
	}
	if v.ID == "" {
		v.ID = rc.CVEID
	}
	if v.Updated.IsZero() {
		v.Updated = rc.DateUpdated
	}
	if v.Rejected {
		v.Description = english(cna.RejectedReasons)
	} else {
		v.Description = english(cna.Descriptions)
	}
	if v.Title == "" {
		v.Title = firstLine(v.Description, 120)
	}
	// The CNA's score, else one an ADP such as CISA added.
	v.Severity = severity(cna.Metrics)
	for _, adp := range rec.Containers.ADP {
		if v.Severity != "" {
			break
		}
		v.Severity = severity(adp.Metrics)
	}
	return v, nil
}

// english picks the English text, else the first.
func english(vs []langValue) string {
	for _, v := range vs {
		if v.Lang == "en" || strings.HasPrefix(v.Lang, "en-") || strings.HasPrefix(v.Lang, "en_") {
			return strings.TrimSpace(v.Value)
		}
	}
	if len(vs) > 0 {
		return strings.TrimSpace(vs[0].Value)
	}
	return ""
}

// severity is the newest CVSS version's score in metrics, such as
// "CRITICAL 10.0 (CVSS 3.1)".
func severity(metrics []map[string]json.RawMessage) string {
	for _, version := range []struct{ key, name string }{
		{"cvssV4_0", "4.0"}, {"cvssV3_1", "3.1"}, {"cvssV3_0", "3.0"}, {"cvssV2_0", "2.0"},
	} {
		for _, m := range metrics {
			raw, ok := m[version.key]
			if !ok {
				continue
			}
			var c struct {
				BaseScore    *float64 `json:"baseScore"`
				BaseSeverity string   `json:"baseSeverity"`
			}
			if json.Unmarshal(raw, &c) != nil || c.BaseScore == nil {
				continue
			}
			s := fmt.Sprintf("%.1f (CVSS %s)", *c.BaseScore, version.name)
			if c.BaseSeverity != "" {
				s = strings.ToUpper(c.BaseSeverity) + " " + s
			}
			return s
		}
	}
	return ""
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(s, "\n")
	return truncate(s, n)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

// atom renders the page as an Atom feed. Each entry's id is the CVE's
// cve.org URL, so a reader shows an update to a CVE as the same entry
// changed, with <updated> from the record's dateUpdated.
// https://www.rfc-editor.org/rfc/rfc4287
func (p viewPage) atom() ([]byte, error) {
	type link struct {
		Rel  string `xml:"rel,attr,omitempty"`
		Type string `xml:"type,attr,omitempty"`
		Href string `xml:"href,attr"`
	}
	type text struct {
		Type string `xml:"type,attr,omitempty"`
		Body string `xml:",chardata"`
	}
	type person struct {
		Name string `xml:"name"`
	}
	type category struct {
		Term string `xml:"term,attr"`
	}
	type entry struct {
		ID         string     `xml:"id"`
		Title      text       `xml:"title"`
		Updated    string     `xml:"updated"`
		Published  string     `xml:"published,omitempty"`
		Author     *person    `xml:"author,omitempty"`
		Links      []link     `xml:"link"`
		Categories []category `xml:"category"`
		Summary    *text      `xml:"summary,omitempty"`
	}
	type feed struct {
		XMLName   xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
		ID        string   `xml:"id"`
		Title     string   `xml:"title"`
		Subtitle  string   `xml:"subtitle"`
		Updated   string   `xml:"updated"`
		Author    person   `xml:"author"`
		Links     []link   `xml:"link"`
		Generator string   `xml:"generator"`
		Entries   []entry  `xml:"entry"`
	}
	f := feed{
		ID:       "https://github.com/CVEProject/cvelistV5",
		Title:    "New and updated CVEs",
		Subtitle: fmt.Sprintf("The %d newest CVE records new or updated in cvelistV5, as of commit %s", len(p.CVEs), short(p.Commit)),
		Updated:  p.Generated.Format(time.RFC3339),
		Author:   person{"CVE Program"},
		// Relative, as the feed is published next to the page wherever
		// that is.
		Links: []link{
			{Rel: "self", Type: "application/atom+xml", Href: "feed.xml"},
			{Rel: "alternate", Type: "text/html", Href: "./"},
			{Rel: "via", Href: "https://github.com/CVEProject/cvelistV5"},
		},
		Generator: "featherd cve-sync",
	}
	if len(p.CVEs) > 0 && !p.CVEs[0].Updated.IsZero() {
		f.Updated = p.CVEs[0].Updated.UTC().Format(time.RFC3339)
	}
	for _, v := range p.CVEs {
		e := entry{
			ID:    v.Link(),
			Title: text{Body: v.ID + ": " + v.Title},
			Links: []link{
				{Rel: "alternate", Type: "text/html", Href: v.Link()},
				{Rel: "related", Type: "application/json", Href: "https://raw.githubusercontent.com/CVEProject/cvelistV5/" + p.Commit + "/" + v.Path},
			},
		}
		if v.Title == "" {
			e.Title.Body = v.ID
		}
		updated := v.Updated
		if updated.IsZero() {
			updated = p.Generated
		}
		e.Updated = updated.UTC().Format(time.RFC3339Nano)
		if !v.Published.IsZero() {
			e.Published = v.Published.UTC().Format(time.RFC3339Nano)
		}
		if v.Assigner != "" {
			e.Author = &person{v.Assigner}
		}
		e.Categories = append(e.Categories, category{map[bool]string{true: "new", false: "updated"}[v.New]})
		if v.Rejected {
			e.Categories = append(e.Categories, category{"rejected"})
		}
		summary := v.Description
		if v.Severity != "" {
			summary = v.Severity + "\n\n" + summary
		}
		if summary = strings.TrimSpace(summary); summary != "" {
			e.Summary = &text{Type: "text", Body: truncate(summary, 2000)}
		}
		f.Entries = append(f.Entries, e)
	}
	out, err := xml.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(out, '\n')...), nil
}

// html/template escapes every value, so a record's text can't inject
// markup into the page.
var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2 Jan 2006, 15:04 UTC")
	},
	"iso":     func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"snippet": func(s string) string { return truncate(s, 400) },
	"short":   short,
	"level": func(sev string) string {
		level, _, _ := strings.Cut(sev, " ")
		return strings.ToLower(level)
	},
}).Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>New and updated CVEs</title>
<link rel="alternate" type="application/atom+xml" title="New and updated CVEs" href="feed.xml">
<style>
body { font: 16px/1.5 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
article { border-bottom: 1px solid #ddd; padding: 0.75rem 0; }
h2 { font-size: 1.05rem; margin: 0; }
a { color: #0645ad; text-decoration: none; }
.id { font-family: ui-monospace, monospace; white-space: nowrap; }
.meta { color: #666; font-size: 0.85rem; }
.tag { display: inline-block; font-size: 0.75rem; padding: 0 0.4em; border-radius: 0.25rem; background: #eee; color: #444; }
.new { background: #dbeafe; color: #1e40af; }
.rejected { background: #e5e7eb; color: #6b7280; text-decoration: line-through; }
.critical { background: #7f1d1d; color: #fff; }
.high { background: #fee2e2; color: #991b1b; }
.medium { background: #fef3c7; color: #92400e; }
.low, .none { background: #dcfce7; color: #166534; }
p { margin: 0.25rem 0 0; }
footer { color: #888; font-size: 0.8rem; margin-top: 1rem; }
@media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } a { color: #8ab4f8; } article { border-color: #333; } .tag { background: #333; color: #ccc; } }
</style>
<h1>New and updated CVEs</h1>
<p>The {{len .CVEs}} newest CVE records new or updated in <a href="https://github.com/CVEProject/cvelistV5">cvelistV5</a>. Also as an <a href="feed.xml">Atom feed</a>.</p>
{{range .CVEs}}<article>
<h2><a class="id" href="{{.Link}}">{{.ID}}</a> {{.Title}}</h2>
<div class="meta">{{if .New}}<span class="tag new">new</span>{{else}}<span class="tag">updated</span>{{end}}
{{- if .Rejected}} <span class="tag rejected">rejected</span>{{end}}
{{- with .Severity}} <span class="tag {{level .}}">{{.}}</span>{{end}}
{{- with .Assigner}} · {{.}}{{end}}
{{- if not .Updated.IsZero}} · <time datetime="{{iso .Updated}}">{{date .Updated}}</time>{{end}}</div>
{{with .Description}}<p>{{snippet .}}</p>{{end}}
</article>
{{else}}<p>No CVEs yet.</p>
{{end}}<footer>Built {{date .Generated}} from cvelistV5 at <span class="id">{{short .Commit}}</span> by cve-sync.</footer>
</html>
`))
