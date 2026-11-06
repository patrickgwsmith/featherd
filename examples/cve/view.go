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

// The views: the newest CVEs that deltaLog.json lists as new or updated,
// and the newest of those rated HIGH or CRITICAL, each as a page and an
// Atom feed. They're a projection of deltaLog.json at the commit synced and
// the records in the bucket, so they're simply rewritten with plain PUTs
// on each sync.
const (
	indexKey    = "view/index.html"
	feedKey     = "view/feed.xml"
	highPageKey = "view/high.html"
	highFeedKey = "view/high.xml"
)

// highWindow bounds how far back in deltaLog.json the high view looks, so
// a bucket missing most records (one never seeded) doesn't read all 30
// days on every sync.
const highWindow = 7 * 24 * time.Hour

// viewBatch is how many records are read back at once while scanning.
const viewBatch = 64

// viewScan collects the views from deltaLog entries given newest first.
// Each CVE is taken once, at its newest listing, and its record is read
// back from the bucket in batches, since only the record has its severity.
type viewScan struct {
	s       *syncer
	seen    map[string]bool
	pending []recentChange
	listed  int       // CVEs taken, for the first view
	all     []viewCVE // of the first viewSize CVEs taken
	high    []viewCVE // HIGH or CRITICAL, up to viewSize
	newest  time.Time // the first entry's fetchTime
}

type recentChange struct {
	CVEID, Path string
	New         bool      // listed under "new", not "updated"
	DateUpdated time.Time // from deltaLog, if the record has none
}

func (v *viewScan) done() bool {
	return v.listed >= v.s.viewSize && len(v.high) >= v.s.viewSize
}

// add takes one entry's CVEs, reading back each full batch.
func (v *viewScan) add(ctx context.Context, e delta) error {
	for i, list := range [][]change{e.New, e.Updated} {
		for _, c := range list {
			p, ok := recordPath(c)
			if !ok || v.seen[p] {
				continue
			}
			v.seen[p] = true
			v.pending = append(v.pending, recentChange{CVEID: c.CVEID, Path: p, New: i == 0, DateUpdated: parseCVETime(c.DateUpdated)})
			if len(v.pending) >= viewBatch {
				if err := v.flush(ctx); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// flush reads the pending CVEs' records back from the bucket. A record
// that isn't in the bucket, such as one missing at the commit, is left
// out.
func (v *viewScan) flush(ctx context.Context) error {
	batch := v.pending
	v.pending = nil
	if v.done() {
		return nil
	}
	cves := make([]viewCVE, len(batch))
	errs := make([]error, len(batch))
	sem := make(chan struct{}, v.s.parallel)
	var wg sync.WaitGroup
	for i, rc := range batch {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := v.s.s3.get(ctx, rc.Path)
			if err != nil {
				errs[i] = err
				return
			}
			if resp.status != http.StatusOK {
				return
			}
			c, err := newViewCVE(rc, resp.body)
			if err != nil {
				v.s.log.Printf("view: %s: %v; left out", rc.Path, err)
				return
			}
			cves[i] = c
		})
	}
	wg.Wait()
	for i, c := range cves {
		if errs[i] != nil {
			return errs[i]
		}
		if v.listed < v.s.viewSize {
			v.listed++
			if c.ID != "" {
				v.all = append(v.all, c)
			}
		}
		if c.High() && len(v.high) < v.s.viewSize {
			v.high = append(v.high, c)
		}
	}
	return nil
}

// ensureView writes the views at commit that are missing, on a run where
// cvelistV5 hasn't moved: the vendor views also when their index was
// just backfilled, or OSV changed.
func (s *syncer) ensureView(ctx context.Context, commit string, osv map[string][]string, osvChanged, kevChanged bool, res *syncResult) error {
	resp, err := s.s3.head(ctx, highFeedKey)
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		if err := s.writeView(ctx, commit); err != nil {
			return err
		}
	}
	backfilled, err := s.writeVendorIndexes(ctx, commit, newVendorChanges())
	if err != nil {
		return err
	}
	// The last vendor's feed is written last.
	resp, err = s.s3.head(ctx, vendors[len(vendors)-1].feedKey())
	if err != nil {
		return err
	}
	if backfilled || osvChanged || resp.status != http.StatusOK {
		if err := s.writeVendorViews(ctx, commit, nil, osv, res); err != nil {
			return err
		}
	}
	if resp, err = s.s3.head(ctx, kevFeedKey); err != nil {
		return err
	}
	if kevChanged || resp.status != http.StatusOK {
		return s.writeKEVView(ctx, commit)
	}
	return nil
}

// writeView reads deltaLog.json at commit, newest first, until both views
// are full or it's highWindow past the newest entry, and writes them.
// The first view usually needs only the newest few hourly entries; the
// high view reads on further, as most CVEs aren't HIGH or CRITICAL, and
// many get a score only later, from an ADP such as CISA's.
func (s *syncer) writeView(ctx context.Context, commit string) error {
	v := &viewScan{s: s, seen: map[string]bool{}}
	var addErr error
	err := s.scanDeltaLog(ctx, commit, func(e delta, t time.Time) bool {
		if v.newest.IsZero() {
			v.newest = t
		} else if t.Before(v.newest.Add(-highWindow)) {
			return false
		}
		addErr = v.add(ctx, e)
		return addErr == nil && !v.done()
	})
	if err == nil {
		err = addErr
	}
	if err == nil {
		err = v.flush(ctx)
	}
	if err != nil {
		return err
	}

	generated := s.now().UTC()
	pages := []viewPage{
		{
			Commit: commit, Generated: generated, CVEs: v.all,
			Title: "New and updated CVEs", About: "new or updated",
			FeedID: "https://github.com/CVEProject/cvelistV5",
			Page:   "./", Feed: "feed.xml",
		},
		{
			Commit: commit, Generated: generated, CVEs: v.high,
			Title: "New and updated HIGH and CRITICAL CVEs", About: "rated HIGH or CRITICAL and new or updated",
			FeedID: "https://github.com/CVEProject/cvelistV5#high",
			Page:   "high.html", Feed: "high.xml",
		},
	}
	keys := [][2]string{{indexKey, feedKey}, {highPageKey, highFeedKey}}
	// The high feed is written last: ensureView takes it as the whole view.
	for i, page := range pages {
		if err := s.putView(ctx, page, keys[i][0], keys[i][1]); err != nil {
			return err
		}
	}
	return nil
}

// putView writes a view's page and its feed.
func (s *syncer) putView(ctx context.Context, page viewPage, pageKey, feedKey string) error {
	sortByUpdated(page.CVEs)
	page.Nav = viewNav
	if page.Source == "" {
		page.Source, page.SourceURL = "cvelistV5", "https://github.com/CVEProject/cvelistV5"
	}
	var html bytes.Buffer
	if err := indexTemplate.Execute(&html, page); err != nil {
		return err
	}
	feed, err := page.atom()
	if err != nil {
		return err
	}
	if _, err := s.s3.put(ctx, pageKey, "text/html; charset=utf-8", html.Bytes(), "", ""); err != nil {
		return err
	}
	_, err = s.s3.put(ctx, feedKey, "application/atom+xml; charset=utf-8", feed, "", "")
	return err
}

// viewNav links every view from each page.
var viewNav = func() []navLink {
	nav := []navLink{{"./", "All"}, {"high.html", "HIGH and CRITICAL"}, {"kev.html", "Known exploited"}}
	for _, v := range vendors {
		nav = append(nav, navLink{v.Name + ".html", v.Title})
	}
	return nav
}()

type navLink struct{ Href, Title string }

func sortByUpdated(cves []viewCVE) {
	sort.SliceStable(cves, func(i, j int) bool {
		a, b := cves[i], cves[j]
		if !a.Updated.Equal(b.Updated) {
			return a.Updated.After(b.Updated)
		}
		return a.ID > b.ID
	})
}

type viewPage struct {
	Commit    string
	Generated time.Time
	CVEs      []viewCVE

	Title, About string // About completes "The N newest CVE records …"
	// Source is what the view lists from, cvelistV5 unless set.
	Source, SourceURL string
	FeedID            string
	Page, Feed        string // relative links to this page and its feed
	Nav               []navLink
}

// viewCVE is what the view shows of one record.
type viewCVE struct {
	ID, Title, Description, Assigner, Path string
	Severity                               string // "CRITICAL 9.8 (CVSS 3.1)"
	Level                                  string // "critical", "high", "medium", "low" or "none"
	New, Rejected                          bool
	Published, Updated                     time.Time
	Refs                                   []viewRef // in the vendor and kev views
	KEV                                    *kevInfo  // in the kev view
}

func (v viewCVE) Link() string { return "https://www.cve.org/CVERecord?id=" + v.ID }

// High reports a published CVE rated HIGH or CRITICAL.
func (v viewCVE) High() bool {
	return v.ID != "" && !v.Rejected && (v.Level == "high" || v.Level == "critical")
}

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
	v.Severity, v.Level = severity(cna.Metrics)
	for _, adp := range rec.Containers.ADP {
		if v.Severity != "" {
			break
		}
		v.Severity, v.Level = severity(adp.Metrics)
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
// "CRITICAL 10.0 (CVSS 3.1)", and its level, such as "critical". A score
// with no baseSeverity gets the level of its range: CVSS 3 and 4's, and
// CVSS 2's, which tops out at high.
func severity(metrics []map[string]json.RawMessage) (label, level string) {
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
			label = fmt.Sprintf("%.1f (CVSS %s)", *c.BaseScore, version.name)
			level = strings.ToLower(c.BaseSeverity)
			if level == "" {
				level = scoreLevel(*c.BaseScore, version.key == "cvssV2_0")
			}
			if c.BaseSeverity != "" {
				label = strings.ToUpper(c.BaseSeverity) + " " + label
			}
			return label, level
		}
	}
	return "", ""
}

func scoreLevel(score float64, v2 bool) string {
	switch {
	case score >= 9 && !v2:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0 || v2:
		return "low"
	}
	return "none"
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
		ID:       p.FeedID,
		Title:    p.Title,
		Subtitle: fmt.Sprintf("The %d newest CVE records %s in %s, as of cvelistV5 commit %s", len(p.CVEs), p.About, p.Source, short(p.Commit)),
		Updated:  p.Generated.Format(time.RFC3339),
		Author:   person{"CVE Program"},
		// Relative, as the feed is published next to the page wherever
		// that is.
		Links: []link{
			{Rel: "self", Type: "application/atom+xml", Href: p.Feed},
			{Rel: "alternate", Type: "text/html", Href: p.Page},
			{Rel: "via", Href: "https://github.com/CVEProject/cvelistV5"},
		},
		Generator: "featherd cve-sync",
	}
	if len(p.CVEs) > 0 && !p.CVEs[0].Updated.IsZero() {
		f.Updated = p.CVEs[0].Updated.UTC().Format(time.RFC3339)
	}
	for _, v := range p.CVEs {
		id := v.Link()
		if v.KEV != nil {
			// Its own entry, apart from the record's in the other feeds.
			id += "#kev"
		}
		e := entry{
			ID:    id,
			Title: text{Body: v.ID + ": " + v.Title},
			Links: []link{
				{Rel: "alternate", Type: "text/html", Href: v.Link()},
				{Rel: "related", Type: "application/json", Href: "https://raw.githubusercontent.com/CVEProject/cvelistV5/" + p.Commit + "/" + v.Path},
			},
		}
		for _, r := range v.Refs {
			e.Links = append(e.Links, link{Rel: "related", Type: "text/html", Href: r.URL})
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
		if v.KEV != nil {
			e.Categories = append(e.Categories, category{"known-exploited"})
			if v.KEV.Ransomware {
				e.Categories = append(e.Categories, category{"ransomware"})
			}
		} else {
			e.Categories = append(e.Categories, category{map[bool]string{true: "new", false: "updated"}[v.New]})
		}
		if v.Rejected {
			e.Categories = append(e.Categories, category{"rejected"})
		}
		summary := v.Description
		if v.Severity != "" {
			summary = v.Severity + "\n\n" + summary
		}
		if k := v.KEV; k != nil {
			summary += "\n\n" + k.Product + ". Added to CISA KEV " + k.Added.Format(time.DateOnly)
			if !k.Due.IsZero() {
				summary += ", due " + k.Due.Format(time.DateOnly)
			}
			summary += "."
			if k.Action != "" {
				summary += " " + k.Action
			}
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
	"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"day": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2 Jan 2006")
	},
	"snippet": func(s string) string { return truncate(s, 400) },
	"short":   short,
}).Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="alternate" type="application/atom+xml" title="{{.Title}}" href="{{.Feed}}">
<style>
body { font: 16px/1.5 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
article { border-bottom: 1px solid #ddd; padding: 0.75rem 0; }
h2 { font-size: 1.05rem; margin: 0; }
a { color: #0645ad; text-decoration: none; }
.id { font-family: ui-monospace, monospace; white-space: nowrap; }
.meta { color: #666; font-size: 0.85rem; }
.tag { display: inline-block; font-size: 0.75rem; padding: 0 0.4em; border-radius: 0.25rem; background: #eee; color: #444; }
.new { background: #dbeafe; color: #1e40af; }
.kev, .ransomware { background: #ede9fe; color: #5b21b6; }
.ransomware { background: #1f2937; color: #fff; }
.rejected { background: #e5e7eb; color: #6b7280; text-decoration: line-through; }
.critical { background: #7f1d1d; color: #fff; }
.high { background: #fee2e2; color: #991b1b; }
.medium { background: #fef3c7; color: #92400e; }
.low, .none { background: #dcfce7; color: #166534; }
p { margin: 0.25rem 0 0; }
nav { font-size: 0.9rem; margin-bottom: 0.5rem; }
.refs { font-size: 0.85rem; }
footer { color: #888; font-size: 0.8rem; margin-top: 1rem; }
@media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } a { color: #8ab4f8; } article { border-color: #333; } .tag { background: #333; color: #ccc; } }
</style>
<h1>{{.Title}}</h1>
<nav>{{range $i, $n := .Nav}}{{if $i}} · {{end}}{{if eq $n.Href $.Page}}<strong>{{$n.Title}}</strong>{{else}}<a href="{{$n.Href}}">{{$n.Title}}</a>{{end}}{{end}}</nav>
<p>The {{len .CVEs}} newest CVE records {{.About}} in <a href="{{.SourceURL}}">{{.Source}}</a>. Also as an <a href="{{.Feed}}">Atom feed</a>.</p>
{{range .CVEs}}<article>
<h2><a class="id" href="{{.Link}}">{{.ID}}</a> {{.Title}}</h2>
<div class="meta">{{if .KEV}}<span class="tag kev">known exploited</span>{{if .KEV.Ransomware}} <span class="tag ransomware">ransomware</span>{{end}}{{else if .New}}<span class="tag new">new</span>{{else}}<span class="tag">updated</span>{{end}}
{{- if .Rejected}} <span class="tag rejected">rejected</span>{{end}}
{{- if .Severity}} <span class="tag {{.Level}}">{{.Severity}}</span>{{end}}
{{- with .Assigner}} · {{.}}{{end}}
{{- if .KEV}}{{with .KEV.Product}} · {{.}}{{end}} · added <time datetime="{{iso .KEV.Added}}">{{day .KEV.Added}}</time>{{if not .KEV.Due.IsZero}}, due {{day .KEV.Due}}{{end}}
{{- else if not .Updated.IsZero}} · <time datetime="{{iso .Updated}}">{{date .Updated}}</time>{{end}}</div>
{{with .Description}}<p>{{snippet .}}</p>{{end}}
{{with .Refs}}<p class="refs">{{range $i, $r := .}}{{if $i}} · {{end}}<a href="{{$r.URL}}">{{$r.Title}}</a>{{end}}</p>{{end}}
</article>
{{else}}<p>No CVEs yet.</p>
{{end}}<footer>Built {{date .Generated}} from cvelistV5 at <span class="id">{{short .Commit}}</span> by cve-sync.</footer>
</html>
`))
