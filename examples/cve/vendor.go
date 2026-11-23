package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// The vendor views: the newest new or updated CVEs a vendor's CNA assigned,
// each linked to the vendor's security notes or bulletins they cite, which
// are mirrored into the bucket under refs/.
//
// deltaLog.json doesn't say who assigned a CVE, so each vendor has an index,
// mut/vendor/<name>, of its records newest first. It's kept up as records
// are stored, built in full by a seed, and for a bucket that has none,
// backfilled once from deltaLog.json's 30 days.
type vendor struct {
	Name     string // view/<Name>.html and .xml, mut/vendor/<Name>
	Assigner string // cveMetadata.assignerShortName
	Title    string
	OSV      bool // link the OSV Android entries that alias a CVE
	// HighOnly shows just the HIGH and CRITICAL ones. The index still
	// holds every record, so one scored later, by an update, joins.
	HighOnly bool
}

// The order is the nav's; the last vendor's feed is written last, which
// ensureView takes as the whole of the vendor views.
//
// The Linux kernel CNA assigns about 25 CVEs a day and scores only about
// 40% of them, all HIGH or CRITICAL, so its page shows just those; the
// unscored rest would fill 500 entries in three weeks. Microsoft scores
// every CVE and publishes in monthly batches, three quarters of them
// HIGH or CRITICAL, so its page shows them all. Chrome's CNA assigns a few
// hundred a year, each with its own severity in the description, and
// leaves the CVSS score to CISA's ADP, so its page shows them all too.
// Go's CNA covers the standard library, golang.org/x and the toolchain, a
// few dozen a year, mostly unscored, so its page shows them all as well.
// Apache's CNA covers every Apache Software Foundation project (httpd,
// Tomcat, Struts, Kafka and the rest), several hundred a year, often rated
// only in the description ("important", "moderate"), so its page shows
// them all too. OpenSSL's CNA covers OpenSSL alone, a dozen or so a year,
// each rated in its advisory (Low, Moderate, High) and often unscored, so
// its page shows them all as well.
var vendors = []vendor{
	{Name: "apple", Assigner: "apple", Title: "Apple"},
	{Name: "android", Assigner: "google_android", Title: "Android", OSV: true},
	{Name: "linux", Assigner: "Linux", Title: "Linux kernel", HighOnly: true},
	{Name: "microsoft", Assigner: "microsoft", Title: "Microsoft"},
	{Name: "chrome", Assigner: "Chrome", Title: "Chrome"},
	{Name: "go", Assigner: "Go", Title: "Go"},
	{Name: "apache", Assigner: "apache", Title: "Apache"},
	{Name: "openssl", Assigner: "openssl", Title: "OpenSSL"},
}

func vendorFor(assigner string) *vendor {
	for i := range vendors {
		if vendors[i].Assigner == assigner {
			return &vendors[i]
		}
	}
	return nil
}

func (v vendor) indexKey() string { return "mut/vendor/" + v.Name }
func (v vendor) pageKey() string  { return "view/" + v.Name + ".html" }
func (v vendor) feedKey() string  { return "view/" + v.Name + ".xml" }

// vendorIndexMax bounds each index. Apple has assigned about 9,000 CVEs,
// Android about 5,000, and the Linux kernel and Microsoft many more; the
// views need only the newest -view of them, or for a HighOnly view, enough
// to find that many HIGH and CRITICAL (about 80 days of Linux's).
const vendorIndexMax = 2000

type indexEntry struct {
	Updated  time.Time
	ID, Path string
}

func encodeIndex(es []indexEntry) []byte {
	var b bytes.Buffer
	for _, e := range es {
		fmt.Fprintf(&b, "%s %s %s\n", e.Updated.UTC().Format(time.RFC3339Nano), e.ID, e.Path)
	}
	return b.Bytes()
}

func decodeIndex(data []byte) []indexEntry {
	var es []indexEntry
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 3 || !pathRE.MatchString(f[2]) {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, f[0])
		es = append(es, indexEntry{Updated: t, ID: f[1], Path: f[2]})
	}
	return es
}

// mergeIndex adds entries to an index, replacing any for the same CVE, and
// keeps it newest first and bounded.
func mergeIndex(old, add []indexEntry) []indexEntry {
	byID := map[string]indexEntry{}
	for _, e := range old {
		byID[e.ID] = e
	}
	for _, e := range add {
		byID[e.ID] = e
	}
	out := make([]indexEntry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Updated.Equal(out[j].Updated) {
			return out[i].Updated.After(out[j].Updated)
		}
		return out[i].ID > out[j].ID
	})
	return out[:min(len(out), vendorIndexMax)]
}

// recordInfo is what the vendor index and mirror read from a record.
type recordInfo struct {
	ID, Assigner string
	Updated      time.Time
	Refs         []string // reference URLs, the CNA's then the ADPs'
}

func parseRecordInfo(data []byte) (recordInfo, error) {
	type refs struct {
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	}
	var rec struct {
		CVEMetadata struct {
			CVEID             string `json:"cveId"`
			AssignerShortName string `json:"assignerShortName"`
			DateUpdated       string `json:"dateUpdated"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA refs   `json:"cna"`
			ADP []refs `json:"adp"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return recordInfo{}, err
	}
	m := rec.CVEMetadata
	info := recordInfo{ID: m.CVEID, Assigner: m.AssignerShortName, Updated: parseCVETime(m.DateUpdated)}
	for _, c := range append([]refs{rec.Containers.CNA}, rec.Containers.ADP...) {
		for _, r := range c.References {
			info.Refs = append(info.Refs, r.URL)
		}
	}
	return info, nil
}

// vendorChanges collects the vendors' records stored by a sync or seed,
// and the pages they cite.
type vendorChanges struct {
	mu      sync.Mutex
	entries map[string][]indexEntry // vendor name → its records stored
	refs    map[string]string       // refs/ key → URL, cited by those
}

func newVendorChanges() *vendorChanges {
	return &vendorChanges{entries: map[string][]indexEntry{}, refs: map[string]string{}}
}

// add notes a stored record if a vendor assigned it. It's safe for
// concurrent use; a nil vendorChanges ignores everything.
func (vc *vendorChanges) add(path string, data []byte) {
	if vc == nil {
		return
	}
	info, err := parseRecordInfo(data)
	if err != nil {
		return
	}
	v := vendorFor(info.Assigner)
	if v == nil || info.ID == "" {
		return
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.entries[v.Name] = append(vc.entries[v.Name], indexEntry{Updated: info.Updated, ID: info.ID, Path: path})
	for _, u := range info.Refs {
		if key, fetch, ok := refKey(u); ok {
			vc.refs[key] = fetch
		}
	}
}

// writeVendorIndexes merges the changes into each vendor's index. A
// vendor with no index yet is first backfilled from deltaLog.json at
// commit, unless commit is "" (a seed, whose changes are every record).
// It reports whether any index was backfilled.
func (s *syncer) writeVendorIndexes(ctx context.Context, commit string, vc *vendorChanges) (backfilled bool, err error) {
	old := map[string][]indexEntry{}
	var missing []vendor
	for _, v := range vendors {
		resp, err := s.s3.get(ctx, v.indexKey())
		if err != nil {
			return false, err
		}
		if resp.status == http.StatusOK {
			old[v.Name] = decodeIndex(resp.body)
			if old[v.Name] == nil {
				old[v.Name] = []indexEntry{} // present, if empty
			}
		} else {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 && commit != "" {
		s.log.Printf("vendor index missing for %d vendors; backfilling from deltaLog.json", len(missing))
		if err := s.backfillVendors(ctx, commit, vc); err != nil {
			return false, err
		}
		backfilled = true
	}
	for _, v := range vendors {
		add := vc.entries[v.Name]
		if len(add) == 0 && old[v.Name] != nil {
			continue
		}
		idx := mergeIndex(old[v.Name], add)
		if _, err := s.s3.put(ctx, v.indexKey(), "text/plain; charset=utf-8", encodeIndex(idx), "", ""); err != nil {
			return backfilled, err
		}
	}
	return backfilled, nil
}

// backfillVendors reads back every record deltaLog.json at commit lists,
// which is about 30 days' worth, and adds the vendors' to vc. It's run
// once, for a bucket synced before the vendor views; a seed builds the
// indexes from every record instead.
func (s *syncer) backfillVendors(ctx context.Context, commit string, vc *vendorChanges) error {
	seen := map[string]bool{}
	var paths []string
	err := s.scanDeltaLog(ctx, commit, func(e delta, _ time.Time) bool {
		for _, c := range append(e.New, e.Updated...) {
			if p, ok := recordPath(c); ok && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
		return true
	})
	if err != nil {
		return err
	}
	// Pages cited by the backfilled records aren't fetched here: the views
	// fetch the ones they show.
	tmp := newVendorChanges()
	if err := s.readBack(ctx, paths, tmp.add); err != nil {
		return err
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	for name, es := range tmp.entries {
		vc.entries[name] = append(vc.entries[name], es...)
	}
	return nil
}

// readBack GETs each key from the bucket, -parallel at a time, and passes
// the ones present to fn, which must be safe for concurrent use.
func (s *syncer) readBack(ctx context.Context, keys []string, fn func(key string, data []byte)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	work := make(chan string)
	for range min(s.parallel, max(len(keys), 1)) {
		wg.Go(func() {
			for k := range work {
				resp, err := s.s3.get(ctx, k)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					mu.Unlock()
					continue
				}
				if resp.status == http.StatusOK {
					fn(k, resp.body)
				}
			}
		})
	}
feed:
	for _, k := range keys {
		select {
		case work <- k:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return firstErr
}

// refs/ mirrors the vendor pages records cite, as raw HTML, at their host
// and path: refs/support.apple.com/en-us/122716.html. Only these shapes of
// URL are mirrored, so nothing a record cites can write elsewhere.
var (
	appleRefRE   = regexp.MustCompile(`^/(?:[a-z]{2}-[a-z]{2}/)?(?:kb/)?(?:HT)?[0-9]+$`)
	androidRefRE = regexp.MustCompile(`^/docs/security/bulletin/(?:[a-z]+/)?(?:[0-9]{4}/)?(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|android-[0-9]+[a-z]*(?:-qpr[0-9]+)?)$`)
)

// refKey maps a cited URL to its key under refs/ and the URL to fetch it
// from, or reports that it isn't a page that's mirrored. Android's
// bulletins moved under /docs/, so the old URLs map to the same key.
func refKey(raw string) (key, fetch string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".html")
	switch host {
	case "support.apple.com":
		ok = appleRefRE.MatchString(p)
	case "source.android.com":
		if !strings.HasPrefix(p, "/docs/") {
			p = "/docs" + p
		}
		ok = androidRefRE.MatchString(p)
	}
	if !ok {
		return "", "", false
	}
	return "refs/" + host + p + ".html", "https://" + host + p, true
}

// maxRefBytes bounds a mirrored page; Apple's and Android's are about
// 200 KB.
const maxRefBytes = 8 << 20

// refParallel is how many vendor pages are fetched at once.
const refParallel = 4

// mirrorRefs fetches each page and stores it, unless featherd's sha256
// ETag shows it's unchanged. It returns the titles of the pages fetched.
// A vendor site's failure is logged and counted rather than fatal, so it
// doesn't hold up the CVE sync; a missing page is fetched again by the
// next view that shows it.
func (s *syncer) mirrorRefs(ctx context.Context, refs map[string]string, res *syncResult) (map[string]string, error) {
	keys := make([]string, 0, len(refs))
	for k := range refs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	titles := map[string]string{}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	work := make(chan string)
	for range min(refParallel, max(len(keys), 1)) {
		wg.Go(func() {
			for k := range work {
				title, stored, err := s.mirrorRef(ctx, k, refs[k])
				mu.Lock()
				switch {
				case err == nil:
					titles[k] = title
					res.RefsFetched++
					if stored {
						res.RefsStored++
					}
				case isS3Error(err):
					if firstErr == nil {
						firstErr = err
					}
				default:
					res.RefsFailed++
					s.log.Printf("refs: %v", err)
				}
				mu.Unlock()
			}
		})
	}
	for _, k := range keys {
		work <- k
	}
	close(work)
	wg.Wait()
	return titles, firstErr
}

func isS3Error(err error) bool {
	_, ok := err.(*s3Error)
	return ok
}

func (s *syncer) mirrorRef(ctx context.Context, key, fetchURL string) (title string, stored bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "featherd-cve-sync")
	resp, err := s.web.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GET %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		return "", false, fmt.Errorf("GET %s: %q, not HTML", fetchURL, ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRefBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("GET %s: %w", fetchURL, err)
	}
	if len(body) > maxRefBytes {
		return "", false, fmt.Errorf("GET %s: over %d bytes", fetchURL, maxRefBytes)
	}
	title = pageTitle(body)
	// featherd's ETag is the body's sha256, so an unchanged page isn't
	// written again.
	stored, err = s.putIfChanged(ctx, key, "text/html; charset=utf-8", body)
	if err != nil {
		return "", false, err
	}
	return title, stored, nil
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// pageTitle is a page's <title> without the site's name: "About the
// security content of macOS Sequoia 15.5", "Android Security
// Bulletin—June 2026".
func pageTitle(page []byte) string {
	m := titleRE.FindSubmatch(page)
	if m == nil {
		return ""
	}
	t := html.UnescapeString(string(m[1]))
	t = strings.Join(strings.Fields(strings.ReplaceAll(t, " ", " ")), " ")
	t, _, _ = strings.Cut(t, " | ")
	t = strings.TrimSuffix(t, " - Apple Support")
	return truncate(strings.TrimSpace(t), 200)
}

// viewRef is a page a CVE in a vendor view cites, linked at its source.
type viewRef struct {
	Title, URL string
}

// writeVendorViews writes each vendor's page and feed of its newest
// records in the index. The pages cited by records stored this sync
// (changed) are fetched again, as vendors revise them as they go, and any
// page a view shows that isn't mirrored yet is fetched.
func (s *syncer) writeVendorViews(ctx context.Context, commit string, changed map[string]string, osv map[string][]string, res *syncResult) error {
	type vendorView struct {
		v    vendor
		cves []viewCVE
		refs [][]string // keys of the pages each cites, in order
	}
	var views []vendorView
	urls := map[string]string{} // key → the URL as cited, to link
	wanted := map[string]string{}
	for k, u := range changed {
		wanted[k] = u
	}
	for _, v := range vendors {
		resp, err := s.s3.get(ctx, v.indexKey())
		if err != nil {
			return err
		}
		idx := decodeIndex(resp.body)
		// The records are read back in batches until the view is full: one
		// batch of -view for most, smaller ones for a HighOnly view, which
		// reads further down the index.
		batch := s.viewSize
		if v.HighOnly {
			batch = viewBatch
		}
		var cves []viewCVE
		var infos []recordInfo
		for start := 0; start < len(idx) && len(cves) < s.viewSize; start += batch {
			part := idx[start:min(len(idx), start+batch)]
			got := make([]viewCVE, len(part))
			gotInfo := make([]recordInfo, len(part))
			pos := map[string]int{}
			paths := make([]string, len(part))
			for i, e := range part {
				pos[e.Path], paths[i] = i, e.Path
			}
			err = s.readBack(ctx, paths, func(path string, data []byte) {
				i := pos[path]
				c, err := newViewCVE(recentChange{CVEID: part[i].ID, Path: path}, data)
				if err != nil {
					return
				}
				info, _ := parseRecordInfo(data)
				got[i], gotInfo[i] = c, info
			})
			if err != nil {
				return err
			}
			for i, c := range got {
				if c.ID == "" || (v.HighOnly && !c.High()) || len(cves) >= s.viewSize {
					continue
				}
				cves, infos = append(cves, c), append(infos, gotInfo[i])
			}
		}
		vv := vendorView{v: v}
		for i, c := range cves {
			// A CVE's first published version is "new"; the views of
			// deltaLog tell new from updated, the index doesn't.
			c.New = !c.Published.IsZero() && c.Updated.Sub(c.Published) < time.Minute
			var keys []string
			for _, u := range infos[i].Refs {
				k, fetch, ok := refKey(u)
				if !ok || slices.Contains(keys, k) {
					continue
				}
				keys = append(keys, k)
				if _, ok := urls[k]; !ok {
					urls[k] = u
				}
				if _, ok := wanted[k]; !ok {
					wanted[k] = "?" + fetch // fetched only if it isn't mirrored
				}
			}
			vv.cves = append(vv.cves, c)
			vv.refs = append(vv.refs, keys)
		}
		views = append(views, vv)
	}

	// Pages not changed this sync are fetched only if they're missing.
	fetch := map[string]string{}
	var present []string
	for k, u := range wanted {
		if rest, ok := strings.CutPrefix(u, "?"); ok {
			head, err := s.s3.head(ctx, k)
			if err != nil {
				return err
			}
			if head.status == http.StatusOK {
				present = append(present, k)
				continue
			}
			u = rest
		}
		fetch[k] = u
	}
	titles, err := s.mirrorRefs(ctx, fetch, res)
	if err != nil {
		return err
	}
	// The titles of pages already mirrored are read from the bucket.
	var titleMu sync.Mutex
	if err := s.readBack(ctx, present, func(k string, data []byte) {
		titleMu.Lock()
		titles[k] = pageTitle(data)
		titleMu.Unlock()
	}); err != nil {
		return err
	}

	generated := s.now().UTC()
	for _, vv := range views {
		for i := range vv.cves {
			c := &vv.cves[i]
			for _, k := range vv.refs[i] {
				t := titles[k]
				if t == "" {
					t = strings.TrimSuffix(strings.TrimPrefix(k, "refs/"), ".html")
				}
				c.Refs = append(c.Refs, viewRef{Title: t, URL: urls[k]})
			}
			if vv.v.OSV {
				for _, id := range osv[c.ID] {
					c.Refs = append(c.Refs, viewRef{Title: id + " on OSV", URL: "https://osv.dev/vulnerability/" + id})
				}
			}
		}
		title, about := vv.v.Title+" CVEs", "assigned by "+vv.v.Title+" and new or updated"
		if vv.v.HighOnly {
			title = vv.v.Title + " HIGH and CRITICAL CVEs"
			about = "assigned by " + vv.v.Title + ", rated HIGH or CRITICAL, and new or updated"
		}
		page := viewPage{
			Commit: commit, Generated: generated, CVEs: vv.cves,
			Title: title, About: about,
			FeedID: "https://github.com/CVEProject/cvelistV5#" + vv.v.Name,
			Page:   vv.v.Name + ".html", Feed: vv.v.Name + ".xml",
		}
		if err := s.putView(ctx, page, vv.v.feedKey(), vv.v.pageKey()); err != nil {
			return err
		}
	}
	return nil
}
