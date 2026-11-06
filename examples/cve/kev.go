package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CISA's Known Exploited Vulnerabilities catalog is fetched from both
// places it's published: cisa.gov, revalidated with its ETag, and the
// cisagov/kev-data repository on GitHub, read like cvelistV5, from HEAD's
// commit in info/refs and the file at that commit on
// raw.githubusercontent.com. Each copy is mirrored raw under refs/ at its
// host and path, and the kev view is built from whichever was released
// last, so either source can be down or behind without holding it up.
// https://www.cisa.gov/known-exploited-vulnerabilities-catalog
const (
	kevCISAURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevRefsURL  = "https://github.com/cisagov/kev-data.git/info/refs?service=git-upload-pack"
	kevRawBase  = "https://raw.githubusercontent.com/cisagov/kev-data/"
	kevFile     = "known_exploited_vulnerabilities.json"
	kevStateKey = "mut/kev"
	kevCISAKey  = "refs/www.cisa.gov/sites/default/files/feeds/" + kevFile
	kevGHKey    = "refs/github.com/cisagov/kev-data/" + kevFile
	kevPageKey  = "view/kev.html"
	kevFeedKey  = "view/kev.xml"
	// maxKEVBytes is well above the catalog's 2 MB.
	maxKEVBytes = 64 << 20
)

// kevState is what each source last gave: CISA's ETag, GitHub's commit,
// and the dateReleased of the copy stored from each.
type kevState struct {
	CISAETag     string
	CISAReleased time.Time
	GHCommit     string
	GHReleased   time.Time
}

func (st kevState) encode() []byte {
	var b bytes.Buffer
	if st.CISAETag != "" {
		fmt.Fprintf(&b, "cisa_etag=%s\n", st.CISAETag)
	}
	if !st.CISAReleased.IsZero() {
		fmt.Fprintf(&b, "cisa_released=%s\n", st.CISAReleased.UTC().Format(time.RFC3339Nano))
	}
	if st.GHCommit != "" {
		fmt.Fprintf(&b, "github_commit=%s\n", st.GHCommit)
	}
	if !st.GHReleased.IsZero() {
		fmt.Fprintf(&b, "github_released=%s\n", st.GHReleased.UTC().Format(time.RFC3339Nano))
	}
	return b.Bytes()
}

func decodeKEVState(data []byte) kevState {
	var st kevState
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "cisa_etag":
			st.CISAETag = v
		case "cisa_released":
			st.CISAReleased, _ = time.Parse(time.RFC3339Nano, v)
		case "github_commit":
			st.GHCommit = v
		case "github_released":
			st.GHReleased, _ = time.Parse(time.RFC3339Nano, v)
		}
	}
	return st
}

// newest is the key of the copy released last, CISA's on a tie, or "" if
// neither is stored.
func (st kevState) newest() (key string, released time.Time) {
	switch {
	case st.GHReleased.After(st.CISAReleased):
		return kevGHKey, st.GHReleased
	case !st.CISAReleased.IsZero():
		return kevCISAKey, st.CISAReleased
	}
	return "", time.Time{}
}

type kevCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

func parseKEV(data []byte) (kevCatalog, time.Time, error) {
	var c kevCatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return c, time.Time{}, err
	}
	released, err := time.Parse(time.RFC3339Nano, c.DateReleased)
	if err != nil {
		return c, time.Time{}, fmt.Errorf("dateReleased %q: %w", c.DateReleased, err)
	}
	if len(c.Vulnerabilities) == 0 {
		return c, time.Time{}, errors.New("no vulnerabilities")
	}
	return c, released, nil
}

// syncKEV updates the mirror from both sources. A source's failure is
// reported in res and doesn't fail the sync; only featherd's does. It
// reports whether the copy the view is built from changed.
func (s *syncer) syncKEV(ctx context.Context, res *syncResult) (changed bool, err error) {
	resp, err := s.s3.get(ctx, kevStateKey)
	if err != nil {
		return false, err
	}
	var st kevState
	if resp.status == http.StatusOK {
		st = decodeKEVState(resp.body)
	}
	next := st
	var errs []error

	// cisa.gov: one revalidated request, 304 when nothing changed.
	data, etag, err := s.fetchKEV(ctx, kevCISAURL, st.CISAETag)
	if err == nil && data != nil {
		var released time.Time
		if released, err = s.storeKEV(ctx, kevCISAKey, data, res); err == nil {
			next.CISAETag, next.CISAReleased = etag, released
		}
	}
	if err != nil {
		if isS3Error(err) {
			return false, err
		}
		errs = append(errs, fmt.Errorf("cisa.gov: %w", err))
	}

	// GitHub: HEAD's commit, and the file only if it moved.
	head, err := s.refsHead(ctx, s.web, kevRefsURL)
	if err == nil && head != st.GHCommit {
		data, _, err = s.fetchKEV(ctx, kevRawBase+head+"/"+kevFile, "")
		if err == nil {
			var released time.Time
			if released, err = s.storeKEV(ctx, kevGHKey, data, res); err == nil {
				next.GHCommit, next.GHReleased = head, released
			}
		}
	}
	if err != nil {
		if isS3Error(err) {
			return false, err
		}
		errs = append(errs, fmt.Errorf("kev-data: %w", err))
	}
	res.KEVErr = errors.Join(errs...)

	if resp.status == http.StatusOK && bytes.Equal(next.encode(), st.encode()) {
		return false, nil
	}
	if _, err := s.s3.put(ctx, kevStateKey, "text/plain; charset=utf-8", next.encode(), "", ""); err != nil {
		return false, err
	}
	// The same release from the other source is the same catalog.
	_, oldReleased := st.newest()
	_, newReleased := next.newest()
	return !newReleased.Equal(oldReleased), nil
}

// fetchKEV GETs a copy of the catalog, revalidating etag if set; it
// returns nil data for 304.
func (s *syncer) fetchKEV(ctx context.Context, u, etag string) (data []byte, newETag string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "featherd-cve-sync")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.web.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxKEVBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", u, err)
	}
	if len(data) > maxKEVBytes {
		return nil, "", fmt.Errorf("GET %s: over %d bytes", u, maxKEVBytes)
	}
	return data, resp.Header.Get("ETag"), nil
}

// storeKEV checks a copy is a catalog and stores it raw at key, unless
// it's unchanged.
func (s *syncer) storeKEV(ctx context.Context, key string, data []byte, res *syncResult) (time.Time, error) {
	_, released, err := parseKEV(data)
	if err != nil {
		return time.Time{}, fmt.Errorf("not a KEV catalog: %w", err)
	}
	stored, err := s.putIfChanged(ctx, key, "application/json", data)
	if err != nil {
		return time.Time{}, err
	}
	if stored {
		res.KEVStored++
	}
	return released, nil
}

// putIfChanged PUTs body at key unless featherd's sha256 ETag shows it's
// already there.
func (s *syncer) putIfChanged(ctx context.Context, key, contentType string, body []byte) (bool, error) {
	head, err := s.s3.head(ctx, key)
	if err != nil {
		return false, err
	}
	if head.status == http.StatusOK && head.etag == `"`+sha256Hex(body)+`"` {
		return false, nil
	}
	if _, err := s.s3.put(ctx, key, contentType, body, "", ""); err != nil {
		return false, err
	}
	return true, nil
}

// kevInfo is what the kev view shows of a CVE's catalog entry.
type kevInfo struct {
	Added, Due time.Time
	Product    string // "Apple Multiple Products"
	Action     string
	Ransomware bool // known to be used in ransomware campaigns
}

// writeKEVView writes view/kev.html and view/kev.xml: the CVEs added to
// the catalog most recently, from the newest copy, with their records read
// back from the bucket for severity. It does nothing until a copy is
// stored.
func (s *syncer) writeKEVView(ctx context.Context, commit string) error {
	resp, err := s.s3.get(ctx, kevStateKey)
	if err != nil || resp.status != http.StatusOK {
		return err
	}
	key, _ := decodeKEVState(resp.body).newest()
	if key == "" {
		return nil
	}
	if resp, err = s.s3.get(ctx, key); err != nil || resp.status != http.StatusOK {
		return err
	}
	cat, _, err := parseKEV(resp.body)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	var entries []kevEntry
	for _, e := range cat.Vulnerabilities {
		if cveIDRE.MatchString(e.CVEID) {
			entries = append(entries, e)
		}
	}
	// dateAdded is YYYY-MM-DD, so it sorts as a string.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].DateAdded > entries[j].DateAdded })
	entries = entries[:min(len(entries), s.viewSize)]

	cves := make([]viewCVE, len(entries))
	pos := map[string]int{}
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i], _ = recordPath(change{CVEID: e.CVEID})
		pos[paths[i]] = i
		cves[i] = viewCVE{ID: e.CVEID, Path: paths[i]}
	}
	if err := s.readBack(ctx, paths, func(path string, data []byte) {
		i := pos[path]
		if c, err := newViewCVE(recentChange{CVEID: entries[i].CVEID, Path: path}, data); err == nil {
			cves[i] = c // each goroutine writes its own index
		}
	}); err != nil {
		return err
	}
	for i, e := range entries {
		c := &cves[i]
		added, _ := time.Parse(time.DateOnly, e.DateAdded)
		due, _ := time.Parse(time.DateOnly, e.DueDate)
		c.KEV = &kevInfo{
			Added: added, Due: due, Action: strings.TrimSpace(e.RequiredAction),
			Product:    strings.TrimSpace(e.VendorProject + " " + e.Product),
			Ransomware: e.KnownRansomwareCampaignUse == "Known",
		}
		// The catalog's name and description are written for defenders;
		// the record's are kept if it has none.
		if e.VulnerabilityName != "" {
			c.Title = e.VulnerabilityName
		}
		if e.ShortDescription != "" {
			c.Description = strings.TrimSpace(e.ShortDescription)
		}
		// The view is of additions to the catalog, so it's ordered, and
		// its feed's entries dated, by when each was added.
		if !added.IsZero() {
			c.Updated = added
		}
		c.Refs = kevRefs(e.Notes)
	}
	page := viewPage{
		Commit: commit, Generated: s.now().UTC(), CVEs: cves,
		Title:  "Known exploited CVEs",
		About:  "most recently added to CISA's Known Exploited Vulnerabilities catalog " + cat.CatalogVersion,
		Source: "CISA KEV", SourceURL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		FeedID: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#cve-sync",
		Page:   "kev.html", Feed: "kev.xml",
	}
	return s.putView(ctx, page, kevPageKey, kevFeedKey)
}

// kevRefs is the links in an entry's notes, which are separated by " ; "
// and sometimes labeled. CISA's own directives, cited by every entry,
// are left out.
func kevRefs(notes string) []viewRef {
	var refs []viewRef
	for part := range strings.SplitSeq(notes, ";") {
		i := strings.Index(part, "http")
		if i < 0 {
			continue
		}
		raw := strings.TrimSpace(part[i:])
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
		if host == "cisa.gov" || strings.HasSuffix(host, ".cisa.gov") {
			continue
		}
		refs = append(refs, viewRef{Title: truncate(host+strings.TrimSuffix(u.Path, "/"), 60), URL: raw})
	}
	return refs
}
