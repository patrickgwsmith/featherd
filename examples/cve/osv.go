package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// OSV's Android ecosystem is mirrored too, entry for entry, to
// refs/osv/Android/<id>.json. Its entries are per Android bug
// (ASB-A-351830787, PUB-A-… for Pixel), not per bulletin, and CVE records
// don't name the bug, so the entries' aliases give the CVEs each covers.
//
// The first run reads all.zip, one 10 MB request; after that each run reads
// modified_id.csv, revalidated with its ETag, and fetches just the entries
// modified since. https://google.github.io/osv.dev/data/#data-dumps
const (
	osvBase     = "https://osv-vulnerabilities.storage.googleapis.com/Android/"
	osvStateKey = "mut/osv/Android"
	osvPrefix   = "refs/osv/Android/"
	// osvRefetchMax is how many changed entries are fetched one by one;
	// past it, all.zip is read again.
	osvRefetchMax = 500
)

var osvIDRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9][A-Za-z0-9._-]*$`)

type osvState struct {
	Modified time.Time           // the newest entry's modified
	CSVETag  string              // modified_id.csv's ETag when last read
	Aliases  map[string][]string // OSV ID → the CVEs it aliases
}

func (st osvState) encode() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "modified=%s\n", st.Modified.UTC().Format(time.RFC3339Nano))
	if st.CSVETag != "" {
		fmt.Fprintf(&b, "csv_etag=%s\n", st.CSVETag)
	}
	b.WriteString("\n")
	ids := make([]string, 0, len(st.Aliases))
	for id := range st.Aliases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "%s %s\n", id, strings.Join(st.Aliases[id], " "))
	}
	return b.Bytes()
}

func decodeOSVState(data []byte) osvState {
	st := osvState{Aliases: map[string][]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	header := true
	for sc.Scan() {
		line := sc.Text()
		if header {
			if line == "" {
				header = false
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			switch k {
			case "modified":
				st.Modified, _ = time.Parse(time.RFC3339Nano, v)
			case "csv_etag":
				st.CSVETag = v
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 {
			st.Aliases[f[0]] = f[1:]
		}
	}
	return st
}

// byCVE inverts the aliases: CVE → the OSV IDs that alias it.
func (st osvState) byCVE() map[string][]string {
	m := map[string][]string{}
	for id, cves := range st.Aliases {
		for _, c := range cves {
			m[c] = append(m[c], id)
		}
	}
	for _, ids := range m {
		sort.Strings(ids)
	}
	return m
}

// osvEntry is what's read of an OSV entry.
type osvEntry struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified"`
	Aliases  []string `json:"aliases"`
}

func (e osvEntry) cves() []string {
	var cves []string
	for _, a := range e.Aliases {
		if cveIDRE.MatchString(a) {
			cves = append(cves, a)
		}
	}
	return cves
}

// syncOSV brings the OSV Android mirror up to date. It returns the
// aliases by CVE as far as the mirror has them, even if the update failed,
// and whether anything changed.
func (s *syncer) syncOSV(ctx context.Context, res *syncResult) (byCVE map[string][]string, changed bool, err error) {
	resp, err := s.s3.get(ctx, osvStateKey)
	if err != nil {
		return nil, false, err
	}
	st := osvState{Aliases: map[string][]string{}}
	if resp.status == http.StatusOK {
		st = decodeOSVState(resp.body)
	}
	next, stored, err := s.updateOSV(ctx, st)
	res.OSVStored = stored
	if err != nil {
		return st.byCVE(), false, err
	}
	if next.Modified.Equal(st.Modified) && next.CSVETag == st.CSVETag && resp.status == http.StatusOK {
		return st.byCVE(), false, nil
	}
	if _, err := s.s3.put(ctx, osvStateKey, "text/plain; charset=utf-8", next.encode(), "", ""); err != nil {
		return st.byCVE(), false, err
	}
	return next.byCVE(), stored > 0, nil
}

func (s *syncer) updateOSV(ctx context.Context, st osvState) (osvState, int, error) {
	if st.Modified.IsZero() {
		return s.loadOSVZip(ctx, st)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvBase+"modified_id.csv", nil)
	if err != nil {
		return st, 0, err
	}
	if st.CSVETag != "" {
		req.Header.Set("If-None-Match", st.CSVETag)
	}
	resp, err := s.web.Do(req)
	if err != nil {
		return st, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return st, 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return st, 0, fmt.Errorf("OSV modified_id.csv: HTTP %d", resp.StatusCode)
	}
	// Each line is "<modified>,<id>"; it's newest first, but it's only
	// ~200 KB, so all of it is read rather than relying on that.
	var ids []string
	newest := st.Modified
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	for sc.Scan() {
		ts, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		t, err := time.Parse(time.RFC3339Nano, ts)
		if !ok || err != nil || !osvIDRE.MatchString(id) || !t.After(st.Modified) {
			continue
		}
		ids = append(ids, id)
		if t.After(newest) {
			newest = t
		}
	}
	if err := sc.Err(); err != nil {
		return st, 0, fmt.Errorf("OSV modified_id.csv: %w", err)
	}
	if len(ids) > osvRefetchMax {
		s.log.Printf("OSV: %d Android entries changed; reading all.zip", len(ids))
		return s.loadOSVZip(ctx, st)
	}

	next := osvState{Modified: newest, CSVETag: resp.Header.Get("ETag"), Aliases: st.Aliases}
	var (
		mu       sync.Mutex
		firstErr error
		stored   int
		wg       sync.WaitGroup
	)
	work := make(chan string)
	for range min(refParallel, max(len(ids), 1)) {
		wg.Go(func() {
			for id := range work {
				e, err := s.storeOSVEntry(ctx, id)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else if e.ID != "" {
					next.Aliases[id] = e.cves()
					stored++
				}
				mu.Unlock()
			}
		})
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		// The state isn't moved, so the next run fetches these again.
		return st, stored, firstErr
	}
	return next, stored, nil
}

func (s *syncer) storeOSVEntry(ctx context.Context, id string) (osvEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvBase+id+".json", nil)
	if err != nil {
		return osvEntry{}, err
	}
	resp, err := s.web.Do(req)
	if err != nil {
		return osvEntry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return osvEntry{}, nil // listed, then gone
	}
	if resp.StatusCode != http.StatusOK {
		return osvEntry{}, fmt.Errorf("OSV %s: HTTP %d", id, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRecordBytes+1))
	if err != nil {
		return osvEntry{}, err
	}
	return s.putOSVEntry(ctx, id, data)
}

func (s *syncer) putOSVEntry(ctx context.Context, id string, data []byte) (osvEntry, error) {
	if len(data) > maxRecordBytes {
		return osvEntry{}, fmt.Errorf("OSV %s: over %d bytes", id, maxRecordBytes)
	}
	var e osvEntry
	if err := json.Unmarshal(data, &e); err != nil || e.ID != id {
		return osvEntry{}, fmt.Errorf("OSV %s: not its entry", id)
	}
	if _, err := s.s3.put(ctx, osvPrefix+id+".json", "application/json", data, "", ""); err != nil {
		return osvEntry{}, err
	}
	return e, nil
}

// loadOSVZip stores every entry in all.zip. modified_id.csv's ETag is
// left unset, so the next run reads it and fetches anything modified after
// the newest entry here.
func (s *syncer) loadOSVZip(ctx context.Context, st osvState) (osvState, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvBase+"all.zip", nil)
	if err != nil {
		return st, 0, err
	}
	resp, err := s.web.Do(req)
	if err != nil {
		return st, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, 0, fmt.Errorf("OSV all.zip: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return st, 0, fmt.Errorf("OSV all.zip: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return st, 0, fmt.Errorf("OSV all.zip: %w", err)
	}
	next := osvState{Aliases: map[string][]string{}}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	work := make(chan *zip.File)
	for range s.parallel {
		wg.Go(func() {
			for f := range work {
				id := strings.TrimSuffix(f.Name, ".json")
				rc, err := f.Open()
				var body []byte
				if err == nil {
					body, err = io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
					rc.Close()
				}
				var e osvEntry
				if err == nil {
					e, err = s.putOSVEntry(ctx, id, body)
				}
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else {
					next.Aliases[id] = e.cves()
					if t, err := time.Parse(time.RFC3339Nano, e.Modified); err == nil && t.After(next.Modified) {
						next.Modified = t
					}
				}
				mu.Unlock()
			}
		})
	}
	for _, f := range zr.File {
		if id, ok := strings.CutSuffix(f.Name, ".json"); ok && osvIDRE.MatchString(id) {
			work <- f
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		return st, len(next.Aliases), firstErr
	}
	if next.Modified.IsZero() {
		return st, 0, fmt.Errorf("OSV all.zip: no entries")
	}
	return next, len(next.Aliases), nil
}
