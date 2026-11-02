package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type syncer struct {
	s3       *s3Client
	github   *http.Client
	refsURL  string // git's info/refs for cvelistV5
	rawBase  string // raw.githubusercontent.com/…/cvelistV5/, + commit/path
	now      func() time.Time
	log      *log.Logger
	parallel int
	viewSize int // CVEs in view/index.html and view/feed.xml
}

// stateKey holds what the last sync reached. It's the commit point: it's
// written only after every record of the deltas it covers is stored.
const stateKey = "mut/sync"

type syncState struct {
	Commit    string    // the cvelistV5 commit synced
	FetchTime time.Time // the newest deltaLog entry stored
	SyncedAt  time.Time
}

func (st syncState) encode() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "commit=%s\n", st.Commit)
	if !st.FetchTime.IsZero() {
		fmt.Fprintf(&b, "fetch_time=%s\n", st.FetchTime.UTC().Format(time.RFC3339Nano))
	}
	fmt.Fprintf(&b, "synced_at=%s\n", st.SyncedAt.UTC().Format(time.RFC3339))
	return b.Bytes()
}

func decodeState(data []byte) syncState {
	var st syncState
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "commit":
			st.Commit = v
		case "fetch_time":
			st.FetchTime, _ = time.Parse(time.RFC3339Nano, v)
		case "synced_at":
			st.SyncedAt, _ = time.Parse(time.RFC3339, v)
		}
	}
	return st
}

type syncResult struct {
	Commit   string
	UpToDate bool // HEAD was the commit already synced
	Deltas   int  // deltaLog entries applied
	Stored   int  // records PUT
	Missing  int  // listed in a delta but not at the commit
	Errors   int  // listed under "error" by cvelistV5
	Gap      bool // deltaLog didn't reach back to the last sync
	First    bool // no earlier sync, so only deltaLog's 30 days
}

func (r syncResult) String() string {
	if r.UpToDate {
		return "up to date at " + short(r.Commit)
	}
	s := fmt.Sprintf("synced %s: %d deltas, %d records stored, %d missing, %d upstream errors",
		short(r.Commit), r.Deltas, r.Stored, r.Missing, r.Errors)
	switch {
	case r.First:
		s += "; first sync, so only records changed in deltaLog's last 30 days"
	case r.Gap:
		s += "; deltaLog no longer reaches back to the last sync, so records changed in between are missing"
	}
	return s
}

func short(sha string) string { return sha[:min(len(sha), 12)] }

// sync brings the bucket up to cvelistV5's HEAD.
func (s *syncer) sync(ctx context.Context) (syncResult, error) {
	resp, err := s.s3.get(ctx, stateKey)
	if err != nil {
		return syncResult{}, err
	}
	var st syncState
	stateETag := ""
	if resp.status == http.StatusOK {
		st, stateETag = decodeState(resp.body), resp.etag
	}

	head, err := s.headCommit(ctx)
	if err != nil {
		return syncResult{}, err
	}
	res := syncResult{Commit: head, First: st.Commit == ""}
	if head == st.Commit {
		res.UpToDate = true
		// The view is normally written with each sync, but one seeded
		// bucket, or an older cve-sync's, has none until HEAD moves.
		return res, s.ensureView(ctx, head)
	}

	recent := newRecentChanges(s.viewSize)
	deltas, complete, err := s.deltasSince(ctx, head, st.FetchTime, recent)
	if err != nil {
		return res, err
	}
	res.Deltas, res.Gap = len(deltas), !complete

	// A record changed in several deltas is fetched once, at head.
	paths := map[string]bool{}
	next := st
	for _, d := range deltas {
		if t, _ := time.Parse(time.RFC3339Nano, d.FetchTime); t.After(next.FetchTime) {
			next.FetchTime = t
		}
		res.Errors += len(d.Error)
		for _, c := range append(d.New, d.Updated...) {
			p, ok := recordPath(c)
			if !ok {
				return res, fmt.Errorf("deltaLog.json: %s has no usable path (%q)", c.CVEID, c.GitHubLink)
			}
			paths[p] = true
		}
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	stored, missing, err := s.storeAll(ctx, head, sorted)
	res.Stored, res.Missing = stored, missing
	if err != nil {
		// The state isn't moved, so the next run repeats these deltas.
		return res, err
	}
	// The view is written before the state too, so a failed write is
	// retried by the next run.
	if err := s.writeView(ctx, head, recent); err != nil {
		return res, err
	}

	next.Commit, next.SyncedAt = head, s.now()
	cond, value := "If-None-Match", "*"
	if stateETag != "" {
		cond, value = "If-Match", stateETag
	}
	put, err := s.s3.put(ctx, stateKey, "text/plain; charset=utf-8", next.encode(), cond, value)
	if err != nil {
		return res, err
	}
	if put.status == http.StatusPreconditionFailed {
		return res, fmt.Errorf("%s changed during the sync; another cve-sync is running", stateKey)
	}
	return res, nil
}

// storeAll fetches each record at commit and PUTs it at the same path.
// PUTs are unconditional: a record listed again is simply replaced with
// its version at commit, which is the newest.
func (s *syncer) storeAll(ctx context.Context, commit string, paths []string) (stored, missing int, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	work := make(chan string)
	for range min(s.parallel, max(len(paths), 1)) {
		wg.Go(func() {
			for p := range work {
				ok, err := s.storeRecord(ctx, commit, p)
				mu.Lock()
				switch {
				case err != nil:
					if firstErr == nil {
						firstErr = err
						cancel()
					}
				case ok:
					stored++
				default:
					missing++
					s.log.Printf("%s is in deltaLog.json but not at %s; skipped", p, short(commit))
				}
				mu.Unlock()
			}
		})
	}
feed:
	for _, p := range paths {
		select {
		case work <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return stored, missing, firstErr
}

func (s *syncer) storeRecord(ctx context.Context, commit, path string) (bool, error) {
	data, err := s.fetchRecord(ctx, commit, path)
	if err != nil || data == nil {
		return false, err
	}
	resp, err := s.s3.put(ctx, path, "application/json", data, "", "")
	if err != nil {
		return false, err
	}
	return resp.status == http.StatusOK, nil
}

var (
	pathRE  = regexp.MustCompile(`^cves/[0-9]{4}/[0-9]+xxx/CVE-[0-9]{4}-[0-9]{4,}\.json$`)
	cveIDRE = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,})$`)
)

// recordPath is a record's path in the repository, which is also its key:
// cves/2026/120xxx/CVE-2026-120339.json. It's taken from githubLink, else
// derived from the CVE ID, and checked, so nothing from deltaLog.json can
// write elsewhere in the bucket.
func recordPath(c change) (string, bool) {
	if i := strings.Index(c.GitHubLink, "/cves/"); i >= 0 {
		if p := c.GitHubLink[i+1:]; pathRE.MatchString(p) {
			return p, true
		}
	}
	m := cveIDRE.FindStringSubmatch(c.CVEID)
	if m == nil {
		return "", false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("cves/%s/%dxxx/%s.json", m[1], n/1000, c.CVEID), true
}
