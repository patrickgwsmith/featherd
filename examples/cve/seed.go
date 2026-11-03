package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"sync"
	"time"
)

// seedResult is what a seed stored.
type seedResult struct {
	Stored    int       // records PUT
	Skipped   int       // zip entries that aren't records, e.g. deltaLog.json
	FetchTime time.Time // where the delta sync picks up
}

func (r seedResult) String() string {
	return fmt.Sprintf("seeded %d records (%d other files skipped); the next sync applies deltas after %s",
		r.Stored, r.Skipped, r.FetchTime.UTC().Format(time.RFC3339))
}

// seedMargin is how far before the newest record's dateUpdated the delta
// sync starts. dateUpdated comes from CVE Services and deltaLog's fetchTime
// from cvelistV5's bot, so the margin covers any skew between their clocks.
// Overlap only means a few records are fetched again.
const seedMargin = time.Hour

// seed stores every record in one of cvelistV5's daily
// *_all_CVEs_at_midnight.zip release assets, then writes mut/sync so the
// delta sync carries on from the snapshot. The asset is a zip holding
// cves.zip, which holds cves/…/CVE-….json; a plain cves.zip works too.
//
// It refuses to run if mut/sync exists: the zip's records are older than
// the ones a sync stored, so seeding over a synced bucket would roll them
// back. Delete mut/sync first to seed again; the next sync then catches up
// from the snapshot.
func (s *syncer) seed(ctx context.Context, zipPath string) (seedResult, error) {
	resp, err := s.s3.get(ctx, stateKey)
	if err != nil {
		return seedResult{}, err
	}
	if resp.status == http.StatusOK {
		return seedResult{}, fmt.Errorf("%s exists, so the bucket has been synced; delete it to seed again", stateKey)
	}

	zr, closeZip, err := openRecordsZip(zipPath)
	if err != nil {
		return seedResult{}, err
	}
	defer closeZip()

	var res seedResult
	var files []*zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !pathRE.MatchString(f.Name) {
			res.Skipped++
			continue
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return res, fmt.Errorf("%s: no cves/…/CVE-….json records", zipPath)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	vc := newVendorChanges()
	newest, err := s.storeZipped(ctx, files, vc)
	if err != nil {
		// No state is written, so the seed can simply be run again.
		return res, err
	}
	// Every record was just stored, so the vendor indexes are built from
	// them, not backfilled; the pages they cite are fetched by the views.
	if _, err := s.writeVendorIndexes(ctx, "", vc); err != nil {
		return res, err
	}
	res.Stored = len(files)
	res.FetchTime = newest.Add(-seedMargin)

	st := syncState{Commit: "seed", FetchTime: res.FetchTime, SyncedAt: s.now()}
	put, err := s.s3.put(ctx, stateKey, "text/plain; charset=utf-8", st.encode(), "If-None-Match", "*")
	if err != nil {
		return res, err
	}
	if put.status == http.StatusPreconditionFailed {
		return res, fmt.Errorf("%s was written during the seed; a cve-sync ran at the same time, so delete %s and seed again", stateKey, stateKey)
	}
	return res, nil
}

// openRecordsZip opens the zip at name and, if it holds cves.zip rather
// than records, unpacks that to a temporary file and opens it instead.
func openRecordsZip(name string) (*zip.Reader, func(), error) {
	outer, err := zip.OpenReader(name)
	if err != nil {
		return nil, nil, err
	}
	var inner *zip.File
	for _, f := range outer.File {
		if path.Base(f.Name) == "cves.zip" {
			inner = f
			break
		}
	}
	if inner == nil {
		return &outer.Reader, func() { outer.Close() }, nil
	}
	defer outer.Close()

	tmp, err := os.CreateTemp("", "cves-*.zip")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { tmp.Close(); os.Remove(tmp.Name()) }
	rc, err := inner.Open()
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	n, err := io.Copy(tmp, rc)
	rc.Close()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("%s: unpacking cves.zip: %w", name, err)
	}
	zr, err := zip.NewReader(tmp, n)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("%s: cves.zip: %w", name, err)
	}
	return zr, cleanup, nil
}

// storeZipped PUTs each record, -parallel at a time, and returns the
// newest cveMetadata.dateUpdated among them.
func (s *syncer) storeZipped(ctx context.Context, files []*zip.File, vc *vendorChanges) (time.Time, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
		newest   time.Time
		done     int
		wg       sync.WaitGroup
	)
	work := make(chan *zip.File)
	for range min(s.parallel, len(files)) {
		wg.Go(func() {
			for f := range work {
				updated, err := s.storeZippedRecord(ctx, f, vc)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel()
					}
				} else {
					if updated.After(newest) {
						newest = updated
					}
					done++
					if done%25000 == 0 {
						s.log.Printf("seed: %d of %d records stored", done, len(files))
					}
				}
				mu.Unlock()
			}
		})
	}
feed:
	for _, f := range files {
		select {
		case work <- f:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	if firstErr == nil && newest.IsZero() {
		firstErr = errors.New("no record has cveMetadata.dateUpdated, so there's no time to sync deltas from")
	}
	return newest, firstErr
}

func (s *syncer) storeZippedRecord(ctx context.Context, f *zip.File, vc *vendorChanges) (time.Time, error) {
	if f.UncompressedSize64 > maxRecordBytes {
		return time.Time{}, fmt.Errorf("%s: over %d bytes", f.Name, maxRecordBytes)
	}
	rc, err := f.Open()
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", f.Name, err)
	}
	data, err := io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
	rc.Close()
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", f.Name, err)
	}
	if len(data) > maxRecordBytes {
		return time.Time{}, fmt.Errorf("%s: over %d bytes", f.Name, maxRecordBytes)
	}
	var rec struct {
		CVEMetadata struct {
			DateUpdated string `json:"dateUpdated"`
		} `json:"cveMetadata"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return time.Time{}, fmt.Errorf("%s: not JSON: %w", f.Name, err)
	}
	resp, err := s.s3.put(ctx, f.Name, "application/json", data, "", "")
	if err != nil {
		return time.Time{}, err
	}
	if resp.status != http.StatusOK {
		return time.Time{}, fmt.Errorf("PUT %s: HTTP %d", f.Name, resp.status)
	}
	vc.add(f.Name, data)
	return parseCVETime(rec.CVEMetadata.DateUpdated), nil
}

// parseCVETime reads a CVE record timestamp. They're RFC 3339, but often
// without a zone ("2024-03-29T15:15:29.000Z" or "2024-03-29T15:15:29"),
// which means UTC. A time it can't read is zero, so it doesn't count.
func parseCVETime(v string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}
