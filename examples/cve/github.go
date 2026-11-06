package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// headCommit returns the commit HEAD points to, read from git's smart HTTP
// ref advertisement, as collected-press does. It's one small request, and
// the commit then pins every raw.githubusercontent.com read to one
// snapshot of the repository.
// https://git-scm.com/docs/http-protocol#_smart_clients
func (s *syncer) headCommit(ctx context.Context) (string, error) {
	return s.refsHead(ctx, s.github, s.refsURL)
}

// refsHead reads HEAD's commit from a repository's info/refs URL.
func (s *syncer) refsHead(ctx context.Context, client *http.Client, refsURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, refsURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("info/refs: HTTP %d", resp.StatusCode)
	}
	// HEAD is the first ref, so only the start of the advertisement is read.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	return headFromRefs(data)
}

// headFromRefs finds HEAD in a pkt-line ref advertisement: each line is
// four hex digits of length (including themselves) and the payload, with
// "0000" as a flush. The first ref line carries capabilities after a NUL.
func headFromRefs(data []byte) (string, error) {
	for len(data) >= 4 {
		n, err := strconv.ParseUint(string(data[:4]), 16, 16)
		if err != nil {
			return "", fmt.Errorf("info/refs: bad pkt-line length %q", data[:4])
		}
		if n < 4 { // flush or delimiter
			data = data[4:]
			continue
		}
		if int(n) > len(data) {
			break
		}
		line := strings.TrimRight(string(data[4:n]), "\n")
		data = data[n:]
		if strings.HasPrefix(line, "#") {
			continue
		}
		line, _, _ = strings.Cut(line, "\x00")
		oid, ref, _ := strings.Cut(line, " ")
		if ref == "HEAD" && isHexSHA(oid) {
			return oid, nil
		}
	}
	return "", errors.New("info/refs: no HEAD")
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// delta is one hourly entry of cves/deltaLog.json.
type delta struct {
	FetchTime string   `json:"fetchTime"`
	New       []change `json:"new"`
	Updated   []change `json:"updated"`
	Error     []change `json:"error"`
}

type change struct {
	CVEID       string `json:"cveId"`
	GitHubLink  string `json:"githubLink"`
	DateUpdated string `json:"dateUpdated"`
}

// deltasSince reads cves/deltaLog.json at commit, newest entry first, and
// returns the entries fetched after since (all of them for the zero time).
// It stops reading at the first entry at or before since, so a regular run
// downloads only the head of the 35 MB file. complete reports that it
// reached such an entry: if not, the log no longer goes back to since, and
// records changed in between are missing.
func (s *syncer) deltasSince(ctx context.Context, commit string, since time.Time) (deltas []delta, complete bool, err error) {
	err = s.scanDeltaLog(ctx, commit, func(e delta, t time.Time) bool {
		if since.IsZero() || t.After(since) {
			deltas = append(deltas, e)
			return true
		}
		complete = true
		return false
	})
	if err != nil {
		return nil, false, err
	}
	return deltas, complete || since.IsZero(), nil
}

// scanDeltaLog streams cves/deltaLog.json at commit, newest entry first,
// to visit until it returns false, then hangs up.
func (s *syncer) scanDeltaLog(ctx context.Context, commit string, visit func(e delta, fetchTime time.Time) bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.rawBase+commit+"/cves/deltaLog.json", nil)
	if err != nil {
		return err
	}
	resp, err := s.github.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deltaLog.json: HTTP %d", resp.StatusCode)
	}
	d := json.NewDecoder(resp.Body)
	if tok, err := d.Token(); err != nil || tok != json.Delim('[') {
		return fmt.Errorf("deltaLog.json: not an array: %v", err)
	}
	for d.More() {
		var e delta
		if err := d.Decode(&e); err != nil {
			return fmt.Errorf("deltaLog.json: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, e.FetchTime)
		if err != nil {
			return fmt.Errorf("deltaLog.json: fetchTime %q: %w", e.FetchTime, err)
		}
		if !visit(e, t) {
			return nil
		}
	}
	return nil
}

// fetchRecord returns the record at path in commit, or nil if it isn't
// there.
func (s *syncer) fetchRecord(ctx context.Context, commit, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.rawBase+commit+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.github.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	if len(data) > maxRecordBytes {
		return nil, fmt.Errorf("GET %s: over %d bytes", path, maxRecordBytes)
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("GET %s: not JSON", path)
	}
	return data, nil
}

// maxRecordBytes is well above the largest CVE record (a few MB), and
// below featherd's default 20 MiB cap.
const maxRecordBytes = 16 << 20
