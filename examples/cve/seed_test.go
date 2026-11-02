package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dated(id, title, updated string) string {
	return fmt.Sprintf(`{"dataType":"CVE_RECORD","cveMetadata":{"cveId":%q,"dateUpdated":%q},"containers":{"cna":{"title":%q}}}`, id, updated, title)
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// midnightZip is laid out like the release asset: a zip holding cves.zip.
func midnightZip(t *testing.T, files map[string]string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "2026-11-02_all_CVEs_at_midnight.zip.zip")
	if err := os.WriteFile(name, zipOf(t, map[string]string{"cves.zip": string(zipOf(t, files))}), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSeed(t *testing.T) {
	env := newTestEnv(t)
	a, b := "cves/2026/0xxx/CVE-2026-0001.json", "cves/2024/3xxx/CVE-2024-3094.json"
	zipName := midnightZip(t, map[string]string{
		a:                    dated("CVE-2026-0001", "a v1", "2026-11-01T23:40:00.000Z"),
		b:                    dated("CVE-2024-3094", "xz", "2024-12-01T10:00:00"),
		"cves/deltaLog.json": "[]",
		"cves/delta.json":    "{}",
		"../escape.json":     "{}",
	})

	res, err := env.s.seed(context.Background(), zipName)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stored != 2 || res.Skipped != 3 {
		t.Fatalf("seed: %+v", res)
	}
	if body, _, ct, _ := env.object(t, b); body != dated("CVE-2024-3094", "xz", "2024-12-01T10:00:00") || ct != "application/json" {
		t.Fatalf("b: %q %q", body, ct)
	}
	st := env.state(t)
	if st.Commit != "seed" || st.FetchTime.Format(time.RFC3339) != "2026-11-01T22:40:00Z" {
		t.Fatalf("state: %+v", st)
	}

	// A synced bucket isn't seeded over.
	if _, err := env.s.seed(context.Background(), zipName); err == nil || !strings.Contains(err.Error(), "delete it") {
		t.Fatalf("second seed: %v", err)
	}

	// The delta sync picks up from the snapshot: deltas before fetch_time
	// are skipped, later ones applied.
	env.gh.commit(sha1, map[string]string{
		"cves/deltaLog.json": deltaLog(
			delta{FetchTime: "2026-11-02T00:10:00.000Z", Updated: []change{ch("CVE-2026-0001")}},
			delta{FetchTime: "2026-11-01T20:00:00.000Z", New: []change{ch("CVE-2024-3094")}},
		),
		a: dated("CVE-2026-0001", "a v2", "2026-11-02T00:05:00.000Z"),
		b: dated("CVE-2024-3094", "xz", "2024-12-01T10:00:00"),
	})
	if res := env.sync(t); res.Deltas != 1 || res.Stored != 1 || res.First || res.Gap {
		t.Fatalf("sync after seed: %+v", res)
	}
	if body, _, _, _ := env.object(t, a); !strings.Contains(body, "a v2") {
		t.Fatalf("a: %q", body)
	}
	if n := env.gh.fetched[b]; n != 0 {
		t.Fatalf("b fetched %d times", n)
	}
}

func TestSeedFailure(t *testing.T) {
	env := newTestEnv(t)
	// A plain cves.zip works too; a record that isn't JSON stops the seed
	// before the state is written.
	name := filepath.Join(t.TempDir(), "cves.zip")
	os.WriteFile(name, zipOf(t, map[string]string{
		"cves/2026/0xxx/CVE-2026-0001.json": dated("CVE-2026-0001", "a", "2026-11-01T23:40:00Z"),
		"cves/2026/0xxx/CVE-2026-0002.json": "not json",
	}), 0o644)
	if _, err := env.s.seed(context.Background(), name); err == nil {
		t.Fatal("seed with a broken record succeeded")
	}
	if _, _, _, status := env.object(t, stateKey); status != http.StatusNotFound {
		t.Fatalf("state written after a failed seed: %d", status)
	}
}
