package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaimOnce checks the storage pattern behind examples/claim-once: the
// first If-None-Match: * PUT of a (subject, window) key claims it, a second
// one in the same window gets 412, marking it used with a stale ETag fails,
// and the date-prefixed range delete removes only the earlier days.
func TestClaimOnce(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	mustCreateBucket(t, handler, "claims")
	put := func(key, body string, header, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/claims/"+key, strings.NewReader(body))
		req.Header.Set(header, value)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}

	const key = "pending/20261013T1415/" + "e2724f22416548a2da6868588f1a4eb10156c9e161b61eb784203c4d4525d049"
	first := put(key, `{"used":false}`, "If-None-Match", "*")
	if first.Code != http.StatusOK {
		t.Fatalf("first claim = %d %q", first.Code, first.Body.String())
	}
	if resp := put(key, `{"used":false}`, "If-None-Match", "*"); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("second claim = %d %q", resp.Code, resp.Body.String())
	}
	if resp := serve(handler, http.MethodGet, "/claims/"+key, nil); resp.Body.String() != `{"used":false}` {
		t.Fatalf("second claim overwrote the first: %q", resp.Body.String())
	}

	used := put(key, `{"used":true}`, "If-Match", first.Header().Get("ETag"))
	if used.Code != http.StatusOK {
		t.Fatalf("mark used = %d %q", used.Code, used.Body.String())
	}
	if resp := put(key, `{"used":true}`, "If-Match", first.Header().Get("ETag")); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("mark used with stale ETag = %d %q", resp.Code, resp.Body.String())
	}

	cli := sqliteCLI(t)
	for _, k := range []string{"pending/20261011T2345/a", "pending/20261012T0000/b", "pending0", "pendinf", "subscribers/a@example.com"} {
		if resp := put(k, "x", "Content-Type", "application/json"); resp.Code != http.StatusOK {
			t.Fatalf("put %s = %d %q", k, resp.Code, resp.Body.String())
		}
	}
	runSQLite(t, cli, filepath.Join(path, "claims.sqlite3"), ".timeout 5000",
		"DELETE FROM sqlar WHERE name >= 'pending/' AND name < 'pending/20261012'")
	keys := listKeys(t, handler, "claims")
	for _, k := range []string{"pending/20261012T0000/b", key, "pending0", "pendinf", "subscribers/a@example.com"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("sweep deleted %s", k)
		}
	}
	if len(keys) != 5 {
		t.Fatalf("listed %v after sweep", keys)
	}
	if keys[key] != used.Header().Get("ETag") {
		t.Fatalf("ETag after sweep = %s, want %s", keys[key], used.Header().Get("ETag"))
	}
}

// TestRunOnce checks the pattern behind examples/claim-once/run-once.sh:
// daily and hourly runs of a job get their own keys and are claimed once
// each, of two workers taking over the same stale claim only one wins, and
// the sweep deletes a job's earlier days, daily and hourly alike, without
// touching other jobs.
func TestRunOnce(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	mustCreateBucket(t, handler, "jobs")
	put := func(key, body string, header, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/jobs/"+key, strings.NewReader(body))
		req.Header.Set(header, value)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}

	for _, key := range []string{"runs/backup/20261013", "runs/backup/20261013T14", "runs/backup/20261013T15"} {
		if resp := put(key, `{"status":"running"}`, "If-None-Match", "*"); resp.Code != http.StatusOK {
			t.Fatalf("first claim of %s = %d %q", key, resp.Code, resp.Body.String())
		}
		if resp := put(key, `{"status":"running"}`, "If-None-Match", "*"); resp.Code != http.StatusPreconditionFailed {
			t.Fatalf("second claim of %s = %d %q", key, resp.Code, resp.Body.String())
		}
	}

	// Two workers find the same crashed claim; both try to take it over with
	// its ETag, and only the first succeeds.
	stale := serve(handler, http.MethodGet, "/jobs/runs/backup/20261013", nil).Header().Get("ETag")
	if resp := put("runs/backup/20261013", `{"status":"running","attempt":2}`, "If-Match", stale); resp.Code != http.StatusOK {
		t.Fatalf("first take-over = %d %q", resp.Code, resp.Body.String())
	}
	if resp := put("runs/backup/20261013", `{"status":"running","attempt":2}`, "If-Match", stale); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("second take-over = %d %q", resp.Code, resp.Body.String())
	}

	cli := sqliteCLI(t)
	for _, k := range []string{"runs/backup/20261011", "runs/backup/20261012T23", "runs/backup-db/20261011", "runs/backup0"} {
		if resp := put(k, "x", "Content-Type", "application/json"); resp.Code != http.StatusOK {
			t.Fatalf("put %s = %d %q", k, resp.Code, resp.Body.String())
		}
	}
	runSQLite(t, cli, filepath.Join(path, "jobs.sqlite3"), ".timeout 5000",
		"DELETE FROM sqlar WHERE name >= 'runs/backup/' AND name < 'runs/backup/20261013'")
	keys := listKeys(t, handler, "jobs")
	for _, k := range []string{"runs/backup/20261013", "runs/backup/20261013T14", "runs/backup/20261013T15", "runs/backup-db/20261011", "runs/backup0"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("sweep deleted %s", k)
		}
	}
	if len(keys) != 5 {
		t.Fatalf("listed %v after sweep", keys)
	}
}
