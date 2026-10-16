package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestAtomicPublish checks the pattern behind
// examples/atomic-publish/publish.sh: of two publishers that read the same
// pointer only one moves it, a rollback that read the pointer before gc
// raised the floor gets 412, and gc's range deletes remove only releases
// below the floor.
func TestAtomicPublish(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	mustCreateBucket(t, handler, "site")
	put := func(key, body string, header, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/site/"+key, strings.NewReader(body))
		req.Header.Set(header, value)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}
	const (
		r1 = "20261013T140000Z-00000001"
		r2 = "20261013T141500Z-00000002"
		r3 = "20261013T143000Z-00000003"
	)
	for _, r := range []string{r1, r2, r3} {
		for _, k := range []string{"releases/" + r + "/index.html", "releases/" + r + "/css/site.css", "manifests/" + r} {
			if resp := put(k, r, "If-None-Match", "*"); resp.Code != http.StatusOK {
				t.Fatalf("put %s = %d %q", k, resp.Code, resp.Body.String())
			}
		}
	}

	if resp := put("current", `{"release":"`+r1+`"}`, "If-None-Match", "*"); resp.Code != http.StatusOK {
		t.Fatalf("first publish = %d %q", resp.Code, resp.Body.String())
	}
	// Two publishers read r1 as current; only the first moves the pointer.
	seen := serve(handler, http.MethodGet, "/site/current", nil).Header().Get("ETag")
	won := put("current", `{"release":"`+r3+`","previous":"`+r1+`"}`, "If-Match", seen)
	if won.Code != http.StatusOK {
		t.Fatalf("first publisher = %d %q", won.Code, won.Body.String())
	}
	if resp := put("current", `{"release":"`+r2+`","previous":"`+r1+`"}`, "If-Match", seen); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("second publisher = %d %q", resp.Code, resp.Body.String())
	}

	// A rollback to r1 reads the pointer, then gc raises the floor to r2
	// with the same ETag; the rollback's write must fail.
	seen = won.Header().Get("ETag")
	if resp := put("current", `{"release":"`+r3+`","previous":"`+r1+`","floor":"`+r2+`"}`, "If-Match", seen); resp.Code != http.StatusOK {
		t.Fatalf("raise floor = %d %q", resp.Code, resp.Body.String())
	}
	if resp := put("current", `{"release":"`+r1+`","previous":"`+r3+`"}`, "If-Match", seen); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("rollback after gc = %d %q", resp.Code, resp.Body.String())
	}

	cli := sqliteCLI(t)
	db := filepath.Join(path, "site.sqlite3")
	runSQLite(t, cli, db, ".timeout 5000", "BEGIN;"+
		"DELETE FROM sqlar WHERE name >= 'manifests/' AND name < 'manifests/"+r2+"';"+
		"DELETE FROM sqlar WHERE name >= 'releases/' AND name < 'releases/"+r2+"';"+
		"COMMIT;")
	keys := listKeys(t, handler, "site")
	for _, r := range []string{r2, r3} {
		for _, k := range []string{"releases/" + r + "/index.html", "releases/" + r + "/css/site.css", "manifests/" + r} {
			if _, ok := keys[k]; !ok {
				t.Errorf("gc deleted %s", k)
			}
		}
	}
	if _, ok := keys["current"]; !ok {
		t.Error("gc deleted current")
	}
	if len(keys) != 7 {
		t.Fatalf("listed %v after gc", keys)
	}
	if n := runSQLite(t, cli, db, "SELECT count(*) FROM content_meta"); strings.TrimSpace(n) != "7" {
		t.Fatalf("content_meta has %s rows after gc, want 7", n)
	}
}
