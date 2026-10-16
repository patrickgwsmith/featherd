package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestOAuthClient checks the pattern behind
// examples/oauth-client/github-login.sh: a state is consumed by a GET and an
// If-Match DELETE, so of two callbacks with the same state only one succeeds;
// of two first sign-ins of the same GitHub user only one links a local user;
// and the sweep deletes old state records without touching users.
func TestOAuthClient(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	mustCreateBucket(t, handler, "app")
	send := func(method, key, body string, header, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/app/"+key, strings.NewReader(body))
		req.Header.Set(header, value)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}

	const state = "oauth-client/github.com/state/acc57d35e7f81926da42cdf1655cb31775e256c993c3f841d2cf428e09e09df7"
	if resp := send(http.MethodPut, state, `{"code_verifier":"v"}`, "If-None-Match", "*"); resp.Code != http.StatusOK {
		t.Fatalf("start = %d %q", resp.Code, resp.Body.String())
	}
	// Two callbacks read the state, then both delete it If-Match its ETag.
	seen := serve(handler, http.MethodGet, "/app/"+state, nil).Header().Get("ETag")
	if resp := send(http.MethodDelete, state, "", "If-Match", seen); resp.Code != http.StatusNoContent {
		t.Fatalf("first callback = %d %q", resp.Code, resp.Body.String())
	}
	if resp := send(http.MethodDelete, state, "", "If-Match", seen); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("second callback = %d %q", resp.Code, resp.Body.String())
	}

	const user = "oauth-client/github.com/users/583231"
	first := send(http.MethodPut, user, `{"local_user":"users/a"}`, "If-None-Match", "*")
	if first.Code != http.StatusOK {
		t.Fatalf("first sign-in = %d %q", first.Code, first.Body.String())
	}
	if resp := send(http.MethodPut, user, `{"local_user":"users/b"}`, "If-None-Match", "*"); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("racing first sign-in = %d %q", resp.Code, resp.Body.String())
	}
	// A later sign-in updates the record If-Match what it read; one that
	// read an older version has to read it again.
	if resp := send(http.MethodPut, user, `{"local_user":"users/a","login":"octocat"}`, "If-Match", first.Header().Get("ETag")); resp.Code != http.StatusOK {
		t.Fatalf("update = %d %q", resp.Code, resp.Body.String())
	}
	if resp := send(http.MethodPut, user, `{"local_user":"users/a"}`, "If-Match", first.Header().Get("ETag")); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale update = %d %q", resp.Code, resp.Body.String())
	}

	cli := sqliteCLI(t)
	for _, k := range []string{"oauth-client/github.com/state/old", "oauth-client/github.com/state/new", "oauth-client/github.com/state0"} {
		if resp := send(http.MethodPut, k, "{}", "If-None-Match", "*"); resp.Code != http.StatusOK {
			t.Fatalf("put %s = %d %q", k, resp.Code, resp.Body.String())
		}
	}
	db := filepath.Join(path, "app.sqlite3")
	runSQLite(t, cli, db, ".timeout 5000", "UPDATE sqlar SET mtime = 1000 WHERE name LIKE '%/state/old' OR name = 'oauth-client/github.com/state0' OR name = '"+user+"'")
	runSQLite(t, cli, db, ".timeout 5000",
		"DELETE FROM sqlar WHERE name >= 'oauth-client/github.com/state/' AND name < 'oauth-client/github.com/state0' AND mtime < 2000")
	keys := listKeys(t, handler, "app")
	for _, k := range []string{user, "oauth-client/github.com/state/new", "oauth-client/github.com/state0"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("sweep deleted %s", k)
		}
	}
	if len(keys) != 3 {
		t.Fatalf("listed %v after sweep", keys)
	}
}
