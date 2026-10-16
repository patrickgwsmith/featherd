package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestWebhookOnce checks the pattern behind
// examples/webhook-once/webhook-once.sh: a redelivered event finds its first
// delivery's claim, of two deliveries retrying the same failed event only one
// wins, and the sweep deletes a provider's events by mtime without touching
// newer events or other providers.
func TestWebhookOnce(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	mustCreateBucket(t, handler, "webhooks")
	put := func(key, body string, header, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/webhooks/"+key, strings.NewReader(body))
		req.Header.Set(header, value)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}

	const key = "events/stripe/evt_1NG8Du2eZvKYlo2CUI79vXWy"
	if resp := put(key, `{"status":"processing"}`, "If-None-Match", "*"); resp.Code != http.StatusOK {
		t.Fatalf("first delivery = %d %q", resp.Code, resp.Body.String())
	}
	if resp := put(key, `{"status":"processing"}`, "If-None-Match", "*"); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("redelivery = %d %q", resp.Code, resp.Body.String())
	}

	failed := put(key, `{"status":"failed"}`, "If-Match", serve(handler, http.MethodGet, "/webhooks/"+key, nil).Header().Get("ETag"))
	if failed.Code != http.StatusOK {
		t.Fatalf("record failure = %d %q", failed.Code, failed.Body.String())
	}
	// Two retries find the failed record; both try to take it over with its
	// ETag, and only the first succeeds.
	seen := failed.Header().Get("ETag")
	if resp := put(key, `{"status":"processing","attempt":2}`, "If-Match", seen); resp.Code != http.StatusOK {
		t.Fatalf("first retry = %d %q", resp.Code, resp.Body.String())
	}
	if resp := put(key, `{"status":"processing","attempt":2}`, "If-Match", seen); resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("second retry = %d %q", resp.Code, resp.Body.String())
	}

	cli := sqliteCLI(t)
	for _, k := range []string{"events/stripe/evt_old", "events/stripe-test/evt_old", "events/stripe0"} {
		if resp := put(k, "x", "Content-Type", "application/json"); resp.Code != http.StatusOK {
			t.Fatalf("put %s = %d %q", k, resp.Code, resp.Body.String())
		}
	}
	db := filepath.Join(path, "webhooks.sqlite3")
	runSQLite(t, cli, db, ".timeout 5000", "UPDATE sqlar SET mtime = 1000 WHERE name LIKE '%evt_old' OR name = 'events/stripe0'")
	runSQLite(t, cli, db, ".timeout 5000",
		"DELETE FROM sqlar WHERE name >= 'events/stripe/' AND name < 'events/stripe0' AND mtime < 2000")
	keys := listKeys(t, handler, "webhooks")
	for _, k := range []string{key, "events/stripe-test/evt_old", "events/stripe0"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("sweep deleted %s", k)
		}
	}
	if len(keys) != 3 {
		t.Fatalf("listed %v after sweep", keys)
	}
}
