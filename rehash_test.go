package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkMeta fails unless content_meta holds exactly want, key -> the body's
// digest and the content type.
func checkMeta(t *testing.T, path string, want map[string][2]string) {
	t.Helper()
	store := openSQLARStore(t, path)
	defer store.Close()
	n, _, err := store.queryInt(`SELECT count(*) FROM content_meta`, nil)
	if err != nil || n != int64(len(want)) {
		t.Fatalf("content_meta has %d rows, %v; want %d", n, err, len(want))
	}
	for key, w := range want {
		sum := sha256.Sum256([]byte(w[0]))
		n, _, err := store.queryInt(`SELECT count(*) FROM content_meta WHERE name = :k AND sha256 = :s AND content_type = :ct`,
			params{"k": key, "s": sum[:], "ct": w[1]})
		if err != nil || n != 1 {
			t.Errorf("%s: no content_meta row with the digest of %q and %q (%v)", key, w[0], w[1], err)
		}
	}
}

func TestRehashFixesAndAddsDigests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	for key, body := range map[string]string{"good.txt": "good", "bad.json": `{"bad":true}`} {
		if _, err := store.Put("b", key, []byte(body), "application/x-test", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	compressed := []byte(strings.Repeat("compressible ", 100))
	wrong := sha256.Sum256([]byte("something else"))
	err := store.execParams(`UPDATE content_meta SET sha256 = :wrong WHERE name = 'bad.json'`, params{"wrong": wrong[:]})
	if err == nil {
		// Written directly, as a tool that bypasses featherd would; the
		// triggers leave these without metadata.
		err = store.execParams(`INSERT INTO sqlar(name, mode, mtime, sz, data) VALUES
	('raw.html', 33188, 1700000000, 4, 'html'),
	('dir', 16877, 1700000000, 0, NULL),
	('z/packed.bin', 33188, 1700000000, :sz, :data),
	('broken.txt', 33188, 1700000000, 99, x'00010203')`,
			params{"sz": int64(len(compressed)), "data": zlibCompress(t, compressed)})
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	var out, errOut bytes.Buffer
	if code := runRehash([]string{"--dry-run", path}, &out, &errOut); code != 1 {
		t.Fatalf("dry run exit = %d, want 1 for the broken entry; stderr %s", code, errOut.String())
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("dry run modified the database")
	}
	for _, want := range []string{
		"bad.json: digest would be corrected from " + etagOf(wrong[:]),
		`key "broken.txt"`,
		"5 entries (", "1 correct, 2 would be added, 1 would be corrected, 1 unreadable",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := runRehash([]string{path}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1; output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "1 correct, 2 added, 1 corrected, 1 unreadable") {
		t.Fatalf("output:\n%s", out.String())
	}
	checkMeta(t, path, map[string][2]string{
		"good.txt":     {"good", "application/x-test"},
		"bad.json":     {`{"bad":true}`, "application/x-test"},
		"raw.html":     {"html", "text/html; charset=utf-8"},
		"z/packed.bin": {string(compressed), "application/octet-stream"},
	})

	// Served ETags now come from the fixed rows.
	store = openSQLARStore(t, path)
	if obj, err := store.Head("b", "bad.json"); err != nil || obj.ETag != quoteETag([]byte(`{"bad":true}`)) {
		t.Fatalf("Head(bad.json) = %q, %v", obj.ETag, err)
	}
	store.Close()

	out.Reset()
	runRehash([]string{path}, &out, &errOut)
	if !strings.Contains(out.String(), "4 correct, 0 added, 0 corrected, 1 unreadable") {
		t.Fatalf("second run output:\n%s", out.String())
	}
}

// TestRehashRebuildsUntrustedMeta covers an archive whose triggers are gone,
// e.g. recreated by `sqlite3 -A -c`, so its content_meta can't be trusted.
func TestRehashRebuildsUntrustedMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	if _, err := store.Put("b", "a.txt", []byte("a"), "text/plain", nil, false); err != nil {
		t.Fatal(err)
	}
	if err := store.exec(`DROP TRIGGER sqlar_update_drops_meta; UPDATE sqlar SET data = 'changed', sz = 7`); err != nil {
		t.Fatal(err)
	}
	store.Close()

	var out, errOut bytes.Buffer
	if code := runRehash([]string{path}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "content_meta missing or untrusted, rebuilt") ||
		!strings.Contains(out.String(), "0 correct, 1 added") {
		t.Fatalf("output:\n%s", out.String())
	}
	checkMeta(t, path, map[string][2]string{"a.txt": {"changed", "text/plain; charset=utf-8"}})
	store = openSQLARStore(t, path)
	if err := store.inspectLocked(); err != nil || !store.metaTrusted {
		t.Fatalf("triggers not restored: trusted=%v err=%v", store.metaTrusted, err)
	}
}

func TestRehashSpansBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	if _, err := store.Put("b", "seed", nil, "", nil, false); err != nil {
		t.Fatal(err)
	}
	n := rehashBatchEntries*2 + 7
	if err := store.execParams(`WITH RECURSIVE i(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM i WHERE n < :n)
INSERT INTO sqlar(name, mode, mtime, sz, data) SELECT printf('k%05d', n), 33188, 0, length(n), CAST(n AS TEXT) FROM i`,
		params{"n": int64(n)}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	var out, errOut bytes.Buffer
	if code := runRehash([]string{path}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if want := fmt.Sprintf("%d entries", n+1); !strings.Contains(out.String(), want) {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	store = openSQLARStore(t, path)
	if got, _, err := store.queryInt(`SELECT count(*) FROM content_meta`, nil); err != nil || got != int64(n+1) {
		t.Fatalf("content_meta has %d rows, %v; want %d", got, err, n+1)
	}
}

func TestRehashLeavesNonArchiveAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sqlite3")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runRehash([]string{path}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if fi, _ := os.Stat(path); fi.Size() != 0 {
		t.Fatal("rehash wrote to a file with no sqlar table")
	}
	if code := runRehash([]string{filepath.Join(t.TempDir(), "missing.sqlite3")}, &out, &errOut); code != 1 {
		t.Fatalf("missing file exit = %d, want 1", code)
	}
}

func TestParseRehashArgs(t *testing.T) {
	got, err := parseRehashArgs([]string{"-nv", "a.sqlite3", "--", "-b.sqlite3"})
	if err != nil || !got.dryRun || !got.verbose || fmt.Sprint(got.files) != "[a.sqlite3 -b.sqlite3]" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for args, want := range map[string]string{
		"":                "no database files given",
		"-x a":            "unknown option -x",
		"--force a":       "unknown option --force",
		"--dry-run=yes a": "does not take a value",
	} {
		_, err := parseRehashArgs(strings.Fields(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseRehashArgs(%q) = %v, want %q", args, err, want)
		}
	}
}
