package main

import (
	"bytes"
	"compress/zlib"
	"encoding/xml"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func openSQLARStore(t testing.TB, path string) *Store {
	t.Helper()
	store := openTestStoreAt(t, path)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSQLARReadsEntriesFromOtherTools writes archive rows the way `sqlite3 -A`
// does: REPLACE INTO sqlar, zlib-compressed data when that is smaller, and
// directory and symlink entries.
func TestSQLARReadsEntriesFromOtherTools(t *testing.T) {
	store := openSQLARStore(t, filepath.Join(t.TempDir(), "b.sqlite3"))
	put, err := store.Put("b", "a.txt", []byte("from featherd"), "text/plain", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	text := []byte(strings.Repeat("compressible ", 100))
	err = store.execParams(`REPLACE INTO sqlar(name, mode, mtime, sz, data) VALUES
	('a.txt', 33188, 1700000000, 3, 'new'),
	('dir', 16877, 1700000000, 0, NULL),
	('dir/z.txt', 33188, 1700000001, :sz, :data),
	('link', 41471, 1700000000, -1, 'a.txt')`, params{"sz": int64(len(text)), "data": zlibCompress(t, text)})
	if err != nil {
		t.Fatal(err)
	}

	// Rewriting a.txt dropped its metadata, so its ETag is the new data's.
	got, err := store.Get("b", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "new" || got.ETag != quoteETag([]byte("new")) || got.ETag == put.ETag ||
		got.ContentType != "application/octet-stream" || got.Mtime != 1700000000 {
		t.Fatalf("rewritten entry = %+v", got)
	}

	// Compressed entries are inflated, and HEAD agrees with GET.
	got, err = store.Get("b", "dir/z.txt")
	if err != nil || !bytes.Equal(got.Body, text) || got.Size != len(text) || got.ETag != quoteETag(text) {
		t.Fatalf("compressed entry = %d bytes, size %d, etag %s, err %v", len(got.Body), got.Size, got.ETag, err)
	}
	head, err := store.Head("b", "dir/z.txt")
	if err != nil || head.ETag != got.ETag || head.Size != len(text) || head.Body != nil {
		t.Fatalf("head = %+v, %v", head, err)
	}

	// Directories and symlinks aren't objects.
	list, _, err := store.List("b", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, obj := range list {
		keys = append(keys, obj.Key)
		if obj.Key == "dir/z.txt" && (obj.ETag != got.ETag || obj.Body != nil) {
			t.Fatalf("listed %+v", obj)
		}
	}
	if strings.Join(keys, ",") != "a.txt,dir/z.txt" {
		t.Fatalf("keys = %v", keys)
	}
	for _, key := range []string{"dir", "link"} {
		if _, err := store.Get("b", key); err == nil {
			t.Fatalf("get %s succeeded", key)
		}
		if err := store.Delete("b", key, nil); err != nil {
			t.Fatal(err)
		}
	}
	if entries, _, err := store.queryInt(`SELECT count(*) FROM sqlar`, nil); err != nil || entries != 4 {
		t.Fatalf("sqlar entries = %d, %v; DELETE removed a directory or symlink", entries, err)
	}

	// featherd writes metadata, and deletes drop it with the entry.
	if _, err := store.Put("b", "dir/z.txt", []byte("v2"), "text/plain", nil, false); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Head("b", "dir/z.txt"); err != nil || got.ContentType != "text/plain" {
		t.Fatalf("head after put = %+v, %v", got, err)
	}
	if err := store.Delete("b", "dir/z.txt", nil); err != nil {
		t.Fatal(err)
	}
	if meta, _, err := store.queryInt(`SELECT count(*) FROM content_meta`, nil); err != nil || meta != 0 {
		t.Fatalf("content_meta rows = %d, %v; want 0", meta, err)
	}
}

// TestSQLARGetRange checks that ranges of stored and metadata-less entries
// match the whole object, that compressed entries ignore ranges, and that a
// small range of a large object isn't copied into memory whole.
func TestSQLARGetRange(t *testing.T) {
	store := openSQLARStore(t, filepath.Join(t.TempDir(), "b.sqlite3"))
	big := make([]byte, 4<<20)
	for i := range big {
		big[i] = byte(i * 7 / 3)
	}
	if _, err := store.Put("b", "big", big, "", nil, false); err != nil {
		t.Fatal(err)
	}
	text := []byte(strings.Repeat("compressible ", 1000))
	err := store.execParams(`REPLACE INTO sqlar(name, mode, mtime, sz, data) VALUES
	('plain', 33188, 1700000000, :bigsz, :big),
	('zipped', 33188, 1700000000, :sz, :zipped),
	('corrupt', 33188, 1700000000, :sz, :truncated)`, params{
		"bigsz": int64(len(big)), "big": big,
		"sz": int64(len(text)), "zipped": zlibCompress(t, text), "truncated": zlibCompress(t, text)[:20],
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		key  string
		want []byte
	}{{"big", big}, {"plain", big}} {
		full, err := store.Get("b", tc.key)
		if err != nil || !bytes.Equal(full.Body, tc.want) || full.ETag != quoteETag(tc.want) {
			t.Fatalf("%s: get = %d bytes, etag %s, %v", tc.key, len(full.Body), full.ETag, err)
		}
		n := len(tc.want)
		for _, rng := range []string{"bytes=0-0", "bytes=5-1004", fmt.Sprintf("bytes=%d-", n-3), "bytes=-10", fmt.Sprintf("bytes=0-%d", n+5)} {
			obj, start, end, partial, err := store.GetRange("b", tc.key, rng)
			if err != nil || !partial || !bytes.Equal(obj.Body, tc.want[start:end]) || obj.Size != n || obj.ETag != full.ETag {
				t.Fatalf("%s %s: [%d, %d) partial=%v size %d etag %s, %v", tc.key, rng, start, end, partial, obj.Size, obj.ETag, err)
			}
		}
		if obj, _, _, _, err := store.GetRange("b", tc.key, fmt.Sprintf("bytes=%d-", n)); !errors.Is(err, errInvalidRange) || obj.Size != n {
			t.Fatalf("%s: unsatisfiable range = size %d, %v", tc.key, obj.Size, err)
		}
	}
	for _, rng := range []string{"bytes=0-0", "bytes=-10", fmt.Sprintf("bytes=%d-", len(text))} {
		obj, start, end, partial, err := store.GetRange("b", "zipped", rng)
		if err != nil || partial || start != 0 || end != len(text) || !bytes.Equal(obj.Body, text) || !obj.Compressed || obj.ETag != quoteETag(text) {
			t.Fatalf("zipped %s: [%d, %d) partial=%v compressed=%v etag %s, %v", rng, start, end, partial, obj.Compressed, obj.ETag, err)
		}
	}
	handler := newHandler(singleStore(store))
	for _, tc := range []struct{ key, accept string }{{"zipped", "none"}, {"plain", "bytes"}} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req := httptest.NewRequest(method, "/bucket/"+tc.key, nil)
			req.Header.Set("Range", "bytes=0-0")
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if got := resp.Header().Get("Accept-Ranges"); got != tc.accept {
				t.Fatalf("%s %s: Accept-Ranges = %q, want %q (status %d)", method, tc.key, got, tc.accept, resp.Code)
			}
			if tc.key == "zipped" && method == http.MethodGet && (resp.Code != http.StatusOK || !bytes.Equal(resp.Body.Bytes(), text) || resp.Header().Get("Content-Range") != "") {
				t.Fatalf("ranged GET of zipped = %d, %d bytes, Content-Range %q", resp.Code, resp.Body.Len(), resp.Header().Get("Content-Range"))
			}
		}
	}
	if _, _, _, _, err := store.GetRange("b", "corrupt", "bytes=0-0"); err == nil || !strings.Contains(err.Error(), "inflate") {
		t.Fatalf("corrupt range err = %v", err)
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	obj, _, _, _, err := store.GetRange("b", "big", "bytes=2097152-2101247")
	runtime.ReadMemStats(&after)
	if err != nil || len(obj.Body) != 4096 {
		t.Fatal(len(obj.Body), err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<10 {
		t.Fatalf("a 4 KiB range of a 4 MiB object allocated %d bytes", alloc)
	}
}

// sqliteCLI returns the path of the sqlite3 command-line shell, or skips the
// test if it isn't installed.
func sqliteCLI(t *testing.T) string {
	t.Helper()
	cli, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 CLI not found")
	}
	return cli
}

// runSQLite runs the sqlite3 shell and returns its output.
func runSQLite(t *testing.T, cli string, args ...string) string {
	t.Helper()
	out, err := exec.Command(cli, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3 %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// writeTree writes files under dir, each with the modification time mtime.
func writeTree(t *testing.T, dir string, files map[string][]byte, mtime int64) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Unix(mtime, 0), time.Unix(mtime, 0)); err != nil {
			t.Fatal(err)
		}
	}
}

// noise returns n incompressible bytes, which `sqlite3 -A` stores as is.
func noise(n int, seed byte) []byte {
	buf := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{seed}).Read(buf)
	return buf
}

// listKeys lists a bucket over HTTP and returns its keys and ETags.
func listKeys(t *testing.T, handler http.Handler, bucket string) map[string]string {
	t.Helper()
	resp := serve(handler, http.MethodGet, "/"+bucket+"?list-type=2", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("list %s = %d %q", bucket, resp.Code, resp.Body.String())
	}
	var result listBucketResult
	if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, c := range result.Contents {
		keys[c.Key] = c.ETag
	}
	return keys
}

// TestServesArchiveFromSQLiteCLI serves an archive made by `sqlite3 -A -c`
// and copied into the data directory as a bucket: every file is an object,
// directories aren't, compressed and stored entries both read back exactly,
// and nothing changes the file until the first write.
func TestServesArchiveFromSQLiteCLI(t *testing.T) {
	cli := sqliteCLI(t)
	src := t.TempDir()
	files := map[string][]byte{
		"index.html":   []byte(strings.Repeat("<p>hello from sqlar</p>\n", 100)),
		"css/site.css": []byte("body{}"),
		"img/logo.bin": noise(64<<10, 1),
		"empty":        nil,
	}
	writeTree(t, src, files, 1700000000)
	dir, path := newTestDir(t)
	archive := filepath.Join(path, "site.sqlite3")
	runSQLite(t, cli, archive, "-A", "-c", "-C", src, "index.html", "css", "img", "empty")
	if got := runSQLite(t, cli, archive, "SELECT name FROM sqlar WHERE length(data) < sz"); got != "index.html\n" {
		t.Fatalf("compressed entries = %q, want index.html only", got)
	}
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}

	handler := newHandler(dir)
	keys := listKeys(t, handler, "site")
	if len(keys) != len(files) {
		t.Fatalf("listed %v, want the %d files and no directories", keys, len(files))
	}
	for key, body := range files {
		etag := quoteETag(body)
		resp := serve(handler, http.MethodGet, "/site/"+key, nil)
		if resp.Code != http.StatusOK || !bytes.Equal(resp.Body.Bytes(), body) || resp.Header().Get("ETag") != etag ||
			resp.Header().Get("Content-Type") != "application/octet-stream" ||
			resp.Header().Get("Last-Modified") != "Tue, 14 Nov 2023 22:13:20 GMT" {
			t.Fatalf("get %s = %d, %d bytes, headers %v", key, resp.Code, resp.Body.Len(), resp.Header())
		}
		resp = serve(handler, http.MethodHead, "/site/"+key, nil)
		if resp.Code != http.StatusOK || resp.Header().Get("ETag") != etag || resp.Header().Get("Content-Length") != fmt.Sprint(len(body)) {
			t.Fatalf("head %s = %d, headers %v", key, resp.Code, resp.Header())
		}
		if keys[key] != etag {
			t.Fatalf("listed %s with ETag %s, want %s", key, keys[key], etag)
		}
	}
	for _, key := range []string{"css", "img"} {
		if resp := serve(handler, http.MethodGet, "/site/"+key, nil); resp.Code != http.StatusNotFound {
			t.Fatalf("get directory %s = %d", key, resp.Code)
		}
	}

	// A range of a stored entry is read in part; a compressed one is sent whole.
	logo := files["img/logo.bin"]
	req := httptest.NewRequest(http.MethodGet, "/site/img/logo.bin", nil)
	req.Header.Set("Range", "bytes=1000-1999")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusPartialContent || !bytes.Equal(resp.Body.Bytes(), logo[1000:2000]) ||
		resp.Header().Get("Content-Range") != fmt.Sprintf("bytes 1000-1999/%d", len(logo)) {
		t.Fatalf("ranged get = %d, %d bytes, Content-Range %q", resp.Code, resp.Body.Len(), resp.Header().Get("Content-Range"))
	}
	req = httptest.NewRequest(http.MethodGet, "/site/index.html", nil)
	req.Header.Set("Range", "bytes=0-9")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || !bytes.Equal(resp.Body.Bytes(), files["index.html"]) || resp.Header().Get("Accept-Ranges") != "none" {
		t.Fatalf("ranged get of compressed = %d, %d bytes, Accept-Ranges %q", resp.Code, resp.Body.Len(), resp.Header().Get("Accept-Ranges"))
	}
	if resp := serve(handler, http.MethodDelete, "/site/missing", nil); resp.Code != http.StatusNoContent {
		t.Fatalf("delete missing = %d", resp.Code)
	}
	if after, err := os.ReadFile(archive); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("archive changed by reads: %v", err)
	}

	// The first write adds featherd's metadata, and the archive still
	// extracts with the sqlite3 shell, including the new object.
	put := httptest.NewRequest(http.MethodPut, "/site/robots.txt", strings.NewReader("User-agent: *\n"))
	put.Header.Set("Content-Type", "text/plain")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, put)
	if resp.Code != http.StatusOK {
		t.Fatalf("put = %d %q", resp.Code, resp.Body.String())
	}
	if resp := serve(handler, http.MethodHead, "/site/robots.txt", nil); resp.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("head robots.txt Content-Type = %q", resp.Header().Get("Content-Type"))
	}
	out := t.TempDir()
	runSQLite(t, cli, archive, "-A", "-x", "-C", out)
	files["robots.txt"] = []byte("User-agent: *\n")
	for key, body := range files {
		if got, err := os.ReadFile(filepath.Join(out, key)); err != nil || !bytes.Equal(got, body) {
			t.Fatalf("extracted %s = %d bytes, %v; want %d bytes", key, len(got), err, len(body))
		}
	}
}

// TestServesArchiveUpdatedBySQLiteCLI changes an archive with the sqlite3
// shell while featherd is serving it. Updated and added files are served at
// once with ETags of their new data, even where featherd had stored metadata,
// and recreating the archive replaces its objects.
func TestServesArchiveUpdatedBySQLiteCLI(t *testing.T) {
	cli := sqliteCLI(t)
	src := t.TempDir()
	writeTree(t, src, map[string][]byte{"a.txt": []byte("a v1"), "b.bin": noise(4096, 1)}, 1700000000)
	dir, path := newTestDir(t)
	archive := filepath.Join(path, "site.sqlite3")
	runSQLite(t, cli, archive, "-A", "-c", "-C", src, "a.txt", "b.bin")

	handler := newHandler(dir)
	if resp := serve(handler, http.MethodGet, "/site/a.txt", nil); resp.Body.String() != "a v1" {
		t.Fatalf("get a.txt = %d %q", resp.Code, resp.Body.String())
	}
	// featherd writes b.bin, so it has a content type and metadata to go stale.
	put := httptest.NewRequest(http.MethodPut, "/site/b.bin", bytes.NewReader(noise(4096, 2)))
	put.Header.Set("Content-Type", "image/png")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, put)
	if resp.Code != http.StatusOK {
		t.Fatalf("put = %d %q", resp.Code, resp.Body.String())
	}

	// The shell's -u skips files whose mtime is unchanged, so give them new ones.
	updated := map[string][]byte{"a.txt": []byte("a v2"), "b.bin": noise(4096, 3), "c/new.txt": []byte("new")}
	writeTree(t, src, updated, 1700000100)
	runSQLite(t, cli, archive, "-A", "-u", "-C", src, "a.txt", "b.bin", "c")
	keys := listKeys(t, handler, "site")
	if len(keys) != len(updated) {
		t.Fatalf("listed %v after update", keys)
	}
	for key, body := range updated {
		etag := quoteETag(body)
		resp := serve(handler, http.MethodGet, "/site/"+key, nil)
		if resp.Code != http.StatusOK || !bytes.Equal(resp.Body.Bytes(), body) || resp.Header().Get("ETag") != etag ||
			resp.Header().Get("Content-Type") != "application/octet-stream" || keys[key] != etag {
			t.Fatalf("get %s after update = %d, %d bytes, headers %v, listed ETag %s", key, resp.Code, resp.Body.Len(), resp.Header(), keys[key])
		}
	}

	// Compare-and-swap sees the shell's write: the old ETag no longer matches.
	stale := httptest.NewRequest(http.MethodPut, "/site/a.txt", strings.NewReader("lost"))
	stale.Header.Set("If-Match", quoteETag([]byte("a v1")))
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, stale)
	if resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("put with stale If-Match = %d %q", resp.Code, resp.Body.String())
	}

	// -c drops and recreates the archive, so only its new files remain.
	runSQLite(t, cli, archive, "-A", "-c", "-C", src, "c")
	if keys := listKeys(t, handler, "site"); len(keys) != 1 || keys["c/new.txt"] != quoteETag([]byte("new")) {
		t.Fatalf("listed %v after recreate", keys)
	}
	if resp := serve(handler, http.MethodGet, "/site/a.txt", nil); resp.Code != http.StatusNotFound {
		t.Fatalf("get a.txt after recreate = %d", resp.Code)
	}
}

// TestSQLARExtractsWithSQLiteCLI checks that `sqlite3 -Ax` extracts what
// featherd stored, byte for byte.
func TestSQLARExtractsWithSQLiteCLI(t *testing.T) {
	cli := sqliteCLI(t)
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	files := map[string][]byte{
		"web/InterVariable.woff2": bytes.Repeat([]byte{0, 1, 2, 255}, 1000),
		"LICENSE.txt":             []byte("SIL Open Font License"),
		"empty":                   nil,
	}
	for key, body := range files {
		if _, err := store.Put("b", key, body, "", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	cmd := exec.Command(cli, path, "-A", "-x", "-C", out)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 -Ax: %v: %s", err, msg)
	}
	for key, body := range files {
		got, err := os.ReadFile(filepath.Join(out, key))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("extracted %s = %d bytes, %v; want %d bytes", key, len(got), err, len(body))
		}
	}
}

// TestStoreIsReadOnlyUntilWritten checks that reading a bucket, or deleting
// a missing object, leaves its file untouched, and that the first write uses a
// rollback journal, not WAL.
func TestStoreIsReadOnlyUntilWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	if _, err := store.Get("b", "k"); !errors.Is(err, errNotFound) {
		t.Fatalf("get err = %v", err)
	}
	if objs, truncated, err := store.List("b", "", "", 10); err != nil || len(objs) != 0 || truncated {
		t.Fatalf("list = %v, %v, %v", objs, truncated, err)
	}
	if err := store.Delete("b", "k", nil); err != nil {
		t.Fatal(err)
	}
	ifMatch := "*"
	if err := store.Delete("b", "k", &ifMatch); !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("conditional delete err = %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 || store.writable {
		t.Fatalf("after reads: %v, %v, writable %v; want an untouched empty file", info, err, store.writable)
	}

	// A file that can't be written still serves reads.
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b", "k", []byte("v"), "", nil, false); err == nil {
		t.Fatal("put to a read-only file succeeded")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b", "k", []byte("v"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	if isDelete, _, err := store.queryInt(`SELECT journal_mode = 'delete' FROM pragma_journal_mode`, nil); err != nil || isDelete != 1 {
		t.Fatalf("journal_mode is not delete: %v", err)
	}
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WAL file exists: %v", err)
	}
}

// TestReadsLeaveArchiveUnchanged serves an archive made by another tool, with
// no content_meta table, without adding featherd's tables to it.
func TestReadsLeaveArchiveUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	other := openSQLARStore(t, path)
	if err := other.openLocked(true); err != nil {
		t.Fatal(err)
	}
	if err := other.exec(`CREATE TABLE sqlar(name TEXT PRIMARY KEY, mode INT, mtime INT, sz INT, data BLOB);
INSERT INTO sqlar VALUES ('a.txt', 33188, 1700000000, 2, 'hi'), ('dir', 16877, 1700000000, 0, NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	store := openSQLARStore(t, path)
	got, err := store.Get("b", "a.txt")
	if err != nil || string(got.Body) != "hi" || got.ETag != quoteETag([]byte("hi")) || got.Mtime != 1700000000 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if objs, _, err := store.List("b", "", "", 10); err != nil || len(objs) != 1 || objs[0].ETag != got.ETag {
		t.Fatalf("list = %+v, %v", objs, err)
	}
	if err := store.Delete("b", "missing", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("archive changed by reads: %v", err)
	}
}

// TestRecreatedArchiveDropsStaleMeta recreates the sqlar table under a running
// store, as `sqlite3 -A -c` does, which also drops its triggers. The old
// content_meta rows are then ignored, and discarded by the next write.
func TestRecreatedArchiveDropsStaleMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sqlite3")
	store := openSQLARStore(t, path)
	if _, err := store.Put("b", "a.txt", []byte("old"), "text/plain", nil, false); err != nil {
		t.Fatal(err)
	}
	other := openSQLARStore(t, path)
	if err := other.openLocked(true); err != nil {
		t.Fatal(err)
	}
	if err := other.exec(`DROP TABLE sqlar;
CREATE TABLE sqlar(name TEXT PRIMARY KEY, mode INT, mtime INT, sz INT, data BLOB);
INSERT INTO sqlar VALUES ('a.txt', 33188, 1700000000, 3, 'new')`); err != nil {
		t.Fatal(err)
	}

	want := quoteETag([]byte("new"))
	if got, err := store.Head("b", "a.txt"); err != nil || got.ETag != want || got.ContentType != "application/octet-stream" {
		t.Fatalf("head after recreate = %+v, %v; want ETag %s", got, err, want)
	}
	if _, err := store.Put("b", "b.txt", []byte("b"), "text/plain", nil, false); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Head("b", "a.txt"); err != nil || got.ETag != want {
		t.Fatalf("head after next put = %+v, %v; want ETag %s", got, err, want)
	}
	if got, err := store.Head("b", "b.txt"); err != nil || got.ContentType != "text/plain" || !store.metaTrusted {
		t.Fatalf("head b.txt = %+v, %v, metaTrusted %v", got, err, store.metaTrusted)
	}
}

// TestReadRollsBackCrashedWrite opens a copy of a database taken mid-write,
// with its hot journal. Only a read-write connection can roll that back.
func TestReadRollsBackCrashedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.sqlite3")
	store := openSQLARStore(t, path)
	if _, err := store.Put("b", "k", []byte("committed"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	// A small cache that spills makes SQLite write uncommitted pages to the database
	// file, after syncing their originals to the journal.
	if err := store.exec("PRAGMA cache_size = 10; PRAGMA cache_spill = 1; BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), 1<<20)
	for i := range 4 {
		if err := store.execParams(`INSERT INTO sqlar VALUES (:key, 33188, 0, length(:body), :body)`,
			params{"key": fmt.Sprint("big", i), "body": big}); err != nil {
			t.Fatal(err)
		}
	}
	crashed := filepath.Join(dir, "crashed.sqlite3")
	for _, suffix := range []string{"", "-journal"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(crashed+suffix, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store.rollbackLocked()

	copy := openSQLARStore(t, crashed)
	got, err := copy.Get("b", "k")
	if err != nil || string(got.Body) != "committed" {
		t.Fatalf("get = %q, %v", got.Body, err)
	}
	if objs, _, err := copy.List("b", "", "", 10); err != nil || len(objs) != 1 {
		t.Fatalf("list = %d objects, %v; want the uncommitted ones rolled back", len(objs), err)
	}
}

// BenchmarkStore times the Store operations the handler uses. Run with:
// go test -run '^$' -bench Store -benchmem
func BenchmarkStore(b *testing.B) {
	sizes := []int{1 << 10, 64 << 10, 1 << 20}
	for _, size := range sizes {
		body := bytes.Repeat([]byte("featherd!"), size/9+1)[:size]
		name := fmt.Sprintf("%dKiB", size>>10)
		newStore := func(b *testing.B, keys int) *Store {
			store := openSQLARStore(b, filepath.Join(b.TempDir(), "b.sqlite3"))
			for i := range keys {
				if _, err := store.Put("b", fmt.Sprintf("k/%06d", i), body, "", nil, false); err != nil {
					b.Fatal(err)
				}
			}
			return store
		}
		b.Run(name+"/put-new", func(b *testing.B) {
			store := newStore(b, 0)
			b.SetBytes(int64(size))
			i := 0
			for b.Loop() {
				if _, err := store.Put("b", fmt.Sprintf("k/%09d", i), body, "", nil, false); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
		b.Run(name+"/put-overwrite-if-match", func(b *testing.B) {
			store := newStore(b, 1)
			obj, err := store.Head("b", "k/000000")
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			for b.Loop() {
				// Same body, so the ETag is unchanged and If-Match keeps matching.
				if _, err := store.Put("b", "k/000000", body, "", &obj.ETag, false); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"/get", func(b *testing.B) {
			store := newStore(b, 100)
			b.SetBytes(int64(size))
			i := 0
			for b.Loop() {
				if _, err := store.Get("b", fmt.Sprintf("k/%06d", i%100)); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
		b.Run(name+"/get-range-4KiB", func(b *testing.B) {
			store := newStore(b, 100)
			rng := fmt.Sprintf("bytes=%d-%d", size/2, size/2+min(size, 4096)-1)
			i := 0
			for b.Loop() {
				if _, _, _, _, err := store.GetRange("b", fmt.Sprintf("k/%06d", i%100), rng); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
		b.Run(name+"/head", func(b *testing.B) {
			store := newStore(b, 100)
			i := 0
			for b.Loop() {
				if _, err := store.Head("b", fmt.Sprintf("k/%06d", i%100)); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
		b.Run(name+"/list-100", func(b *testing.B) {
			store := newStore(b, 100)
			for b.Loop() {
				if objs, _, err := store.List("b", "k/", "", 100); err != nil || len(objs) != 100 {
					b.Fatal(len(objs), err)
				}
			}
		})
		b.Run(name+"/delete", func(b *testing.B) {
			store := newStore(b, 0)
			i := 0
			for b.Loop() {
				// Untimed re-put so each iteration deletes a real object.
				b.StopTimer()
				if _, err := store.Put("b", "k", body, "", nil, false); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := store.Delete("b", "k", nil); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}
