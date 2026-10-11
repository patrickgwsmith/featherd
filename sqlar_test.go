package main

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

// TestSQLARExtractsWithSQLiteCLI checks that `sqlite3 -Ax` extracts what
// featherd stored, byte for byte.
func TestSQLARExtractsWithSQLiteCLI(t *testing.T) {
	cli, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 CLI not found")
	}
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
