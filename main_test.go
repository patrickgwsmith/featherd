package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store := openTestStoreAt(t, filepath.Join(t.TempDir(), "store.sqlite3"))
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	})
	return store
}

func readSchema(t testing.TB) []byte {
	t.Helper()
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

// openTestStoreAt opens the database at path, creating an empty one if needed.
func openTestStoreAt(t testing.TB, path string) *Store {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	store, err := OpenStore(path, readSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// singleStore serves every bucket from one store, for tests of handler
// behavior that doesn't depend on per-bucket databases.
func singleStore(store *Store) Buckets {
	return oneStore{store}
}

type oneStore struct{ store *Store }

func (o oneStore) Store(string) (*Store, error) { return o.store, nil }
func (o oneStore) CreateBucket(string) error    { return nil }

// serve sends a request to handler and returns the recorded response.
func serve(handler http.Handler, method, target string, body io.Reader) *httptest.ResponseRecorder {
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(method, target, body))
	return resp
}

func mustCreateBucket(t *testing.T, handler http.Handler, bucket string) {
	t.Helper()
	if resp := serve(handler, http.MethodPut, "/"+bucket, nil); resp.Code != http.StatusOK {
		t.Fatalf("create %s status = %d body=%q", bucket, resp.Code, resp.Body.String())
	}
}

func newTestDir(t *testing.T) (*Dir, string) {
	t.Helper()
	path := t.TempDir()
	dir, err := OpenDir(path, readSchema(t), defaultMaxObjectBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dir.Close(); err != nil {
			t.Fatal(err)
		}
	})
	return dir, path
}

func TestEachBucketHasItsOwnDatabase(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	for _, bucket := range []string{"fonts", "photos"} {
		mustCreateBucket(t, handler, bucket)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/"+bucket+"/k", strings.NewReader(bucket)))
		if resp.Code != http.StatusOK {
			t.Fatalf("put %s status = %d body=%q", bucket, resp.Code, resp.Body.String())
		}
	}
	for _, bucket := range []string{"fonts", "photos"} {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/"+bucket+"/k", nil))
		if resp.Code != http.StatusOK || resp.Body.String() != bucket {
			t.Fatalf("get %s = %d %q", bucket, resp.Code, resp.Body.String())
		}
		resp = httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/"+bucket+"?list-type=2", nil))
		if n := strings.Count(resp.Body.String(), "<Key>"); n != 1 {
			t.Fatalf("list %s has %d keys: %s", bucket, n, resp.Body.String())
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var dbs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sqlite3") {
			dbs = append(dbs, e.Name())
		}
	}
	if strings.Join(dbs, ",") != "fonts.sqlite3,photos.sqlite3" {
		t.Fatalf("databases = %v", dbs)
	}
}

func TestUnknownBucketIsNoSuchBucket(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)
	for _, tc := range []struct {
		method, target string
		header         string
		want           int
		code           string
	}{
		{http.MethodGet, "/nobucket/k", "", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodHead, "/nobucket/k", "", http.StatusNotFound, ""},
		{http.MethodDelete, "/nobucket/k", "", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodDelete, "/nobucket/k", "*", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodGet, "/nobucket?list-type=2", "", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodPut, "/nobucket/k", "", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodPut, "/nobucket/k", "*", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodPost, "/nobucket/k", "", http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{http.MethodPut, "/nobucket?versioning", "", http.StatusNotImplemented, "NotImplemented"},
		{http.MethodPut, "/nobucket?list-type=2", "", http.StatusNotImplemented, "NotImplemented"},
		{http.MethodDelete, "/nobucket", "", http.StatusNotImplemented, "NotImplemented"},
	} {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("v"))
		if tc.header != "" {
			req.Header.Set("If-Match", tc.header)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != tc.want {
			t.Fatalf("%s %s If-Match=%q status = %d, want %d", tc.method, tc.target, tc.header, resp.Code, tc.want)
		}
		if tc.code != "" && !strings.Contains(resp.Body.String(), "<Code>"+tc.code+"</Code>") {
			t.Fatalf("%s %s body = %q, want code %s", tc.method, tc.target, resp.Body.String(), tc.code)
		}
		if tc.method == http.MethodHead && resp.Body.Len() != 0 {
			t.Fatalf("HEAD %s has body %q", tc.target, resp.Body.String())
		}
	}
	if _, err := os.Stat(filepath.Join(path, "nobucket.sqlite3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat nobucket.sqlite3 err = %v, want not exist", err)
	}

	// Once created, a missing key is NoSuchKey and an empty listing is 200.
	mustCreateBucket(t, handler, "nobucket")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/nobucket/k", strings.NewReader("v")))
	if resp.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%q", resp.Code, resp.Body.String())
	}
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/nobucket/other", nil))
	if resp.Code != http.StatusNotFound || !strings.Contains(resp.Body.String(), "<Code>NoSuchKey</Code>") {
		t.Fatalf("get missing key = %d %q", resp.Code, resp.Body.String())
	}
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/nobucket?list-type=2&prefix=zz", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestCreateBucket(t *testing.T) {
	dir, path := newTestDir(t)
	handler := newHandler(dir)

	resp := serve(handler, http.MethodPut, "/fonts", nil)
	if resp.Code != http.StatusOK || resp.Header().Get("Location") != "/fonts" || resp.Body.Len() != 0 {
		t.Fatalf("create = %d Location=%q body=%q", resp.Code, resp.Header().Get("Location"), resp.Body.String())
	}
	if _, err := os.Stat(filepath.Join(path, "fonts.sqlite3")); err != nil {
		t.Fatal(err)
	}
	resp = serve(handler, http.MethodGet, "/fonts?list-type=2", nil)
	if resp.Code != http.StatusOK || strings.Contains(resp.Body.String(), "<Key>") {
		t.Fatalf("list new bucket = %d %q", resp.Code, resp.Body.String())
	}

	// Creating it again is 409, whether it's open in this process or only on disk.
	resp = serve(handler, http.MethodPut, "/fonts", nil)
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "<Code>BucketAlreadyOwnedByYou</Code>") {
		t.Fatalf("re-create = %d %q", resp.Code, resp.Body.String())
	}
	if err := os.WriteFile(filepath.Join(path, "other.sqlite3"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if resp := serve(handler, http.MethodPut, "/other", nil); resp.Code != http.StatusConflict {
		t.Fatalf("create bucket existing on disk = %d %q", resp.Code, resp.Body.String())
	}

	// A CreateBucketConfiguration body is accepted; malformed XML is not.
	config := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	if resp := serve(handler, http.MethodPut, "/configured", strings.NewReader(config)); resp.Code != http.StatusOK {
		t.Fatalf("create with configuration = %d %q", resp.Code, resp.Body.String())
	}
	resp = serve(handler, http.MethodPut, "/malformed", strings.NewReader("<Nope>"))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "<Code>MalformedXML</Code>") {
		t.Fatalf("create with malformed body = %d %q", resp.Code, resp.Body.String())
	}
	if _, err := os.Stat(filepath.Join(path, "malformed.sqlite3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat malformed.sqlite3 err = %v, want not exist", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/locked", nil)
	req.Header.Set("X-Amz-Bucket-Object-Lock-Enabled", "true")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("create with object lock = %d %q", resp.Code, resp.Body.String())
	}
}

func TestConcurrentCreateBucketSingleWinner(t *testing.T) {
	dir, _ := newTestDir(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := dir.CreateBucket("fonts")
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, errBucketExists):
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins = %d, want 1", wins.Load())
	}
}

func TestDirReopensBucketDatabases(t *testing.T) {
	schema := readSchema(t)
	path := t.TempDir()
	dir, err := OpenDir(path, schema, defaultMaxObjectBytes)
	if err != nil {
		t.Fatal(err)
	}
	mustCreateBucket(t, newHandler(dir), "fonts")
	resp := httptest.NewRecorder()
	newHandler(dir).ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/fonts/k", strings.NewReader("kept")))
	if resp.Code != http.StatusOK {
		t.Fatalf("put status = %d", resp.Code)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}

	dir, err = OpenDir(path, schema, defaultMaxObjectBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	resp = httptest.NewRecorder()
	newHandler(dir).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/fonts/k", nil))
	if resp.Code != http.StatusOK || resp.Body.String() != "kept" {
		t.Fatalf("get after reopen = %d %q", resp.Code, resp.Body.String())
	}
}

func TestPutGetHead(t *testing.T) {
	store := newTestStore(t)
	put, err := store.Put("bkt", "hello.txt", []byte("hello"), "text/plain", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("bkt", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, []byte("hello")) {
		t.Fatalf("body = %q", got.Body)
	}
	if got.ETag != put.ETag {
		t.Fatalf("etag = %q, want %q", got.ETag, put.ETag)
	}
	head, err := store.Head("bkt", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(head.Body) != 0 || head.ContentType != "text/plain" {
		t.Fatalf("head = %+v", head)
	}
}

func TestIfNoneMatchCreate(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Put("bkt", "once", []byte("one"), "", nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("bkt", "once", []byte("two"), "", nil, true); !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("second create err = %v, want precondition", err)
	}
	got, err := store.Get("bkt", "once")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "one" {
		t.Fatalf("body changed to %q", got.Body)
	}
}

func TestIfMatchCompareAndSwap(t *testing.T) {
	store := newTestStore(t)
	first, err := store.Put("bkt", "state", []byte("v1"), "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wrong := `"wrong"`
	if _, err := store.Put("bkt", "state", []byte("bad"), "", &wrong, false); !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("wrong etag err = %v, want precondition", err)
	}
	second, err := store.Put("bkt", "state", []byte("v2"), "", &first.ETag, false)
	if err != nil {
		t.Fatal(err)
	}
	if second.ETag == first.ETag {
		t.Fatalf("etag did not change")
	}
	got, err := store.Get("bkt", "state")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "v2" {
		t.Fatalf("body = %q", got.Body)
	}
}

func TestMaxObjectSize(t *testing.T) {
	store := newTestStore(t)
	store.maxObjectBytes = 4
	if _, err := store.Put("bkt", "small", []byte("1234"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("bkt", "large", []byte("12345"), "", nil, false); !errors.Is(err, errObjectTooLarge) {
		t.Fatalf("large put err = %v, want object too large", err)
	}
	if got, err := readCapped(bytes.NewReader([]byte("12345")), 4); !errors.Is(err, errObjectTooLarge) || got != nil {
		t.Fatalf("readCapped = %q, %v; want object too large", got, err)
	}
}

func TestReadAfterOverwriteAndDelete(t *testing.T) {
	store := newTestStore(t)
	first, err := store.Put("bkt", "state", []byte("v1"), "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("bkt", "state", []byte("v2"), "", &first.ETag, false); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("bkt", "state")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "v2" {
		t.Fatalf("body after overwrite = %q", got.Body)
	}
	if err := store.Delete("bkt", "state", &got.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("bkt", "state"); !errors.Is(err, errNotFound) {
		t.Fatalf("get after delete err = %v, want not found", err)
	}
}

func TestConcurrentCreateIfAbsentSingleWinner(t *testing.T) {
	store := newTestStore(t)
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Put("bkt", "once", []byte{byte(i)}, "", nil, true)
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, errPreconditionFailed):
			default:
				t.Errorf("put %d err = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d, want 1", winners.Load())
	}
}

func TestConcurrentIfMatchSingleWinner(t *testing.T) {
	store := newTestStore(t)
	first, err := store.Put("bkt", "state", []byte("v1"), "", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Put("bkt", "state", []byte{byte(i)}, "", &first.ETag, false)
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, errPreconditionFailed):
			default:
				t.Errorf("put %d err = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d, want 1", winners.Load())
	}
}

func TestListPrefixAndDelete(t *testing.T) {
	store := newTestStore(t)
	for _, key := range []string{"logs/001", "logs/002", "other"} {
		if _, err := store.Put("bkt", key, []byte(key), "", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	list, truncated, err := store.List("bkt", "logs/", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Key != "logs/001" || list[1].Key != "logs/002" || truncated {
		t.Fatalf("list = %+v truncated=%v", list, truncated)
	}
	if err := store.Delete("bkt", "logs/001", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("bkt", "logs/001"); !errors.Is(err, errNotFound) {
		t.Fatalf("get deleted err = %v, want not found", err)
	}
}

func TestReopenPersistsObjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.sqlite3")
	store := openTestStoreAt(t, path)
	put, err := store.Put("bkt", "persist", []byte("still here"), "text/plain", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStoreAt(t, path)
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	})
	got, err := reopened.Get("bkt", "persist")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "still here" || got.ETag != put.ETag {
		t.Fatalf("got = %+v, want persisted body and etag %s", got, put.ETag)
	}
}

func TestHTTPHeadRangeListAndDelete(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))

	put := httptest.NewRequest(http.MethodPut, "/bucket/logs/001", strings.NewReader("abcdef"))
	put.Header.Set("If-None-Match", "*")
	put.Header.Set("Content-Type", "text/plain")
	putResp := httptest.NewRecorder()
	handler.ServeHTTP(putResp, put)
	if putResp.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%q", putResp.Code, putResp.Body.String())
	}
	etag := putResp.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing etag")
	}
	if _, err := store.Put("bucket", "logs/002", []byte("second"), "text/plain", nil, false); err != nil {
		t.Fatal(err)
	}

	head := httptest.NewRequest(http.MethodHead, "/bucket/logs/001", nil)
	headResp := httptest.NewRecorder()
	handler.ServeHTTP(headResp, head)
	if headResp.Code != http.StatusOK {
		t.Fatalf("head status = %d", headResp.Code)
	}
	if headResp.Header().Get("Content-Length") != "6" || headResp.Body.Len() != 0 {
		t.Fatalf("head content-length/body = %q/%q", headResp.Header().Get("Content-Length"), headResp.Body.String())
	}

	getRange := httptest.NewRequest(http.MethodGet, "/bucket/logs/001", nil)
	getRange.Header.Set("Range", "bytes=1-3")
	rangeResp := httptest.NewRecorder()
	handler.ServeHTTP(rangeResp, getRange)
	if rangeResp.Code != http.StatusPartialContent {
		t.Fatalf("range status = %d body=%q", rangeResp.Code, rangeResp.Body.String())
	}
	if rangeResp.Body.String() != "bcd" || rangeResp.Header().Get("Content-Range") != "bytes 1-3/6" {
		t.Fatalf("range body/header = %q/%q", rangeResp.Body.String(), rangeResp.Header().Get("Content-Range"))
	}

	list := httptest.NewRequest(http.MethodGet, "/bucket?list-type=2&prefix=logs/", nil)
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, list)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", listResp.Code, listResp.Body.String())
	}
	body := listResp.Body.String()
	if !strings.Contains(body, "<Key>logs/001</Key>") || !strings.Contains(body, "<Key>logs/002</Key>") {
		t.Fatalf("list body = %s", body)
	}

	del := httptest.NewRequest(http.MethodDelete, "/bucket/logs/001", nil)
	del.Header.Set("If-Match", etag)
	delResp := httptest.NewRecorder()
	handler.ServeHTTP(delResp, del)
	if delResp.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%q", delResp.Code, delResp.Body.String())
	}

	getDeleted := httptest.NewRequest(http.MethodGet, "/bucket/logs/001", nil)
	getDeletedResp := httptest.NewRecorder()
	handler.ServeHTTP(getDeletedResp, getDeleted)
	if getDeletedResp.Code != http.StatusNotFound {
		b, _ := io.ReadAll(getDeletedResp.Result().Body)
		t.Fatalf("deleted get status = %d body=%q", getDeletedResp.Code, b)
	}
}

func TestListPagination(t *testing.T) {
	store := newTestStore(t)
	for _, key := range []string{"p/1", "p/2", "p/3", "p/4", "p/5"} {
		if _, err := store.Put("bkt", key, []byte(key), "", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	handler := newHandler(singleStore(store))

	var keys []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
		url := "/bkt?list-type=2&prefix=p/&max-keys=2"
		if token != "" {
			url += "&continuation-token=" + token
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, url, nil))
		if resp.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%q", resp.Code, resp.Body.String())
		}
		var result listBucketResult
		if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, c := range result.Contents {
			keys = append(keys, c.Key)
		}
		if !result.IsTruncated {
			if result.NextContinuationToken != "" {
				t.Fatalf("unexpected next token on final page")
			}
			break
		}
		if result.NextContinuationToken == "" {
			t.Fatal("truncated page missing next token")
		}
		token = result.NextContinuationToken
	}
	if strings.Join(keys, ",") != "p/1,p/2,p/3,p/4,p/5" {
		t.Fatalf("keys = %v", keys)
	}

	list, truncated, err := store.List("bkt", "p/", "p/3", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Key != "p/4" || truncated {
		t.Fatalf("start-after list = %+v truncated=%v", list, truncated)
	}
}

func TestListCapsMaxKeys(t *testing.T) {
	store := newTestStore(t)
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/bkt?list-type=2&max-keys=5000", nil))
	if !strings.Contains(resp.Body.String(), "<MaxKeys>1000</MaxKeys>") {
		t.Fatalf("list body = %s", resp.Body.String())
	}
}

func TestListIncludesHighestUnicodeKey(t *testing.T) {
	store := newTestStore(t)
	for _, key := range []string{"ordinary", "\U0010ffff", "\U0010ffff/end"} {
		if _, err := store.Put("bkt", key, []byte("x"), "", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	objects, truncated, err := store.List("bkt", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || truncated || objects[1].Key != "\U0010ffff" || objects[2].Key != "\U0010ffff/end" {
		t.Fatalf("objects = %+v, truncated = %v", objects, truncated)
	}
}

func TestListEncodesXMLInvalidKey(t *testing.T) {
	store := newTestStore(t)
	key := "a\x00b"
	if _, err := store.Put("bkt", key, []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/bkt?list-type=2", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", resp.Code, resp.Body.String())
	}
	var result listBucketResult
	if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.EncodingType != "url" || len(result.Contents) != 1 || result.Contents[0].Key != url.QueryEscape(key) {
		t.Fatalf("list = %+v", result)
	}
	decoded, err := url.QueryUnescape(result.Contents[0].Key)
	if err != nil || decoded != key {
		t.Fatalf("decoded key = %q, err = %v", decoded, err)
	}
}

func TestListRequestedURLEncoding(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Put("bkt", "a/b", []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/bkt?list-type=2&encoding-type=url", nil))
	var result listBucketResult
	if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.EncodingType != "url" || len(result.Contents) != 1 || result.Contents[0].Key != "a%2Fb" {
		t.Fatalf("list = %+v", result)
	}
}

func TestIfMatchStar(t *testing.T) {
	store := newTestStore(t)
	star := "*"
	if _, err := store.Put("bkt", "k", []byte("v1"), "", &star, false); !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("put If-Match * on missing err = %v, want precondition", err)
	}
	if err := store.Delete("bkt", "k", &star); !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("delete If-Match * on missing err = %v, want precondition", err)
	}
	if _, err := store.Put("bkt", "k", []byte("v1"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("bkt", "k", []byte("v2"), "", &star, false); err != nil {
		t.Fatalf("put If-Match * on existing err = %v", err)
	}
	if err := store.Delete("bkt", "k", &star); err != nil {
		t.Fatalf("delete If-Match * on existing err = %v", err)
	}
}

func TestKeysWithNULBytes(t *testing.T) {
	store := newTestStore(t)
	key := "a\x00b"
	if _, err := store.Put("bkt", key, []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("bkt", key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != key {
		t.Fatalf("key = %q, want %q", got.Key, key)
	}
	if _, err := store.Get("bkt", "a"); !errors.Is(err, errNotFound) {
		t.Fatalf("truncated key lookup err = %v, want not found", err)
	}
}

func TestStepErrorIncludesSQLiteMessage(t *testing.T) {
	store := newTestStore(t)
	// The first put creates content_meta.
	if _, err := store.Put("bkt", "k", []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	err := store.withStmt(`INSERT INTO content_meta(name, sha256) VALUES ('k', NULL)`, stepDone)
	if err == nil || !strings.Contains(err.Error(), "NOT NULL") {
		t.Fatalf("err = %v, want sqlite NOT NULL message", err)
	}
	// sha256 must be the raw digest, not hex text or a quoted ETag.
	err = store.withStmt(`UPDATE content_meta SET sha256 = hex(sha256) WHERE name = 'k'`, stepDone)
	if err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("err = %v, want sqlite CHECK message", err)
	}
}

func TestListURLEncodingEscapesPlus(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Put("bkt", "x+y z", []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/bkt?list-type=2&encoding-type=url", nil))
	var result listBucketResult
	if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	// Clients such as boto3 decode with unquote_plus, so a literal "+" must be escaped.
	if len(result.Contents) != 1 || result.Contents[0].Key != "x%2By+z" {
		t.Fatalf("list = %+v", result)
	}
}

func TestKeysWithDotAndDoubleSlashSegments(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))
	for _, key := range []string{"a//b", "a/./b", "a/../b", "trailing/"} {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/bkt/"+key, strings.NewReader("v")))
		if resp.Code != http.StatusOK {
			t.Fatalf("put %q status = %d", key, resp.Code)
		}
		if _, err := store.Get("bkt", key); err != nil {
			t.Fatalf("get %q err = %v", key, err)
		}
	}
}

func TestSuffixRangeOnEmptyObject(t *testing.T) {
	if _, _, _, err := parseRangeHeader("bytes=-5", 0); !errors.Is(err, errInvalidRange) {
		t.Fatalf("err = %v, want invalid range", err)
	}
}

func TestEmptyObject(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))
	put := httptest.NewRecorder()
	handler.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/bkt/empty", nil))
	if put.Code != http.StatusOK {
		t.Fatalf("put status = %d body = %q", put.Code, put.Body.String())
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/bkt/empty", nil))
	if get.Code != http.StatusOK || get.Body.Len() != 0 {
		t.Fatalf("get status = %d body = %q", get.Code, get.Body.String())
	}
	obj, err := store.Head("bkt", "empty")
	if err != nil || obj.Size != 0 {
		t.Fatalf("head = %+v, %v", obj, err)
	}
}

func TestRangeEndAtIntLimits(t *testing.T) {
	for _, header := range []string{
		"bytes=2-9223372036854775807",
		"bytes=2-99999999999999999999",
	} {
		start, end, partial, err := parseRangeHeader(header, 6)
		if err != nil || !partial || start != 2 || end != 6 {
			t.Fatalf("%s: got %d-%d partial=%v err=%v", header, start, end, partial, err)
		}
	}
}

func TestRangeSuffixBeyondIntLimit(t *testing.T) {
	start, end, partial, err := parseRangeHeader("bytes=-99999999999999999999", 6)
	if err != nil || !partial || start != 0 || end != 6 {
		t.Fatalf("got %d-%d partial=%v err=%v", start, end, partial, err)
	}
}

func TestPutRejectsIfNoneMatchETag(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/bkt/k", strings.NewReader("v"))
	req.Header.Set("If-None-Match", `"abc"`)
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, req)
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d", resp.Code)
	}
	if _, err := store.Head("bkt", "k"); !errors.Is(err, errNotFound) {
		t.Fatalf("object written despite rejected precondition: %v", err)
	}
}

func TestListLastModifiedHasMilliseconds(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Put("bkt", "k", []byte("x"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/bkt?list-type=2", nil))
	var result listBucketResult
	if err := xml.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Contents) != 1 {
		t.Fatalf("list = %+v", result)
	}
	got := result.Contents[0].LastModified
	if _, err := time.Parse(listTimeFormat, got); err != nil || len(got) != len("2006-01-02T15:04:05.000Z") {
		t.Fatalf("LastModified = %q, err = %v", got, err)
	}
}

func TestSecondConnectionWaitsForWriteLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.sqlite3")
	first := openTestStoreAt(t, path)
	second := openTestStoreAt(t, path)
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})

	// A store's connection is read-only until its first write.
	if _, err := first.Put("bkt", "setup", nil, "", nil, false); err != nil {
		t.Fatal(err)
	}
	if err := first.exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := second.Put("bkt", "k", []byte("x"), "", nil, false)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if err := first.exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("second connection put: %v", err)
	}
}

func TestConditionalDeleteRechecksAfterWriteLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.sqlite3")
	first := openTestStoreAt(t, path)
	second := openTestStoreAt(t, path)
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})

	original, err := first.Put("bkt", "k", []byte("old"), "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if err := first.exec(`UPDATE content_meta SET sha256 = zeroblob(32) WHERE name = 'k'`); err != nil {
		_ = first.exec("ROLLBACK")
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- second.Delete("bkt", "k", &original.ETag) }()
	time.Sleep(200 * time.Millisecond)
	if err := first.exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, errPreconditionFailed) {
		t.Fatalf("conditional delete err = %v, want precondition failure", err)
	}
	if _, err := first.Head("bkt", "k"); err != nil {
		t.Fatalf("object was deleted: %v", err)
	}
}

func TestUnsupportedRequestsDoNotTouchObjects(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Put("bkt", "k", []byte("original"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(singleStore(store))
	cases := []struct {
		method, target string
		header         http.Header
	}{
		{http.MethodPut, "/bkt/k?tagging", nil},
		{http.MethodPut, "/bkt/k?acl", nil},
		{http.MethodPut, "/bkt/k?partNumber=1&uploadId=u", nil},
		{http.MethodDelete, "/bkt/k?tagging", nil},
		{http.MethodDelete, "/bkt/k?versionId=v1", nil},
		{http.MethodGet, "/bkt/k?versionId=v1", nil},
		{http.MethodGet, "/bkt?list-type=2&delimiter=/", nil},
		{http.MethodPut, "/bkt/k", http.Header{"X-Amz-Copy-Source": {"/bkt/other"}}},
		{http.MethodPut, "/bkt/k", http.Header{"Content-Encoding": {"aws-chunked"}}},
		{http.MethodPut, "/bkt/k", http.Header{"X-Amz-Content-Sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"}}},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("replacement"))
		for name, values := range tc.header {
			req.Header[name] = values
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusNotImplemented {
			t.Errorf("%s %s %v: status = %d, want 501", tc.method, tc.target, tc.header, resp.Code)
		}
	}
	got, err := store.Get("bkt", "k")
	if err != nil || string(got.Body) != "original" {
		t.Fatalf("object after rejected requests = %q, %v", got.Body, err)
	}
}

func TestAllowedQueryParameters(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))
	for _, tc := range []struct{ method, target string }{
		{http.MethodPut, "/bkt/k?x-id=PutObject"},
		{http.MethodGet, "/bkt/k?x-id=GetObject&response-content-type=text/plain"},
		{http.MethodGet, "/bkt/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"},
		{http.MethodGet, "/bkt?list-type=2&delimiter=&fetch-owner=false"},
	} {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(tc.method, tc.target, strings.NewReader("v")))
		if resp.Code != http.StatusOK {
			t.Errorf("%s %s: status = %d %s", tc.method, tc.target, resp.Code, resp.Body)
		}
	}
}

func TestPutVerifiesPayloadDigests(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))
	cases := []struct {
		header http.Header
		want   int
	}{
		{http.Header{"Content-Md5": {"XUFAKrxLKna5cZ2REBfFkg=="}}, http.StatusOK}, // md5("hello")
		{http.Header{"Content-Md5": {"1B2M2Y8AsgTpgAmY7PhCfg=="}}, http.StatusBadRequest},
		{http.Header{"X-Amz-Content-Sha256": {"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}, http.StatusOK},
		{http.Header{"X-Amz-Content-Sha256": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, http.StatusBadRequest},
		{http.Header{"X-Amz-Content-Sha256": {"UNSIGNED-PAYLOAD"}}, http.StatusOK},
	}
	for i, tc := range cases {
		req := httptest.NewRequest(http.MethodPut, "/bkt/k", strings.NewReader("hello"))
		for name, values := range tc.header {
			req.Header[name] = values
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != tc.want {
			t.Errorf("case %d %v: status = %d, want %d", i, tc.header, resp.Code, tc.want)
		}
	}
}

func TestGetAndHeadSendLastModified(t *testing.T) {
	store := newTestStore(t)
	put, err := store.Put("bkt", "k", []byte("v"), "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(put.Mtime, 0).UTC().Format(http.TimeFormat)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp := httptest.NewRecorder()
		newHandler(singleStore(store)).ServeHTTP(resp, httptest.NewRequest(method, "/bkt/k", nil))
		if got := resp.Header().Get("Last-Modified"); got != want {
			t.Errorf("%s Last-Modified = %q, want %q", method, got, want)
		}
	}
}

func TestErrorsAreS3XML(t *testing.T) {
	store := newTestStore(t)
	store.maxObjectBytes = 8
	if _, err := store.Put("bkt", "k", []byte("hello"), "", nil, false); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(singleStore(store))
	cases := []struct {
		method, target string
		header         http.Header
		body           string
		status         int
		code, key      string
	}{
		{http.MethodGet, "/bkt/missing", nil, "", http.StatusNotFound, "NoSuchKey", "missing"},
		{http.MethodDelete, "/bkt/k", http.Header{"If-Match": {`"nope"`}}, "", http.StatusPreconditionFailed, "PreconditionFailed", "k"},
		{http.MethodGet, "/bkt/k", http.Header{"Range": {"bytes=9-"}}, "", http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "k"},
		{http.MethodPut, "/bkt/big", nil, "123456789", http.StatusBadRequest, "EntityTooLarge", "big"},
		{http.MethodPut, "/bkt/k", http.Header{"Content-Md5": {"1B2M2Y8AsgTpgAmY7PhCfg=="}}, "hello", http.StatusBadRequest, "BadDigest", "k"},
		{http.MethodPut, "/bkt/k", http.Header{"X-Amz-Content-Sha256": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, "hello", http.StatusBadRequest, "XAmzContentSHA256Mismatch", "k"},
		{http.MethodPut, "/bkt/k?tagging", nil, "", http.StatusNotImplemented, "NotImplemented", "k"},
		{http.MethodPut, "/bkt?versioning", nil, "", http.StatusNotImplemented, "NotImplemented", ""},
		{http.MethodPut, "/bkt", nil, "<Nope>", http.StatusBadRequest, "MalformedXML", ""},
		{http.MethodGet, "/", nil, "", http.StatusNotImplemented, "NotImplemented", ""},
		{http.MethodGet, "/bkt?list-type=2&max-keys=x", nil, "", http.StatusBadRequest, "InvalidArgument", ""},
		{http.MethodPost, "/bkt/k", nil, "", http.StatusMethodNotAllowed, "MethodNotAllowed", "k"},
		{http.MethodGet, "/bkt/nul%00key", nil, "", http.StatusNotFound, "NoSuchKey", "nul�key"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		for name, values := range tc.header {
			req.Header[name] = values
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		var doc s3Error
		if err := xml.Unmarshal(resp.Body.Bytes(), &doc); err != nil {
			t.Errorf("%s %s: status %d, body %q is not XML: %v", tc.method, tc.target, resp.Code, resp.Body, err)
			continue
		}
		if resp.Code != tc.status || doc.Code != tc.code || doc.Key != tc.key || resp.Header().Get("Content-Type") != "application/xml" {
			t.Errorf("%s %s: got %d %+v (%s), want %d %s key %q", tc.method, tc.target, resp.Code, doc, resp.Header().Get("Content-Type"), tc.status, tc.code, tc.key)
		}
		if tc.key != "" && doc.BucketName != "bkt" {
			t.Errorf("%s %s: BucketName = %q", tc.method, tc.target, doc.BucketName)
		}
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/bkt/missing", nil))
	if head.Code != http.StatusNotFound || head.Body.Len() != 0 {
		t.Fatalf("head missing = %d %q, want 404 with no body", head.Code, head.Body)
	}
}

func TestChecksumAlgorithmVectors(t *testing.T) {
	// Standard check values for "123456789".
	want := map[string]string{
		"CRC32":     "cbf43926",
		"CRC32C":    "e3069283",
		"CRC64NVME": "ae8b14860a799888",
		"SHA1":      "f7c3bc1d808e04732adf679965ccc34ca7ae3441",
		"SHA256":    "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
	}
	for _, alg := range checksumAlgorithms {
		if got := hex.EncodeToString(alg.sum([]byte("123456789"))); got != want[alg.name] {
			t.Errorf("%s = %s, want %s", alg.name, got, want[alg.name])
		}
	}
}

func TestChecksumVerification(t *testing.T) {
	body := "hello"
	sha := sha256.Sum256([]byte(body))
	goodSHA := base64.StdEncoding.EncodeToString(sha[:])
	badSHA := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	goodCRC := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE([]byte(body))))
	cases := []struct {
		name, target string
		header       http.Header
		status       int
		code         string
	}{
		{"sha256 header", "/bkt/k", http.Header{"X-Amz-Checksum-Sha256": {goodSHA}}, http.StatusOK, ""},
		{"crc32 header", "/bkt/k", http.Header{"X-Amz-Checksum-Crc32": {goodCRC}, "X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}}, http.StatusOK, ""},
		{"presigned sha256", "/bkt/k?X-Amz-Signature=abc&x-amz-checksum-sha256=" + url.QueryEscape(goodSHA), nil, http.StatusOK, ""},
		{"sha256 mismatch", "/bkt/k", http.Header{"X-Amz-Checksum-Sha256": {badSHA}}, http.StatusBadRequest, "BadDigest"},
		{"presigned mismatch", "/bkt/k?x-amz-checksum-sha256=" + url.QueryEscape(badSHA), nil, http.StatusBadRequest, "BadDigest"},
		{"header good, query bad", "/bkt/k?x-amz-checksum-sha256=" + url.QueryEscape(badSHA), http.Header{"X-Amz-Checksum-Sha256": {goodSHA}}, http.StatusBadRequest, "BadDigest"},
		{"presigned content sha256 mismatch", "/bkt/k?X-Amz-Content-Sha256=" + strings.Repeat("0", 64), nil, http.StatusBadRequest, "XAmzContentSHA256Mismatch"},
		{"not base64", "/bkt/k", http.Header{"X-Amz-Checksum-Sha256": {"!!"}}, http.StatusBadRequest, "InvalidRequest"},
		{"wrong length", "/bkt/k", http.Header{"X-Amz-Checksum-Sha256": {goodCRC}}, http.StatusBadRequest, "InvalidRequest"},
		{"two algorithms", "/bkt/k", http.Header{"X-Amz-Checksum-Sha256": {goodSHA}, "X-Amz-Checksum-Crc32": {goodCRC}}, http.StatusBadRequest, "InvalidRequest"},
		{"sdk algorithm without checksum", "/bkt/k", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"SHA256"}}, http.StatusBadRequest, "InvalidRequest"},
		{"sdk algorithm differs", "/bkt/k", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}, "X-Amz-Checksum-Sha256": {goodSHA}}, http.StatusBadRequest, "InvalidRequest"},
		{"trailer", "/bkt/k", http.Header{"X-Amz-Trailer": {"x-amz-checksum-crc32"}}, http.StatusNotImplemented, "NotImplemented"},
	}
	for _, tc := range cases {
		store := newTestStore(t)
		handler := newHandler(singleStore(store))
		req := httptest.NewRequest(http.MethodPut, tc.target, strings.NewReader(body))
		for name, values := range tc.header {
			req.Header[name] = values
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		var doc s3Error
		_ = xml.Unmarshal(resp.Body.Bytes(), &doc)
		if resp.Code != tc.status || doc.Code != tc.code {
			t.Errorf("%s: got %d %q, want %d %q", tc.name, resp.Code, doc.Code, tc.status, tc.code)
		}
		_, err := store.Get("bkt", "k")
		if stored := err == nil; stored != (tc.status == http.StatusOK) {
			t.Errorf("%s: stored = %v, err = %v", tc.name, stored, err)
		}
	}
}

func TestBucketNameRules(t *testing.T) {
	valid := []string{"abc", strings.Repeat("a", 63), "my.bucket-1", "1bucket", "192.168.5.4x", "a.b.c.d"}
	invalid := []string{
		"ab", strings.Repeat("a", 64), "My-Bucket", "my_bucket", "-bucket", "bucket-", ".bucket", "bucket.",
		"my..bucket", "192.168.5.4", "xn--bucket", "sthree-bucket", "amzn-s3-demo-bucket",
		"bucket-s3alias", "bucket--ol-s3", "bucket.mrap", "bucket--x-s3", "bucket--table-s3",
	}
	for _, name := range valid {
		if !validBucketName(name) {
			t.Errorf("validBucketName(%q) = false, want true", name)
		}
	}
	for _, name := range invalid {
		if validBucketName(name) {
			t.Errorf("validBucketName(%q) = true, want false", name)
		}
	}
}

func TestHTTPRejectsInvalidBucketsAndLongKeys(t *testing.T) {
	store := newTestStore(t)
	handler := newHandler(singleStore(store))
	cases := []struct {
		method, target string
		status         int
		code           string
	}{
		{http.MethodPut, "/My_Bucket/k", http.StatusBadRequest, "InvalidBucketName"},
		{http.MethodGet, "/ab/k", http.StatusBadRequest, "InvalidBucketName"},
		{http.MethodGet, "/ab?list-type=2", http.StatusBadRequest, "InvalidBucketName"},
		{http.MethodPut, "/bkt/" + strings.Repeat("k", maxKeyBytes+1), http.StatusBadRequest, "KeyTooLongError"},
		// 512 two-byte runes: 1024 bytes, so the limit counts UTF-8 bytes, not characters.
		{http.MethodPut, "/bkt/" + url.PathEscape(strings.Repeat("é", 513)), http.StatusBadRequest, "KeyTooLongError"},
		{http.MethodPut, "/bkt/" + url.PathEscape(strings.Repeat("é", 512)), http.StatusOK, ""},
		{http.MethodPut, "/bkt/" + strings.Repeat("k", maxKeyBytes), http.StatusOK, ""},
	}
	for _, tc := range cases {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(tc.method, tc.target, strings.NewReader("v")))
		var doc s3Error
		_ = xml.Unmarshal(resp.Body.Bytes(), &doc)
		if resp.Code != tc.status || doc.Code != tc.code {
			t.Errorf("%s %.40s: got %d %q, want %d %q", tc.method, tc.target, resp.Code, doc.Code, tc.status, tc.code)
		}
	}
	// Only the two valid PUTs were stored. The store has no bucket column, so
	// check its whole contents, not just "My_Bucket".
	objects, _, err := store.List("bkt", "", "", 10)
	if err != nil || len(objects) != 2 {
		t.Fatalf("stored objects = %d, %v; want the 2 valid PUTs", len(objects), err)
	}
}
