package main

/*
#cgo darwin LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"
)

const (
	defaultMaxObjectBytes int64 = 20 * 1024 * 1024
	maxListKeys                 = 1000
	busyTimeoutMS               = 5000
	maxKeyBytes                 = 1024
	// S3 always includes milliseconds in listing timestamps.
	listTimeFormat = "2006-01-02T15:04:05.000Z"
)

var (
	errNotFound           = errors.New("object not found")
	errNoSuchBucket       = errors.New("bucket not found")
	errBucketExists       = errors.New("bucket already exists")
	errMalformedXML       = errors.New("malformed XML")
	errPreconditionFailed = errors.New("precondition failed")
	errNotModified        = errors.New("not modified")
	errObjectTooLarge     = errors.New("object too large")
	errInvalidRange       = errors.New("invalid range")
	errBadDigest          = errors.New("payload does not match Content-MD5")
	errSHA256Mismatch     = errors.New("payload does not match x-amz-content-sha256")
)

//go:embed schema.sql
var defaultSchema []byte

// checksumMismatch is the algorithm, e.g. "SHA256", of an x-amz-checksum-*
// value that the body does not match.
type checksumMismatch string

func (a checksumMismatch) Error() string {
	return "payload does not match x-amz-checksum-" + strings.ToLower(string(a))
}

// invalidRequest is S3's 400 InvalidRequest, with its message.
type invalidRequest string

func (m invalidRequest) Error() string { return string(m) }

type Store struct {
	db             *C.sqlite3
	path           string
	writable       bool
	maxObjectBytes int64
	mu             sync.Mutex

	// What the database held at schemaVersion, its PRAGMA schema_version when
	// last inspected; -1 forces another look.
	schemaVersion int64
	hasSQLAR      bool
	// metaTrusted means content_meta exists along with the sqlar triggers that
	// drop its rows when an entry is written. Without them, e.g. after
	// `sqlite3 -A -c` recreated the archive, a row may describe data that has
	// since changed, so content_meta is ignored.
	metaTrusted bool
}

// sqlarFile selects regular files (S_IFREG); sqlar also holds directory and
// symlink entries, which aren't objects.
const sqlarFile = `mode & 61440 = 32768`

// metaTriggers are the schema's triggers that keep content_meta fresh.
var metaTriggers = []string{"sqlar_insert_drops_meta", "sqlar_update_drops_meta", "sqlar_delete_drops_meta"}

// selectObjects returns a query for the regular files matching where, with
// columns rowid, key, length(data), size, sha256, content_type and mtime.
// SQLite computes length(data) without reading the data. With meta false,
// content_meta is not read.
func selectObjects(meta bool, where string) string {
	if !meta {
		return `SELECT s.rowid, s.name, length(s.data), s.sz, NULL, NULL, s.mtime FROM sqlar s WHERE ` + where
	}
	return `SELECT s.rowid, s.name, length(s.data), s.sz, m.sha256, m.content_type, s.mtime
FROM sqlar s LEFT JOIN content_meta m ON m.name = s.name
WHERE ` + where
}

const (
	whereKey  = `s.name = :key AND ` + sqlarFile
	whereList = `s.name >= :prefix AND s.name > :after AND (:prefix = '' OR s.name < :upper) AND ` + sqlarFile + `
ORDER BY s.name
LIMIT :limit`

	// Mode 33188 is 0100644, a regular file readable by all. Data is stored
	// uncompressed, so sz = length(data). The sqlar triggers drop the old
	// metadata when the entry is written, so the metadata goes in second.
	putEntrySQL = `INSERT INTO sqlar(name, mode, mtime, sz, data)
VALUES (:key, 33188, :mtime, length(:body), :body)
ON CONFLICT(name) DO UPDATE SET
	mode = excluded.mode,
	mtime = excluded.mtime,
	sz = excluded.sz,
	data = excluded.data`
	putMetaSQL = `INSERT INTO content_meta(name, sha256, content_type)
VALUES (:key, :sha256, :content_type)
ON CONFLICT(name) DO UPDATE SET
	sha256 = excluded.sha256,
	content_type = excluded.content_type`
	deleteSQL = `DELETE FROM sqlar WHERE name = :key AND ` + sqlarFile
)

type Object struct {
	Bucket      string
	Key         string
	Body        []byte
	Size        int
	ETag        string
	ContentType string
	// Mtime is the last write in Unix seconds, sqlar.mtime.
	Mtime int64
	// Compressed is set for a zlib-compressed sqlar entry, written by another
	// tool, which can't be read in part and so doesn't support ranges.
	Compressed bool
}

// entry is an object's sqlar row, read without its data.
type entry struct {
	Object
	rowid int64
	// stored is length(data). It is less than Size for a zlib-compressed entry.
	stored int
}

type listBucketResult struct {
	XMLName               xml.Name      `xml:"ListBucketResult"`
	Xmlns                 string        `xml:"xmlns,attr"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	EncodingType          string        `xml:"EncodingType,omitempty"`
	StartAfter            string        `xml:"StartAfter,omitempty"`
	ContinuationToken     string        `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	KeyCount              int           `xml:"KeyCount"`
	MaxKeys               int           `xml:"MaxKeys"`
	IsTruncated           bool          `xml:"IsTruncated"`
	Contents              []listContent `xml:"Contents"`
}

// s3Error is S3's error document. SDKs map Code to typed exceptions, e.g.
// boto3's NoSuchKey, so the codes must match S3's.
type s3Error struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
	Resource   string   `xml:"Resource"`
}

type listContent struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int    `xml:"Size"`
}

// OpenStore opens the existing database at path, a SQLite Archive or an
// empty file, read-only. The first write reopens it read-write and applies
// the embedded schema, so a bucket that is only read is never modified.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, maxObjectBytes: defaultMaxObjectBytes}
	if err := s.openLocked(false); err != nil {
		return nil, err
	}
	// Fails early if the file isn't a SQLite database.
	if err := s.readyLocked(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// openLocked (re)opens the connection, read-write or read-only. It keeps
// SQLite's default rollback journal, so the database file alone always holds
// every committed write.
func (s *Store) openLocked(writable bool) error {
	cpath := C.CString(s.path)
	defer C.free(unsafe.Pointer(cpath))

	flags := C.int(C.SQLITE_OPEN_READONLY)
	if writable {
		flags = C.SQLITE_OPEN_READWRITE
	}
	var db *C.sqlite3
	if rc := C.sqlite3_open_v2(cpath, &db, flags|C.SQLITE_OPEN_FULLMUTEX, nil); rc != C.SQLITE_OK {
		msg := "open sqlite"
		if db != nil {
			msg = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return errors.New(msg)
	}
	// SQLite opens a write-protected file read-only rather than failing.
	if writable && C.sqlite3_db_readonly(db, nil) == 1 {
		C.sqlite3_close(db)
		return fmt.Errorf("%s is read-only", filepath.Base(s.path))
	}
	C.sqlite3_extended_result_codes(db, 1)
	// Wait for locks held by other connections instead of failing with SQLITE_BUSY.
	C.sqlite3_busy_timeout(db, busyTimeoutMS)

	if s.db != nil {
		C.sqlite3_close(s.db)
	}
	s.db, s.writable, s.schemaVersion = db, writable, -1
	if writable {
		return s.exec("PRAGMA synchronous = FULL")
	}
	return nil
}

// readyLocked prepares the connection for a read.
func (s *Store) readyLocked() error {
	err := s.inspectLocked()
	if err != nil && !s.writable && C.sqlite3_extended_errcode(s.db) == C.SQLITE_READONLY_ROLLBACK {
		// A writer crashed mid-transaction, and only a read-write connection
		// can roll its journal back.
		if err := s.openLocked(true); err != nil {
			return err
		}
		return s.inspectLocked()
	}
	return err
}

// inspectLocked notes which of the schema's tables and triggers exist, if the
// schema has changed since it last looked.
func (s *Store) inspectLocked() error {
	version, _, err := s.queryInt(`PRAGMA schema_version`, nil)
	if err != nil || version == s.schemaVersion {
		return err
	}
	n, _, err := s.queryInt(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'sqlar'`, nil)
	if err != nil {
		return err
	}
	s.hasSQLAR = n == 1
	n, _, err = s.queryInt(`SELECT count(*) FROM sqlite_master
WHERE (type = 'table' AND name = 'content_meta')
	OR (type = 'trigger' AND tbl_name = 'sqlar' AND name IN (:t0, :t1, :t2))`,
		params{"t0": metaTriggers[0], "t1": metaTriggers[1], "t2": metaTriggers[2]})
	if err != nil {
		return err
	}
	s.metaTrusted = n == 1+int64(len(metaTriggers))
	s.schemaVersion = version
	return nil
}

// rollbackLocked ends a write transaction, which may have created schema it
// now undoes, so the schema is inspected again before the next use.
func (s *Store) rollbackLocked() {
	_ = s.exec("ROLLBACK")
	s.schemaVersion = -1
}

// beginWriteLocked starts a write transaction, first reopening the database
// read-write if needed, and applies the schema if any of it is missing.
func (s *Store) beginWriteLocked() (err error) {
	if !s.writable {
		if err := s.openLocked(true); err != nil {
			return err
		}
	}
	if err := s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.rollbackLocked()
		}
	}()
	if err := s.inspectLocked(); err != nil || s.metaTrusted {
		return err
	}
	// Rows written without the triggers in place may be stale.
	if err := s.exec("DROP TABLE IF EXISTS content_meta"); err != nil {
		return err
	}
	if err := s.exec(string(defaultSchema)); err != nil {
		return err
	}
	if err := s.inspectLocked(); err != nil {
		return err
	}
	if !s.hasSQLAR || !s.metaTrusted {
		return errors.New("schema does not create the sqlar and content_meta tables and content_meta's triggers")
	}
	return nil
}

// Dir keeps one SQLite database per bucket at <path>/<bucket>.sqlite3.
// Bucket names are validated before they reach Dir, so they are safe file
// names: lowercase letters, digits, '.' and '-', with no leading '.' and no "..".
type Dir struct {
	path           string
	maxObjectBytes int64
	mu             sync.Mutex
	stores         map[string]*Store
}

func OpenDir(path string, maxObjectBytes int64) (*Dir, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return &Dir{path: path, maxObjectBytes: maxObjectBytes, stores: map[string]*Store{}}, nil
}

// Store returns the bucket's database. As in S3, a bucket must be created
// with CreateBucket first; an unknown bucket is errNoSuchBucket.
func (d *Dir) Store(bucket string) (*Store, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.stores[bucket]; ok {
		return s, nil
	}
	path := d.bucketPath(bucket)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, errNoSuchBucket
	} else if err != nil {
		return nil, err
	}
	return d.openLocked(bucket, path)
}

// CreateBucket creates the bucket's database, or returns errBucketExists.
func (d *Dir) CreateBucket(bucket string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.stores[bucket]; ok {
		return errBucketExists
	}
	// O_EXCL, so a bucket created by another process isn't treated as new.
	path := d.bucketPath(bucket)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return errBucketExists
	} else if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// SQLite treats the empty file as an empty database. It stays empty until
	// the first object is put.
	if _, err := d.openLocked(bucket, path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func (d *Dir) bucketPath(bucket string) string {
	return filepath.Join(d.path, bucket+".sqlite3")
}

func (d *Dir) openLocked(bucket, path string) (*Store, error) {
	s, err := OpenStore(path)
	if err != nil {
		return nil, err
	}
	s.maxObjectBytes = d.maxObjectBytes
	d.stores[bucket] = s
	return s, nil
}

func (d *Dir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var errs []error
	for bucket, s := range d.stores {
		errs = append(errs, s.Close())
		delete(d.stores, bucket)
	}
	return errors.Join(errs...)
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	if rc := C.sqlite3_close(s.db); rc != C.SQLITE_OK {
		return errors.New("close sqlite")
	}
	s.db = nil
	return nil
}

func (s *Store) Put(bucket, key string, body []byte, contentType string, ifMatch *string, ifNoneMatchStar bool) (Object, error) {
	if int64(len(body)) > s.maxObjectBytes {
		return Object{}, errObjectTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if contentType == "" {
		contentType = "application/octet-stream"
	}
	sum := sha256.Sum256(body)
	next := Object{
		Bucket:      bucket,
		Key:         key,
		Body:        append([]byte(nil), body...),
		Size:        len(body),
		ETag:        etagOf(sum[:]),
		ContentType: contentType,
		Mtime:       time.Now().Unix(),
	}

	if err := s.beginWriteLocked(); err != nil {
		return Object{}, err
	}
	committed := false
	defer func() {
		if !committed {
			s.rollbackLocked()
		}
	}()

	current, err := s.headLocked(bucket, key)
	if err != nil && !errors.Is(err, errNotFound) {
		return Object{}, err
	}
	exists := err == nil
	if ifNoneMatchStar && exists {
		return Object{}, errPreconditionFailed
	}
	if ifMatch != nil {
		if !exists || !etagMatches(*ifMatch, current.ETag) {
			return Object{}, errPreconditionFailed
		}
	}

	values := params{
		"key":          key,
		"body":         body,
		"sha256":       sum[:],
		"content_type": contentType,
		"mtime":        next.Mtime,
	}
	for _, sql := range []string{putEntrySQL, putMetaSQL} {
		if err := s.execParams(sql, values); err != nil {
			return Object{}, err
		}
	}
	if err := s.exec("COMMIT"); err != nil {
		return Object{}, err
	}
	committed = true
	return next, nil
}

// Get returns the whole object.
func (s *Store) Get(bucket, key string) (Object, error) {
	obj, _, _, _, err := s.GetRange(bucket, key, "")
	return obj, err
}

// GetRange returns the object with Body holding only bytes [start, end) of
// it, as selected by rangeHeader, a Range header value; partial is false if
// that is the whole object. Only those bytes are read from the database, so a
// small range of a large object needs little memory. An unsatisfiable range
// is errInvalidRange, returned with the object's metadata. A compressed entry
// ignores rangeHeader and is always returned whole.
func (s *Store) GetRange(bucket, key, rangeHeader string) (obj Object, start, end int, partial bool, err error) {
	return s.GetRangeIf(bucket, key, rangeHeader, conditions{})
}

// GetRangeIf is GetRange that first checks cond against the object, before
// reading any of its data. A failed condition is errPreconditionFailed or
// errNotModified, returned with the object's metadata.
func (s *Store) GetRangeIf(bucket, key, rangeHeader string, cond conditions) (obj Object, start, end int, partial bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return Object{}, 0, 0, false, err
	}
	// One read transaction, so the metadata and data are from the same snapshot.
	if err := s.exec("BEGIN"); err != nil {
		return Object{}, 0, 0, false, err
	}
	defer func() { _ = s.exec("COMMIT") }()

	e, err := s.entryLocked(key)
	if err != nil {
		return Object{}, 0, 0, false, err
	}
	obj = e.Object
	obj.Bucket = bucket
	if cond != (conditions{}) {
		if obj.ETag == "" {
			if obj.ETag, err = s.etagLocked(e); err != nil {
				return Object{}, 0, 0, false, err
			}
		}
		if err := cond.check(obj.ETag); err != nil {
			return obj, 0, 0, false, err
		}
	}
	if obj.Compressed {
		rangeHeader = ""
	}
	start, end, partial, err = parseRangeHeader(rangeHeader, obj.Size)
	if err != nil {
		return obj, 0, 0, false, err
	}
	if obj.Body, err = s.readLocked(e, start, end); err != nil {
		return Object{}, 0, 0, false, err
	}
	if obj.ETag == "" {
		if partial {
			obj.ETag, err = s.etagLocked(e)
		} else {
			obj.ETag = quoteETag(obj.Body)
		}
	}
	if err != nil {
		return Object{}, 0, 0, false, err
	}
	return obj, start, end, partial, nil
}

func (s *Store) Head(bucket, key string) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return Object{}, err
	}
	return s.headLocked(bucket, key)
}

// headLocked returns the object without its body.
func (s *Store) headLocked(bucket, key string) (Object, error) {
	e, err := s.entryLocked(key)
	if err != nil {
		return Object{}, err
	}
	if e.ETag == "" {
		if e.ETag, err = s.etagLocked(e); err != nil {
			return Object{}, err
		}
	}
	e.Bucket = bucket
	return e.Object, nil
}

// entryLocked returns key's entry, whose ETag is empty if it has no metadata.
func (s *Store) entryLocked(key string) (entry, error) {
	if !s.hasSQLAR {
		return entry{}, errNotFound
	}
	var out entry
	err := s.withStmt(selectObjects(s.metaTrusted, whereKey), func(stmt *C.sqlite3_stmt) error {
		if err := bindParams(stmt, params{"key": key}); err != nil {
			return err
		}
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			return errNotFound
		}
		if rc != C.SQLITE_ROW {
			return s.lastErr()
		}
		out = scanEntry(stmt)
		return nil
	})
	return out, err
}

func (s *Store) Delete(bucket, key string, ifMatch *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.writable {
		// Deleting a missing object changes nothing, so leave the database read-only.
		if err := s.readyLocked(); err != nil {
			return err
		}
		if _, err := s.headLocked(bucket, key); errors.Is(err, errNotFound) {
			if ifMatch != nil {
				return errPreconditionFailed
			}
			return nil
		} else if err != nil {
			return err
		}
	}
	if err := s.beginWriteLocked(); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			s.rollbackLocked()
		}
	}()
	if ifMatch != nil {
		current, err := s.headLocked(bucket, key)
		if errors.Is(err, errNotFound) {
			return errPreconditionFailed
		}
		if err != nil {
			return err
		}
		if !etagMatches(*ifMatch, current.ETag) {
			return errPreconditionFailed
		}
	}
	if err := s.execParams(deleteSQL, params{"key": key}); err != nil {
		return err
	}
	if err := s.exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// List returns up to limit objects under prefix whose keys sort after
// startAfter, and whether more matching objects remain.
func (s *Store) List(bucket, prefix, startAfter string, limit int) ([]Object, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > maxListKeys {
		limit = maxListKeys
	}
	if err := s.readyLocked(); err != nil || !s.hasSQLAR {
		return nil, false, err
	}
	var out []Object
	err := s.withStmt(selectObjects(s.metaTrusted, whereList), func(stmt *C.sqlite3_stmt) error {
		err := bindParams(stmt, params{
			"prefix": prefix,
			"after":  startAfter,
			"upper":  prefixUpperBound(prefix),
			// Fetch one extra row to learn whether the listing is truncated.
			"limit": int64(limit + 1),
		})
		if err != nil {
			return err
		}
		for {
			rc := C.sqlite3_step(stmt)
			if rc == C.SQLITE_DONE {
				return nil
			}
			if rc != C.SQLITE_ROW {
				return s.lastErr()
			}
			e := scanEntry(stmt)
			if e.ETag == "" {
				var err error
				if e.ETag, err = s.etagLocked(e); err != nil {
					return err
				}
			}
			e.Bucket = bucket
			out = append(out, e.Object)
		}
	})
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (s *Store) exec(sql string) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var errmsg *C.char
	if rc := C.sqlite3_exec(s.db, csql, nil, nil, &errmsg); rc != C.SQLITE_OK {
		defer C.sqlite3_free(unsafe.Pointer(errmsg))
		return errors.New(C.GoString(errmsg))
	}
	return nil
}

// execParams runs one statement with named parameters.
func (s *Store) execParams(sql string, values params) error {
	return s.withStmt(sql, func(stmt *C.sqlite3_stmt) error {
		if err := bindParams(stmt, values); err != nil {
			return err
		}
		return stepDone(stmt)
	})
}

// queryInt returns the first column of the first row, and whether there was a row.
func (s *Store) queryInt(sql string, values params) (int64, bool, error) {
	var n int64
	found := false
	err := s.withStmt(sql, func(stmt *C.sqlite3_stmt) error {
		if err := bindParams(stmt, values); err != nil {
			return err
		}
		switch C.sqlite3_step(stmt) {
		case C.SQLITE_ROW:
			n, found = int64(C.sqlite3_column_int64(stmt, 0)), true
		case C.SQLITE_DONE:
		default:
			return s.lastErr()
		}
		return nil
	})
	return n, found, err
}

func (s *Store) withStmt(sql string, fn func(*C.sqlite3_stmt) error) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var stmt *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(s.db, csql, -1, &stmt, nil); rc != C.SQLITE_OK {
		return s.lastErr()
	}
	defer C.sqlite3_finalize(stmt)
	return fn(stmt)
}

func (s *Store) lastErr() error {
	return errors.New(C.GoString(C.sqlite3_errmsg(s.db)))
}

// params are a statement's named parameters, without the leading ':'.
type params map[string]any

// bindParams binds every :name parameter in stmt from values.
func bindParams(stmt *C.sqlite3_stmt, values params) error {
	for i := 1; i <= int(C.sqlite3_bind_parameter_count(stmt)); i++ {
		name := strings.TrimPrefix(C.GoString(C.sqlite3_bind_parameter_name(stmt, C.int(i))), ":")
		switch v := values[name].(type) {
		case string:
			bindText(stmt, i, v)
		case []byte:
			bindBlob(stmt, i, v)
		case int64:
			C.sqlite3_bind_int64(stmt, C.int(i), C.sqlite3_int64(v))
		default:
			return fmt.Errorf("no value for SQL parameter :%s", name)
		}
	}
	return nil
}

func bindText(stmt *C.sqlite3_stmt, idx int, v string) {
	cv := C.CString(v)
	defer C.free(unsafe.Pointer(cv))
	C.sqlite3_bind_text(stmt, C.int(idx), cv, C.int(len(v)), C.SQLITE_TRANSIENT)
}

func bindBlob(stmt *C.sqlite3_stmt, idx int, v []byte) {
	if len(v) == 0 {
		// A nil blob pointer binds NULL; a zero-length zeroblob binds an empty BLOB.
		C.sqlite3_bind_zeroblob(stmt, C.int(idx), 0)
		return
	}
	C.sqlite3_bind_blob(stmt, C.int(idx), unsafe.Pointer(&v[0]), C.int(len(v)), C.SQLITE_TRANSIENT)
}

func stepDone(stmt *C.sqlite3_stmt) error {
	if rc := C.sqlite3_step(stmt); rc != C.SQLITE_DONE {
		return errors.New(C.GoString(C.sqlite3_errmsg(C.sqlite3_db_handle(stmt))))
	}
	return nil
}

// scanEntry reads a row in selectObjects' column order.
func scanEntry(stmt *C.sqlite3_stmt) entry {
	e := entry{
		Object: Object{
			Key:         columnText(stmt, 1),
			Size:        int(C.sqlite3_column_int64(stmt, 3)),
			ETag:        etagOf(columnBlob(stmt, 4)),
			ContentType: columnText(stmt, 5),
			Mtime:       int64(C.sqlite3_column_int64(stmt, 6)),
		},
		rowid:  int64(C.sqlite3_column_int64(stmt, 0)),
		stored: int(C.sqlite3_column_int64(stmt, 2)),
	}
	e.Compressed = e.stored > 0 && e.stored != e.Size
	if !e.Compressed {
		e.Size = e.stored
	}
	if e.ContentType == "" {
		e.ContentType = "application/octet-stream"
	}
	return e
}

// readLocked returns bytes [start, end) of the entry's object, reading only
// those. A compressed entry can only be read whole.
func (s *Store) readLocked(e entry, start, end int) ([]byte, error) {
	if start == end {
		return nil, nil
	}
	blob, err := s.openBlobLocked(e.rowid)
	if err != nil {
		return nil, err
	}
	defer blob.Close()
	if !e.Compressed {
		body := make([]byte, end-start)
		blob.off = start
		_, err := io.ReadFull(blob, body)
		return body, err
	}
	if start != 0 || end != e.Size {
		return nil, fmt.Errorf("key %q: compressed entries can only be read whole", e.Key)
	}
	body, err := inflate(blob, e.Size)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", e.Key, err)
	}
	return body, nil
}

// etagLocked computes the ETag of an entry without metadata from its data,
// which it reads in chunks rather than all at once.
func (s *Store) etagLocked(e entry) (string, error) {
	h := sha256.New()
	if e.stored > 0 {
		blob, err := s.openBlobLocked(e.rowid)
		if err != nil {
			return "", err
		}
		defer blob.Close()
		var r io.Reader = blob
		if e.Compressed {
			zr, err := zlib.NewReader(blob)
			if err != nil {
				return "", fmt.Errorf("key %q: inflate sqlar data: %w", e.Key, err)
			}
			r = io.LimitReader(zr, int64(e.Size)+1)
		}
		n, err := io.Copy(h, r)
		if err == nil && n != int64(e.Size) {
			err = fmt.Errorf("inflate sqlar data: got %d bytes, want %d", n, e.Size)
		}
		if err != nil {
			return "", fmt.Errorf("key %q: %w", e.Key, err)
		}
	}
	return etagOf(h.Sum(nil)), nil
}

// inflate returns a sqlar entry's zlib data, which must hold size bytes, and
// checks its checksum and length.
func inflate(data io.Reader, size int) ([]byte, error) {
	r, err := zlib.NewReader(data)
	if err != nil {
		return nil, fmt.Errorf("inflate sqlar data: %w", err)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("inflate sqlar data: %w", err)
	}
	if extra, err := io.Copy(io.Discard, r); err != nil {
		return nil, fmt.Errorf("inflate sqlar data: %w", err)
	} else if extra > 0 {
		return nil, fmt.Errorf("inflate sqlar data: got %d bytes, want %d", size+int(extra), size)
	}
	return body, nil
}

// blobReader reads a sqlar row's data incrementally, so only the database
// pages holding the bytes read are loaded.
type blobReader struct {
	blob *C.sqlite3_blob
	off  int
	size int
}

func (s *Store) openBlobLocked(rowid int64) (*blobReader, error) {
	db, table, column := C.CString("main"), C.CString("sqlar"), C.CString("data")
	defer C.free(unsafe.Pointer(db))
	defer C.free(unsafe.Pointer(table))
	defer C.free(unsafe.Pointer(column))
	var blob *C.sqlite3_blob
	if rc := C.sqlite3_blob_open(s.db, db, table, column, C.sqlite3_int64(rowid), 0, &blob); rc != C.SQLITE_OK {
		return nil, s.lastErr()
	}
	return &blobReader{blob: blob, size: int(C.sqlite3_blob_bytes(blob))}, nil
}

func (r *blobReader) Read(p []byte) (int, error) {
	n := min(len(p), r.size-r.off)
	if n <= 0 {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	if rc := C.sqlite3_blob_read(r.blob, unsafe.Pointer(&p[0]), C.int(n), C.int(r.off)); rc != C.SQLITE_OK {
		return 0, errors.New(C.GoString(C.sqlite3_errstr(rc)))
	}
	r.off += n
	return n, nil
}

func (r *blobReader) Close() {
	C.sqlite3_blob_close(r.blob)
}

func columnText(stmt *C.sqlite3_stmt, idx int) string {
	ptr := (*C.char)(unsafe.Pointer(C.sqlite3_column_text(stmt, C.int(idx))))
	if ptr == nil {
		return ""
	}
	return C.GoStringN(ptr, C.sqlite3_column_bytes(stmt, C.int(idx)))
}

func columnBlob(stmt *C.sqlite3_stmt, idx int) []byte {
	ptr := C.sqlite3_column_blob(stmt, C.int(idx))
	if ptr == nil {
		return nil
	}
	return C.GoBytes(ptr, C.sqlite3_column_bytes(stmt, C.int(idx)))
}

// etagOf returns the ETag served for a SHA-256 digest, or "" for no digest.
func etagOf(sum []byte) string {
	if len(sum) == 0 {
		return ""
	}
	return `"` + hex.EncodeToString(sum) + `"`
}

func quoteETag(body []byte) string {
	sum := sha256.Sum256(body)
	return etagOf(sum[:])
}

// etagMatches reports whether an If-Match header value, "*" or a
// comma-separated list of ETags, matches an existing object's ETag. Weak
// ETags (W/"...") never match, as If-Match uses the strong comparison.
func etagMatches(ifMatch, etag string) bool {
	return etagListMatches(ifMatch, etag, false)
}

// etagListMatches reports whether header, "*" or a comma-separated list of
// ETags, matches etag. weak allows W/"..." tags to match, for If-None-Match.
// Unquoted ETags are accepted, as S3 does.
func etagListMatches(header, etag string, weak bool) bool {
	want := strings.Trim(etag, `"`)
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" {
			return true
		}
		if strings.HasPrefix(tag, "W/") {
			if !weak {
				continue
			}
			tag = tag[2:]
		}
		if tag != "" && strings.Trim(tag, `"`) == want {
			return true
		}
	}
	return false
}

// conditions holds a GET or HEAD request's If-Match and If-None-Match
// header values, "" if absent.
type conditions struct {
	ifMatch, ifNoneMatch string
}

func requestConditions(r *http.Request) conditions {
	return conditions{ifMatch: r.Header.Get("If-Match"), ifNoneMatch: r.Header.Get("If-None-Match")}
}

// check returns errPreconditionFailed if If-Match doesn't match etag, or
// else errNotModified if If-None-Match does, as S3 does for GET and HEAD.
func (c conditions) check(etag string) error {
	if c.ifMatch != "" && !etagMatches(c.ifMatch, etag) {
		return errPreconditionFailed
	}
	if c.ifNoneMatch != "" && etagListMatches(c.ifNoneMatch, etag, true) {
		return errNotModified
	}
	return nil
}

func prefixUpperBound(prefix string) string {
	b := []byte(prefix)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return prefix + string(rune(0x10ffff))
}

func splitRequestPath(p string) (bucket, key string, bucketOnly bool, ok bool) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", "", false, false
	}
	bucket, key, hasKey := strings.Cut(p, "/")
	if bucket == "" {
		return "", "", false, false
	}
	return bucket, key, !hasKey || key == "", true
}

// validBucketName applies S3's naming rules for general purpose buckets:
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func validBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 || strings.Contains(name, "..") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && ((c != '.' && c != '-') || i == 0 || i == len(name)-1) {
			return false
		}
	}
	for _, reserved := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(name, reserved) {
			return false
		}
	}
	for _, reserved := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(name, reserved) {
			return false
		}
	}
	// Names formatted as IPv4 addresses, e.g. 192.168.5.4.
	labels := strings.Split(name, ".")
	if len(labels) != 4 {
		return true
	}
	for _, label := range labels {
		if strings.Trim(label, "0123456789") != "" {
			return true
		}
	}
	return false
}

// acceptRanges is the Accept-Ranges header for obj: a compressed entry ignores
// Range and is always sent whole.
func acceptRanges(obj Object) string {
	if obj.Compressed {
		return "none"
	}
	return "bytes"
}

func parseRangeHeader(header string, size int) (start, end int, partial bool, err error) {
	if header == "" {
		return 0, size, false, nil
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return 0, 0, false, errInvalidRange
	}
	spec := strings.TrimPrefix(header, "bytes=")
	left, right, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, false, errInvalidRange
	}
	switch {
	case left == "" && right == "":
		return 0, 0, false, errInvalidRange
	case left == "":
		suffix, err := strconv.Atoi(right)
		if errors.Is(err, strconv.ErrRange) && right[0] != '-' {
			// A suffix longer than any int still asks for the whole object.
			suffix, err = size, nil
		}
		if err != nil || suffix <= 0 || size == 0 {
			return 0, 0, false, errInvalidRange
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, size, true, nil
	case right == "":
		start, err := strconv.Atoi(left)
		if err != nil || start < 0 || start >= size {
			return 0, 0, false, errInvalidRange
		}
		return start, size, true, nil
	default:
		start, err := strconv.Atoi(left)
		if err != nil || start < 0 {
			return 0, 0, false, errInvalidRange
		}
		endInclusive, err := strconv.Atoi(right)
		if errors.Is(err, strconv.ErrRange) && right[0] != '-' {
			// An end beyond int range is past the object; clamp it like any other.
			endInclusive, err = math.MaxInt, nil
		}
		if err != nil || endInclusive < start || start >= size {
			return 0, 0, false, errInvalidRange
		}
		if endInclusive >= size-1 {
			return start, size, true, nil
		}
		return start, endInclusive + 1, true, nil
	}
}

func xmlSafeString(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != '\t' && r != '\n' && r != '\r' &&
			(r < 0x20 || r > 0xd7ff && r < 0xe000 || r > 0xfffd && r < 0x10000) {
			return false
		}
	}
	return true
}

// Query parameters featherd understands, or can safely ignore, per request kind.
// Anything else names an S3 subresource or option (?tagging, ?acl, ?uploadId,
// ?versionId, ...) that would otherwise be handled as a plain object
// operation, e.g. PUT ?tagging overwriting the object with the tagging XML.
var (
	listQueryParams   = map[string]bool{"list-type": true, "prefix": true, "start-after": true, "continuation-token": true, "max-keys": true, "encoding-type": true, "fetch-owner": true, "delimiter": true, "x-id": true}
	objectQueryParams = map[string]bool{"x-id": true}
)

// unsupportedRequest names the first S3 feature r relies on that featherd
// would otherwise silently mishandle, or returns "".
func unsupportedRequest(r *http.Request, bucketOnly bool) string {
	allowed := objectQueryParams
	if bucketOnly {
		allowed = listQueryParams
		if r.Method == http.MethodPut {
			// CreateBucket takes no query parameters; ?versioning, ?policy and
			// the like are other bucket operations.
			allowed = nil
		}
	}
	for name := range r.URL.Query() {
		lower := strings.ToLower(name)
		// Presigned URL parameters and GET response-header overrides don't affect stored data.
		if allowed[name] || strings.HasPrefix(lower, "x-amz-") || !bucketOnly && strings.HasPrefix(name, "response-") {
			continue
		}
		return "query parameter " + name
	}
	if bucketOnly && r.URL.Query().Get("delimiter") != "" {
		return "delimiter"
	}
	if bucketOnly && r.Method == http.MethodPut && strings.EqualFold(r.Header.Get("X-Amz-Bucket-Object-Lock-Enabled"), "true") {
		return "x-amz-bucket-object-lock-enabled"
	}
	if r.Method == http.MethodPut {
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			return "x-amz-copy-source"
		}
		if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") ||
			strings.HasPrefix(amzValue(r, "x-amz-content-sha256"), "STREAMING-") ||
			r.Header.Get("X-Amz-Decoded-Content-Length") != "" ||
			r.Header.Get("X-Amz-Trailer") != "" {
			return "aws-chunked payloads"
		}
	}
	return ""
}

// amzValues returns the non-empty values of the x-amz-* parameter name from
// the headers and then the query string. URL signatures are not checked.
func amzValues(r *http.Request, name string) []string {
	var values []string
	if v := r.Header.Get(name); v != "" {
		values = append(values, v)
	}
	for key, vs := range r.URL.Query() {
		if strings.EqualFold(key, name) {
			for _, v := range vs {
				if v != "" {
					values = append(values, v)
				}
			}
		}
	}
	return values
}

// amzValue returns the first of amzValues, or "".
func amzValue(r *http.Request, name string) string {
	if values := amzValues(r, name); len(values) > 0 {
		return values[0]
	}
	return ""
}

var crc64NVME = crc64.MakeTable(0x9a6c9329ac4bc9b5)

// checksumAlgorithms are S3's x-amz-checksum-* algorithms. Each value is the
// base64 of the big-endian digest.
var checksumAlgorithms = []struct {
	name string
	sum  func([]byte) []byte
}{
	{"CRC32", func(b []byte) []byte { return binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(b)) }},
	{"CRC32C", func(b []byte) []byte {
		return binary.BigEndian.AppendUint32(nil, crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	}},
	{"CRC64NVME", func(b []byte) []byte { return binary.BigEndian.AppendUint64(nil, crc64.Checksum(b, crc64NVME)) }},
	{"SHA1", func(b []byte) []byte { s := sha1.Sum(b); return s[:] }},
	{"SHA256", func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
}

// checkPayloadDigests verifies the body against Content-MD5, a hex
// x-amz-content-sha256 and any x-amz-checksum-* value, as S3 does, so a
// corrupted upload is not stored. The x-amz-* values may also come from the
// query string; every digest value given is checked.
func checkPayloadDigests(r *http.Request, body []byte) error {
	if want := r.Header.Get("Content-MD5"); want != "" {
		sum := md5.Sum(body)
		if want != base64.StdEncoding.EncodeToString(sum[:]) {
			return errBadDigest
		}
	}
	// Other values (UNSIGNED-PAYLOAD) carry no digest; STREAMING-* is rejected earlier.
	for _, want := range amzValues(r, "x-amz-content-sha256") {
		if len(want) != sha256.Size*2 {
			continue
		}
		sum := sha256.Sum256(body)
		if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
			return errSHA256Mismatch
		}
	}
	used := ""
	for _, alg := range checksumAlgorithms {
		param := "x-amz-checksum-" + strings.ToLower(alg.name)
		values := amzValues(r, param)
		if len(values) == 0 {
			continue
		}
		if used != "" {
			return invalidRequest("Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.")
		}
		used = alg.name
		sum := alg.sum(body)
		for _, want := range values {
			got, err := base64.StdEncoding.DecodeString(want)
			if err != nil || len(got) != len(sum) {
				return invalidRequest("Value for " + param + " header is invalid.")
			}
			if !bytes.Equal(got, sum) {
				return checksumMismatch(alg.name)
			}
		}
	}
	if sdk := amzValue(r, "x-amz-sdk-checksum-algorithm"); sdk != "" {
		if used == "" {
			return invalidRequest("x-amz-sdk-checksum-algorithm specified, but no corresponding x-amz-checksum-* or x-amz-trailer headers were found.")
		}
		if !strings.EqualFold(sdk, used) {
			return invalidRequest("Value for x-amz-sdk-checksum-algorithm header is invalid.")
		}
	}
	return nil
}

// listRequest is a parsed ListObjectsV2 request. Its fields are echoed back
// in the response.
type listRequest struct {
	Bucket            string
	Prefix            string
	StartAfter        string
	ContinuationToken string
	EncodingType      string
	MaxKeys           int
}

func writeListResult(w http.ResponseWriter, req listRequest, objects []Object, truncated bool) {
	encodingType := req.EncodingType
	if encodingType == "" && (!xmlSafeString(req.Prefix) || !xmlSafeString(req.StartAfter)) {
		encodingType = "url"
	}
	for _, obj := range objects {
		if !xmlSafeString(obj.Key) {
			encodingType = "url"
			break
		}
	}
	result := listBucketResult{
		Xmlns:             "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:              req.Bucket,
		Prefix:            req.Prefix,
		EncodingType:      encodingType,
		StartAfter:        req.StartAfter,
		ContinuationToken: req.ContinuationToken,
		KeyCount:          len(objects),
		MaxKeys:           req.MaxKeys,
		IsTruncated:       truncated,
		Contents:          make([]listContent, 0, len(objects)),
	}
	if encodingType == "url" {
		result.Prefix = url.QueryEscape(req.Prefix)
		result.StartAfter = url.QueryEscape(req.StartAfter)
	}
	if truncated && len(objects) > 0 {
		result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(objects[len(objects)-1].Key))
	}
	for _, obj := range objects {
		key := obj.Key
		if encodingType == "url" {
			key = url.QueryEscape(key)
		}
		result.Contents = append(result.Contents, listContent{
			Key:          key,
			LastModified: time.Unix(obj.Mtime, 0).UTC().Format(listTimeFormat),
			ETag:         obj.ETag,
			Size:         obj.Size,
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(result)
}

// Buckets gives the handler each bucket's database. Store returns
// errNoSuchBucket for a bucket that hasn't been created, and CreateBucket
// returns errBucketExists for one that has.
type Buckets interface {
	Store(bucket string) (*Store, error)
	CreateBucket(bucket string) error
}

// createBucketConfiguration is CreateBucket's optional request body. featherd
// has no regions, so LocationConstraint is accepted and ignored.
type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

const maxCreateBucketBodyBytes = 64 << 10

func createBucket(buckets Buckets, r *http.Request, bucket string) error {
	body, err := readCapped(r.Body, maxCreateBucketBodyBytes)
	if errors.Is(err, errObjectTooLarge) {
		return errMalformedXML
	} else if err != nil {
		return err
	}
	if err := checkPayloadDigests(r, body); err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := xml.Unmarshal(body, &createBucketConfiguration{}); err != nil {
			return errMalformedXML
		}
	}
	return buckets.CreateBucket(bucket)
}

// newHandler serves S3 requests against buckets.
func newHandler(buckets Buckets) http.Handler {
	// Not an http.ServeMux: it would redirect keys containing "//", "." or ".."
	// segments to a cleaned path, making those keys unreachable.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			writeNotImplemented(w, r, "ListBuckets")
			return
		}
		bucket, key, bucketOnly, ok := splitRequestPath(r.URL.Path)
		if !ok {
			writeError(w, r, http.StatusBadRequest, "InvalidURI", "Expected /bucket or /bucket/key.")
			return
		}
		if !validBucketName(bucket) {
			writeError(w, r, http.StatusBadRequest, "InvalidBucketName", "The specified bucket is not valid.")
			return
		}
		if len(key) > maxKeyBytes {
			writeError(w, r, http.StatusBadRequest, "KeyTooLongError", "Your key is too long.")
			return
		}
		if feature := unsupportedRequest(r, bucketOnly); feature != "" {
			writeNotImplemented(w, r, feature)
			return
		}
		if bucketOnly && r.Method != http.MethodPut && (r.Method != http.MethodGet || r.URL.Query().Get("list-type") != "2") {
			writeNotImplemented(w, r, "bucket operations other than CreateBucket and GET ?list-type=2")
			return
		}
		// Rejected before the bucket lookup, so bad requests are reported as
		// such whether or not the bucket exists.
		switch r.Method {
		case http.MethodPut, http.MethodGet, http.MethodHead, http.MethodDelete:
		default:
			writeError(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "The specified method is not allowed against this resource.")
			return
		}
		if bucketOnly && r.Method == http.MethodPut {
			if err := createBucket(buckets, r, bucket); err != nil {
				writeStoreResult(w, r, Object{}, err)
				return
			}
			w.Header().Set("Location", "/"+bucket)
			w.WriteHeader(http.StatusOK)
			return
		}
		store, err := buckets.Store(bucket)
		if err != nil {
			writeStoreResult(w, r, Object{}, err)
			return
		}
		if bucketOnly {
			query := r.URL.Query()
			req := listRequest{
				Bucket:            bucket,
				Prefix:            query.Get("prefix"),
				StartAfter:        query.Get("start-after"),
				ContinuationToken: query.Get("continuation-token"),
				EncodingType:      query.Get("encoding-type"),
				MaxKeys:           maxListKeys,
			}
			if req.EncodingType != "" && req.EncodingType != "url" {
				writeError(w, r, http.StatusBadRequest, "InvalidArgument", "Invalid Encoding Method specified in Request")
				return
			}
			if raw := query.Get("max-keys"); raw != "" {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed < 0 {
					writeError(w, r, http.StatusBadRequest, "InvalidArgument", "Provided max-keys not an integer or within integer range")
					return
				}
				req.MaxKeys = min(parsed, maxListKeys)
			}
			after := req.StartAfter
			if req.ContinuationToken != "" {
				decoded, err := base64.RawURLEncoding.DecodeString(req.ContinuationToken)
				if err != nil {
					writeError(w, r, http.StatusBadRequest, "InvalidArgument", "The continuation token provided is incorrect")
					return
				}
				after = string(decoded)
			}
			var objects []Object
			truncated := false
			if req.MaxKeys > 0 {
				var err error
				objects, truncated, err = store.List(bucket, req.Prefix, after, req.MaxKeys)
				if err != nil {
					writeStoreResult(w, r, Object{}, err)
					return
				}
			}
			writeListResult(w, req, objects, truncated)
			return
		}
		switch r.Method {
		case http.MethodPut:
			ifNoneMatch := r.Header.Get("If-None-Match")
			if ifNoneMatch != "" && ifNoneMatch != "*" {
				writeNotImplemented(w, r, "If-None-Match values other than *")
				return
			}
			body, err := readCapped(r.Body, store.maxObjectBytes)
			if err != nil {
				writeStoreResult(w, r, Object{}, err)
				return
			}
			if err := checkPayloadDigests(r, body); err != nil {
				writeStoreResult(w, r, Object{}, err)
				return
			}
			var ifMatch *string
			if h := r.Header.Get("If-Match"); h != "" {
				ifMatch = &h
			}
			obj, err := store.Put(bucket, key, body, r.Header.Get("Content-Type"), ifMatch, ifNoneMatch == "*")
			writeStoreResult(w, r, obj, err)
		case http.MethodHead:
			obj, err := store.Head(bucket, key)
			if err == nil {
				err = requestConditions(r).check(obj.ETag)
			}
			if err != nil {
				writeStoreResult(w, r, obj, err)
				return
			}
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", lastModifiedHeader(obj))
			w.Header().Set("Accept-Ranges", acceptRanges(obj))
			w.Header().Set("Content-Type", obj.ContentType)
			w.Header().Set("Content-Length", fmt.Sprint(obj.Size))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			obj, start, end, partial, err := store.GetRangeIf(bucket, key, r.Header.Get("Range"), requestConditions(r))
			if errors.Is(err, errInvalidRange) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", obj.Size))
				writeError(w, r, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "The requested range is not satisfiable")
				return
			}
			if err != nil {
				writeStoreResult(w, r, obj, err)
				return
			}
			body := obj.Body
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", lastModifiedHeader(obj))
			w.Header().Set("Accept-Ranges", acceptRanges(obj))
			w.Header().Set("Content-Type", obj.ContentType)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			if partial {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, obj.Size))
				w.WriteHeader(http.StatusPartialContent)
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			var ifMatch *string
			if h := r.Header.Get("If-Match"); h != "" {
				ifMatch = &h
			}
			if err := store.Delete(bucket, key, ifMatch); err != nil {
				writeStoreResult(w, r, Object{}, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

const usage = `usage: featherd [options]

  --addr ADDR              listen address (default 127.0.0.1:8333)
  --dir DIR                directory holding one sqlite database per bucket (default data)
  --max-object-bytes N     maximum object size in bytes (default 20971520)
  -h, --help               show this help
`

type options struct {
	addr           string
	dir            string
	maxObjectBytes int64
	help           bool
}

// parseArgs parses GNU-style options: long options take two dashes and a
// value as --name=value or --name value; a single dash introduces a cluster
// of one-letter boolean options, so -abc means -a -b -c.
func parseArgs(args []string) (options, error) {
	opts := options{addr: "127.0.0.1:8333", dir: "data", maxObjectBytes: defaultMaxObjectBytes}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			if i+1 < len(args) {
				return opts, fmt.Errorf("unexpected argument %q", args[i+1])
			}
		case strings.HasPrefix(arg, "--"):
			name, value, hasValue := strings.Cut(arg[2:], "=")
			if name == "help" {
				if hasValue {
					return opts, fmt.Errorf("option --help does not take a value")
				}
				opts.help = true
				continue
			}
			if name != "addr" && name != "dir" && name != "max-object-bytes" {
				return opts, fmt.Errorf("unknown option --%s", name)
			}
			if !hasValue {
				if i+1 >= len(args) {
					return opts, fmt.Errorf("option --%s requires a value", name)
				}
				i++
				value = args[i]
			}
			switch name {
			case "addr":
				opts.addr = value
			case "dir":
				opts.dir = value
			case "max-object-bytes":
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil || n <= 0 {
					return opts, fmt.Errorf("option --max-object-bytes needs a positive integer, got %q", value)
				}
				opts.maxObjectBytes = n
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			for _, c := range arg[1:] {
				switch c {
				case 'h':
					opts.help = true
				default:
					return opts, fmt.Errorf("unknown option -%c", c)
				}
			}
		default:
			return opts, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	return opts, nil
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "featherd: %v\n\n%s", err, usage)
		os.Exit(2)
	}
	if opts.help {
		fmt.Print(usage)
		return
	}

	dir, err := OpenDir(opts.dir, opts.maxObjectBytes)
	if err != nil {
		panic(err)
	}
	defer dir.Close()

	fmt.Printf("featherd listening on http://%s using %s/<bucket>.sqlite3\n", opts.addr, opts.dir)
	panic(http.ListenAndServe(opts.addr, newHandler(dir)))
}

func writeStoreResult(w http.ResponseWriter, r *http.Request, obj Object, err error) {
	var mismatch checksumMismatch
	var invalid invalidRequest
	switch {
	case err == nil:
		if obj.ETag != "" {
			w.Header().Set("ETag", obj.ETag)
		}
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, errNotFound):
		writeError(w, r, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
	case errors.Is(err, errNoSuchBucket):
		writeError(w, r, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
	case errors.Is(err, errBucketExists):
		writeError(w, r, http.StatusConflict, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.")
	case errors.Is(err, errMalformedXML):
		writeError(w, r, http.StatusBadRequest, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.")
	case errors.Is(err, errPreconditionFailed):
		writeError(w, r, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
	case errors.Is(err, errNotModified):
		// Like S3, a 304 has the object's validators but no body.
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Last-Modified", lastModifiedHeader(obj))
		w.WriteHeader(http.StatusNotModified)
	case errors.Is(err, errObjectTooLarge):
		// S3 reports EntityTooLarge as 400, not 413.
		writeError(w, r, http.StatusBadRequest, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
	case errors.Is(err, errBadDigest):
		writeError(w, r, http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what we received.")
	case errors.Is(err, errSHA256Mismatch):
		writeError(w, r, http.StatusBadRequest, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.")
	case errors.As(err, &mismatch):
		writeError(w, r, http.StatusBadRequest, "BadDigest", "The "+string(mismatch)+" you specified did not match the calculated checksum.")
	case errors.As(err, &invalid):
		writeError(w, r, http.StatusBadRequest, "InvalidRequest", string(invalid))
	default:
		writeError(w, r, http.StatusInternalServerError, "InternalError", err.Error())
	}
}

func writeNotImplemented(w http.ResponseWriter, r *http.Request, feature string) {
	writeError(w, r, http.StatusNotImplemented, "NotImplemented", "A header or query you provided implies functionality that is not implemented: "+feature)
}

// writeError sends an S3 XML error document. HEAD responses carry no body,
// as in S3, so clients see only the status.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	doc := s3Error{Code: code, Message: message, Resource: r.URL.Path}
	if bucket, key, _, ok := splitRequestPath(r.URL.Path); ok {
		doc.BucketName, doc.Key = bucket, key
	}
	body, err := xml.Marshal(doc)
	if err != nil {
		body = []byte("<Error><Code>InternalError</Code></Error>")
	}
	body = append([]byte(xml.Header), body...)
	w.Header().Set("Content-Type", "application/xml")
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func lastModifiedHeader(obj Object) string {
	return time.Unix(obj.Mtime, 0).UTC().Format(http.TimeFormat)
}

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errObjectTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errObjectTooLarge
	}
	return body, nil
}
