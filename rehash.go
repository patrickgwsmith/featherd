package main

/*
#include <sqlite3.h>
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"strings"
)

const (
	// A rehash commits after this many entries, or after hashing this many
	// bytes, so featherd's writers to the same file wait at most one batch,
	// well within busyTimeoutMS.
	rehashBatchEntries = 500
	rehashBatchBytes   = 64 << 20
)

const rehashUsage = `usage: featherd rehash [options] FILE...

Recomputes the SHA-256 digest of every object in each bucket database (a
SQLite Archive, e.g. data/<bucket>.sqlite3) and fixes content_meta: entries
without a row get one, with a content type guessed from the key's extension,
and rows whose digest doesn't match the data are corrected, keeping their
content type. It is safe to run while featherd serves the file.

  -n, --dry-run   report what would change without writing
  -v, --verbose   also list every entry given a new row
  -h, --help      show this help
`

type rehashOptions struct {
	dryRun  bool
	verbose bool
	help    bool
	files   []string
}

func parseRehashArgs(args []string) (rehashOptions, error) {
	var opts rehashOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			opts.files = append(opts.files, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(arg, "--"):
			name, _, hasValue := strings.Cut(arg[2:], "=")
			if name != "dry-run" && name != "verbose" && name != "help" {
				return opts, fmt.Errorf("unknown option --%s", name)
			}
			if hasValue {
				return opts, fmt.Errorf("option --%s does not take a value", name)
			}
			switch name {
			case "dry-run":
				opts.dryRun = true
			case "verbose":
				opts.verbose = true
			case "help":
				opts.help = true
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			for _, c := range arg[1:] {
				switch c {
				case 'n':
					opts.dryRun = true
				case 'v':
					opts.verbose = true
				case 'h':
					opts.help = true
				default:
					return opts, fmt.Errorf("unknown option -%c", c)
				}
			}
		default:
			opts.files = append(opts.files, arg)
		}
	}
	if len(opts.files) == 0 && !opts.help {
		return opts, errors.New("no database files given")
	}
	return opts, nil
}

// rehashResult counts what a rehash found. Added and Fixed are what it
// wrote, or with a dry run, what it would have.
type rehashResult struct {
	Entries int
	Bytes   int64
	OK      int
	Added   []string
	Fixed   []rehashFix
	Failed  []error
	// Rebuilt means content_meta was missing or untrusted (its triggers were
	// absent), so every entry was given a fresh row.
	Rebuilt bool
	// NoArchive means the file has no sqlar table, so there was nothing to do.
	NoArchive bool
}

type rehashFix struct {
	Key      string
	Was, Now string // ETags
}

// Rehash recomputes the digest of every regular file in the archive and
// writes the content_meta rows that are missing or wrong. Each batch is its
// own transaction, so an entry written between batches already has fresh
// metadata from featherd, or none, which a later run fills in.
func (s *Store) Rehash(dryRun bool) (rehashResult, error) {
	var res rehashResult
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return res, err
	}
	if !s.hasSQLAR {
		// Don't turn an empty or unrelated database into an archive.
		res.NoArchive = true
		return res, nil
	}
	res.Rebuilt = !s.metaTrusted

	after := ""
	for {
		last, done, err := s.rehashBatchLocked(after, dryRun, &res)
		if err != nil {
			return res, err
		}
		if done {
			return res, nil
		}
		after = last
	}
}

// rehashBatchLocked handles the entries after the key after, in one
// transaction, returning the last key it handled and whether none were left.
func (s *Store) rehashBatchLocked(after string, dryRun bool, res *rehashResult) (string, bool, error) {
	if dryRun {
		if err := s.exec("BEGIN"); err != nil {
			return "", false, err
		}
		if err := s.inspectLocked(); err != nil {
			_ = s.exec("COMMIT")
			return "", false, err
		}
	} else if err := s.beginWriteLocked(); err != nil {
		// Creates content_meta and its triggers if they're missing, dropping
		// an untrusted content_meta first.
		return "", false, err
	}
	committed := false
	defer func() {
		if !committed {
			s.rollbackLocked()
		}
	}()

	var entries []entry
	err := s.withStmt(selectObjects(s.metaTrusted, `s.name > :after AND `+sqlarFile+`
ORDER BY s.name
LIMIT :limit`), func(stmt *C.sqlite3_stmt) error {
		if err := bindParams(stmt, params{"after": after, "limit": int64(rehashBatchEntries)}); err != nil {
			return err
		}
		for {
			switch C.sqlite3_step(stmt) {
			case C.SQLITE_ROW:
				entries = append(entries, scanEntry(stmt))
			case C.SQLITE_DONE:
				return nil
			default:
				return s.lastErr()
			}
		}
	})
	if err != nil {
		return "", false, err
	}

	var hashed int64
	last := after
	for _, e := range entries {
		if hashed >= rehashBatchBytes {
			break
		}
		last = e.Key
		hashed += int64(e.stored)
		res.Entries++
		res.Bytes += int64(e.Size)

		sum, err := s.digestLocked(e)
		if err != nil {
			res.Failed = append(res.Failed, err)
			continue
		}
		now := etagOf(sum)
		contentType := e.ContentType
		switch {
		case e.ETag == now:
			res.OK++
			continue
		case e.ETag == "":
			contentType = guessContentType(e.Key)
			res.Added = append(res.Added, e.Key)
		default:
			res.Fixed = append(res.Fixed, rehashFix{Key: e.Key, Was: e.ETag, Now: now})
		}
		if dryRun {
			continue
		}
		if err := s.execParams(putMetaSQL, params{"key": e.Key, "sha256": sum, "content_type": contentType}); err != nil {
			return "", false, err
		}
	}
	if err := s.exec("COMMIT"); err != nil {
		return "", false, err
	}
	committed = true
	return last, len(entries) == 0, nil
}

// guessContentType returns the content type for a key's extension, or
// featherd's default.
func guessContentType(key string) string {
	if t := mime.TypeByExtension(path.Ext(key)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// runRehash is `featherd rehash`, returning the exit status.
func runRehash(args []string, stdout, stderr io.Writer) int {
	opts, err := parseRehashArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "featherd rehash: %v\n\n%s", err, rehashUsage)
		return 2
	}
	if opts.help {
		fmt.Fprint(stdout, rehashUsage)
		return 0
	}
	status := 0
	for _, file := range opts.files {
		if err := rehashFile(file, opts, stdout); err != nil {
			fmt.Fprintf(stderr, "featherd rehash: %s: %v\n", file, err)
			status = 1
		}
	}
	return status
}

func rehashFile(file string, opts rehashOptions, stdout io.Writer) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}
	store, err := OpenStore(file)
	if err != nil {
		return err
	}
	defer store.Close()
	res, err := store.Rehash(opts.dryRun)

	var out bytes.Buffer
	verb := map[bool]string{false: "", true: "would be "}[opts.dryRun]
	if res.Rebuilt && !res.NoArchive {
		fmt.Fprintf(&out, "%s: content_meta missing or untrusted, %srebuilt\n", file, verb)
	}
	for _, f := range res.Fixed {
		fmt.Fprintf(&out, "%s: %s: digest %scorrected from %s to %s\n", file, f.Key, verb, f.Was, f.Now)
	}
	if opts.verbose {
		for _, k := range res.Added {
			fmt.Fprintf(&out, "%s: %s: metadata %sadded\n", file, k, verb)
		}
	}
	for _, e := range res.Failed {
		fmt.Fprintf(&out, "%s: %v\n", file, e)
	}
	if res.NoArchive {
		fmt.Fprintf(&out, "%s: no sqlar table, nothing to rehash\n", file)
	} else {
		fmt.Fprintf(&out, "%s: %d entries (%d bytes): %d correct, %d %sadded, %d %scorrected, %d unreadable\n",
			file, res.Entries, res.Bytes, res.OK, len(res.Added), verb, len(res.Fixed), verb, len(res.Failed))
	}
	_, _ = stdout.Write(out.Bytes())
	if err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return fmt.Errorf("%d entries could not be read", len(res.Failed))
	}
	return nil
}
