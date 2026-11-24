// cve-sync mirrors the CVE records in github.com/CVEProject/cvelistV5 into
// a featherd bucket. Each run reads the repository's HEAD commit from
// git's info/refs, reads cves/deltaLog.json at that commit for the records
// changed since the last run, fetches just those from
// raw.githubusercontent.com pinned to the commit, and PUTs them through
// featherd's S3 API, so featherd stores each one's sha256 ETag and
// Content-Type.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "cve-sync:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("cve-sync", flag.ContinueOnError)
	once := fs.Bool("once", false, "sync once and exit")
	interval := fs.Duration("interval", 15*time.Minute, "time between syncs")
	parallel := fs.Int("parallel", 8, "records fetched at once")
	seedZip := fs.String("seed", "", "store every record in a midnight zip `file`, then exit")
	viewSize := fs.Int("view", 500, "CVEs in each view")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `usage: cve-sync [-once] [-interval 15m] [-parallel 8] [-view 500]
       cve-sync -seed FILE [-parallel 8]

-seed stores every record in one of cvelistV5's daily
*_all_CVEs_at_midnight.zip release assets, then sets mut/sync so the next
sync applies only the deltas since. It refuses if mut/sync exists.

Each sync also writes the newest new or updated CVEs to view/all.html
and, as an Atom feed, view/feed.xml, and the newest of those rated HIGH or
CRITICAL to view/index.html, the home page, and view/high.xml (and to
view/high.html, the page's old address). view/apple.html and
view/android.html, with feeds, list the newest CVEs those CNAs assigned,
linked to the Apple security notes and Android bulletins they cite, which
are mirrored as raw HTML under refs/. OSV's Android entries are mirrored
to refs/osv/Android/. view/linux.html lists the Linux kernel's newest HIGH
and CRITICAL CVEs, view/microsoft.html Microsoft's newest, and
view/chrome.html Chrome's, view/go.html Go's, view/apache.html the
Apache Software Foundation's, view/openssl.html OpenSSL's and
view/postgresql.html PostgreSQL's;
view/sqlite.html and view/nginx.html list those affecting SQLite and
nginx, which have no CNA of their own, by the products records name.
view/kev.html lists the CVEs added most recently to CISA's Known Exploited
Vulnerabilities catalog, fetched from both cisa.gov and
github.com/cisagov/kev-data, whichever released last, and each mirrored
raw under refs/. Each page has a line chart of the CVEs published on each
of the last 30 days, by severity (kev.html's, of those added to the
catalog), counted from mut/chart.

Environment:
  FEATHERD               featherd's URL (default http://127.0.0.1:8333)
  BUCKET                 the bucket (default cve)
  AWS_ACCESS_KEY_ID      with AWS_SECRET_ACCESS_KEY, sign requests with SigV4
  AWS_SECRET_ACCESS_KEY  for FEATHERD_AUTH=sigv4; unset for FEATHERD_AUTH=none

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *parallel < 1 || *interval <= 0 || *viewSize < 1 {
		fs.Usage()
		return flag.ErrHelp
	}
	s, err := newSyncer(getenv, *parallel)
	if err != nil {
		return err
	}
	s.viewSize = *viewSize

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *seedZip != "" {
		res, err := s.seed(ctx, *seedZip)
		if err != nil {
			return err
		}
		s.log.Print(res)
		return nil
	}
	for {
		res, err := s.sync(ctx)
		if err != nil {
			if *once || ctx.Err() != nil {
				return err
			}
			s.log.Printf("sync: %v", err)
		} else {
			s.log.Print(res)
		}
		if *once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*interval):
		}
	}
}

func newSyncer(getenv func(string) string, parallel int) (*syncer, error) {
	endpoint := getenv("FEATHERD")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8333"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("FEATHERD=%q is not an http(s) URL", endpoint)
	}
	bucket := getenv("BUCKET")
	if bucket == "" {
		bucket = "cve"
	}
	id, secret := getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY")
	if (id == "") != (secret == "") {
		return nil, errors.New("set both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or neither")
	}
	region := getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1" // featherd has no regions and accepts any
	}
	return &syncer{
		s3: &s3Client{
			endpoint: u, bucket: bucket,
			accessKeyID: id, secretAccessKey: secret, region: region,
			http: &http.Client{Timeout: 30 * time.Second},
			now:  time.Now,
		},
		// The first run reads all of deltaLog.json, about 35 MB.
		github: &http.Client{Timeout: 5 * time.Minute},
		// OSV's all.zip is about 10 MB.
		web:      &http.Client{Timeout: 2 * time.Minute},
		refsURL:  "https://github.com/CVEProject/cvelistV5.git/info/refs?service=git-upload-pack",
		rawBase:  "https://raw.githubusercontent.com/CVEProject/cvelistV5/",
		now:      time.Now,
		log:      log.New(os.Stderr, "cve-sync: ", log.LstdFlags),
		parallel: parallel,
		viewSize: 500,
	}, nil
}
