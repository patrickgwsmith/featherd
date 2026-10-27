// rss-reader polls the feeds listed in a featherd bucket's
// config/subscriptions.opml, stores each post once under const/, keeps each
// feed's state under mut/, and writes the newest posts to view/index.html.
// It talks to featherd only over its S3 API, so featherd enforces every
// conditional write.
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
		fmt.Fprintln(os.Stderr, "rss-reader:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("rss-reader", flag.ContinueOnError)
	once := fs.Bool("once", false, "poll once and exit")
	interval := fs.Duration("interval", 15*time.Minute, "time between polls")
	viewSize := fs.Int("view", 25, "number of posts in view/index.html")
	parallel := fs.Int("parallel", 4, "feeds fetched at once")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `usage: rss-reader [-once] [-interval 15m] [-view 25] [-parallel 4]

Environment:
  FEATHERD               featherd's URL (default http://127.0.0.1:8333)
  BUCKET                 the bucket (default rss)
  AWS_ACCESS_KEY_ID      with AWS_SECRET_ACCESS_KEY, sign requests with SigV4
  AWS_SECRET_ACCESS_KEY  for FEATHERD_AUTH=sigv4; unset for FEATHERD_AUTH=none

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *viewSize < 1 || *parallel < 1 || *interval <= 0 {
		fs.Usage()
		return flag.ErrHelp
	}
	r, err := newReader(getenv, *viewSize, *parallel)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		res, err := r.poll(ctx)
		if err != nil {
			if *once || ctx.Err() != nil {
				return err
			}
			r.log.Printf("poll: %v", err)
		} else {
			r.log.Printf("polled %d feeds: %d fetched, %d not modified, %d failed, %d waiting; %d new posts, %d feeds retired",
				res.Feeds, res.Fetched, res.NotModified, res.Failed, res.Skipped, res.Added, res.Retired)
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

func newReader(getenv func(string) string, viewSize, parallel int) (*reader, error) {
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
		bucket = "rss"
	}
	id, secret := getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY")
	if (id == "") != (secret == "") {
		return nil, errors.New("set both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or neither")
	}
	region := getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1" // featherd has no regions and accepts any
	}
	return &reader{
		s3: &s3Client{
			endpoint: u, bucket: bucket,
			accessKeyID: id, secretAccessKey: secret, region: region,
			http: &http.Client{Timeout: 30 * time.Second},
			now:  time.Now,
		},
		origins:  &http.Client{Timeout: 30 * time.Second},
		now:      time.Now,
		log:      log.New(os.Stderr, "rss-reader: ", log.LstdFlags),
		viewSize: viewSize,
		parallel: parallel,
	}, nil
}
