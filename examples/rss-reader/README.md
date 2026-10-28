# RSS reader

Poll the RSS and Atom feeds you subscribe to, keep every post once, and
write the newest 25 to a web page. featherd holds everything: your
subscriptions, each feed's state, the posts and the page. `rss-reader` is a
standalone Go program (its own module, standard library only) that talks
to featherd over the S3 API, so featherd checks every conditional write.

Its one output is `view/index.html`. Serving that page publicly is left
open for now: featherd's `FEATHERD_AUTH` covers every key, so a browser
can't read it unsigned unless featherd runs with `FEATHERD_AUTH=none`.
Put a GET-only proxy for `view/` in front, or copy the page to a static host.
[`../deploy.sh`](../deploy.sh) does the second on a Linux server:
`ssh <host> bash -s -- rss-reader < examples/deploy.sh`.

## Layout

Each prefix has its own write rule:

```
rss bucket  →  data/rss.sqlite3
├── config/subscriptions.opml           you edit it; rss-reader only reads it
├── mut/feeds/{host}-{hash(url)}        one feed's state, key=value lines
├── const/seen/{hash(url+guid)}         write-once: the post's date key, first seen
├── const/items/{invTS}/{hash(url+guid)}  write-once: one post, as an Atom <entry>
└── view/index.html                     the newest 25, rebuilt from const/items/
```

| prefix    | create             | replace              | delete               |
| --------- | ------------------ | -------------------- | -------------------- |
| `config/` | any `PUT`          | any `PUT`            | any                  |
| `mut/`    | `If-None-Match: *` | `If-Match: "<etag>"` | `If-Match: "<etag>"` |
| `const/`  | `If-None-Match: *` | never                | never                |
| `view/`   | any `PUT` by the one reader; rebuilt from `const/`  | | |

rss-reader keeps these rules itself. featherd doesn't enforce them yet: an
opt-in such as `FEATHERD_IMMUTABLE_PREFIXES=const/` that refuses overwrites
and deletes there is a proposal.

- **Posts.** RSS 2.0, RSS 1.0 and Atom are all converted to one format, an
  Atom `<entry>` with a `<source>` naming the feed, so the log and the view
  read one format. A post is identified by its RSS `<guid>` or Atom `<id>`,
  else its link, hashed together with the feed's URL so two feeds can't
  collide.
- **`invTS`** is `9999999999` minus the post's Unix time, zero-padded, so
  `LIST const/items/` returns the newest first and the view is one `LIST
  max-keys=25` and 25 `GET`s in parallel. The time is the post's published
  date (else updated, else now), capped at now so a misdated post can't
  stay on top.
- **`const/seen/`** keeps a post at one key. Feeds re-date posts, which
  would give them a new `invTS` and store them twice. So the first store
  writes the post's `invTS` to `const/seen/{hash}`, and later fetches reuse
  it.

## Feed states

```
     URL in config/, no mut/feeds/ object
                  │
              ┌───▼───┐
              │  New  │
              └───┬───┘ poll
                  ▼
 ┌────────── Polling (rss-reader's memory only) ─────┐
 │ Fetching ──304─────────────────────▶ Committing   │
 │    │ 200                                  ▲       │
 │    ▼                                      │       │
 │ Storing posts ──all PUTs 200 or 412───────┘       │
 │    (timeout, HTTP error, parse error, PUT error ─▶ fail)
 └────────┬──────────────────────────┬───────────────┘
     ok   ▼                    fail  ▼
      ┌──────┐   fail        ┌──────────┐  failing for 7 days  ┌──────┐
      │ Idle │──────────────▶│  Failed  │─────────────────────▶│ Dead │
      │      │◀──────────────│ backoff  │                      └──┬───┘
      └──────┘   ok          └──────────┘                         │
          ▲                    config/subscriptions.opml changes  │
          └───────────────────────────────────────────────────────┘
  any state ── URL removed from config/ ──▶ Retired (state deleted with
                                             If-Match; its posts stay)
```

Only Idle, Failed and Dead are stored. A crash while polling leaves the
last stored state, so the next poll repeats the work, and the posts already
stored come back as 412.

```
state=idle
url=https://feeds.macrumors.com/MacRumors-All
etag="mr-v2"
last_modified=Mon, 26 Oct 2026 08:58:00 GMT
last_ok=2026-10-26T09:00:00Z
```

```
state=failed
url=https://example.com/feed
etag="x-v1"
last_ok=2026-10-25T21:00:00Z
n=3
first_failed_at=2026-10-26T06:00:00Z
last_failed_at=2026-10-26T09:00:00Z
error=HTTP 502
retry_at=2026-10-26T10:00:00Z
```

- **Failed** keeps the last good `etag` and `last_modified`, so the retry is
  still a conditional fetch. `retry_at` backs off 15 min, 30 min, 1 h, …
  up to a day.
- **Dead** is decided by `first_failed_at`, not `n`, so a feed that fails
  often but briefly isn't killed. A dead feed records the ETag of
  `config/subscriptions.opml`, and is tried once more whenever that changes.
- A 304 from an Idle feed writes nothing.

## A refresh

MacRumors has two new posts, Daring Fireball hasn't changed, and a third
feed is down:

```
rss-reader         origins                         featherd
  │ GET config/subscriptions.opml ────────────────────▶│
  │ GET mut/feeds/feeds.macrumors.com-… ──────────────▶│ idle, "mr-v1", ETag E1
  │ GET MR, If-None-Match: "mr-v1" ▶│                  │
  │◀─ 200, "mr-v2", 30 posts        │                  │
  │ for each post:                                     │
  │   PUT const/seen/{h}   If-None-Match: * ──────────▶│ 28 × 412, 2 × 200
  │   (412: GET const/seen/{h} for its invTS)          │
  │   PUT const/items/{invTS}/{h}   If-None-Match: * ─▶│ 28 × 412, 2 × 200
  │ PUT mut/feeds/… state=idle etag="mr-v2"            │
  │                       If-Match: E1 ───────────────▶│ ← MR's commit point
  │                                                    │
  │ GET mut/feeds/daringfireball.net-… ───────────────▶│ idle, "df-v1"
  │ GET DF, If-None-Match: "df-v1" ▶│                  │
  │◀─ 304                           │  write nothing   │
  │                                                    │
  │ GET X ─────────────────────────▶│ 502              │
  │ PUT mut/feeds/… state=failed n=1 retry_at=+15m     │
  │                       If-Match: E3 ───────────────▶│
  │                                                    │
  │ (posts were added, so rebuild the view)            │
  │ LIST const/items/ max-keys=25 → GET ×25 ──────────▶│
  │ PUT view/index.html ──────────────────────────────▶│
```

## Consistency

S3 has no multi-key transactions, so each `PUT` stands alone and the order
of the writes does the work:

1. **Posts first.** Each is write-once, so storing it again does nothing.
   The seen object comes before the item: if rss-reader stops between
   them, the next fetch finds the seen object and writes the item at its
   key.
2. **The feed's state last.** It's the commit point: it moves to the
   origin's new ETag only after every post from that fetch is stored. If
   anything fails first, it keeps the old ETag, so the next poll fetches
   the same content again.
3. **The view afterwards.** It's rebuilt from `const/`, so it can lag or
   fail without losing anything.

Two pollers at once are safe: each post is still stored once, and for a
feed's state one gets 200 and the other 412, which it logs and leaves.

## Try it

```sh
mkdir -p data && touch data/rss.sqlite3    # creates the rss bucket
FEATHERD_AUTH=none go run . --dir data &

curl -T examples/rss-reader/subscriptions.opml \
  http://127.0.0.1:8333/rss/config/subscriptions.opml

cd examples/rss-reader
go run . -once
# rss-reader: polled 2 feeds: 2 fetched, 0 not modified, 0 failed, 0 waiting; 68 new posts, 0 feeds retired
go run . -once
# rss-reader: polled 2 feeds: 1 fetched, 1 not modified, 0 failed, 0 waiting; 0 new posts, 0 feeds retired

curl -s 'http://127.0.0.1:8333/rss?list-type=2&prefix=mut/'
curl -s http://127.0.0.1:8333/rss/view/index.html > /tmp/index.html && open /tmp/index.html
```

A bucket is just the file `<dir>/<bucket>.sqlite3`, and featherd adds its
schema on the first write, so an empty file is enough. If featherd is
already running, `curl -X PUT http://127.0.0.1:8333/rss` does the same.

MacRumors sends `Last-Modified` but no `ETag`, and answers 200 anyway, so
the second poll fetches it again and every post comes back as 412. Daring
Fireball answers 304.

Without `-once` it polls every `-interval` (default 15 min) until stopped.
Export your subscriptions from Unread or any reader as OPML and upload them
in place of the sample.

With `FEATHERD_AUTH=sigv4`, set `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` to featherd's key pair and rss-reader signs its
requests. `FEATHERD` (default `http://127.0.0.1:8333`) and `BUCKET`
(default `rss`) choose the server and the bucket.

## Notes

- `go test` in this directory builds featherd from the repository root and
  runs it with SigV4 on, against fake origins. `TestRefresh` covers the
  walkthrough above, a re-dated post keeping its key, the backoff, Dead and
  its revival, and retiring a feed. `TestCrashBetweenSeenAndItem` covers a
  stop between the seen object and the item.
- A changed feed costs up to three requests per post it already has (the
  seen `PUT`, its `GET`, the item `PUT`), all answered by featherd locally.
- Reading the newest posts could be one read-only SQL query on
  `data/rss.sqlite3` instead of a LIST and 25 GETs, but every write should
  still go through featherd so its conditional checks apply.
- Posts are kept forever; there's no pruning.
