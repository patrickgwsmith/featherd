# RSS reader, Node and QIP

This is the [`rss-reader`](../rss-reader) example rebuilt as a Node host
with four [QIP](https://qip.dev) components written in Odin. It uses the
same bucket layout, write rules and feed statechart, and the item keys and
state files match the Go version's. Read that README for the design; this
one covers how the work is split.

```
host (Node, no npm dependencies)          QIP components (Odin → .wasm, no imports)
────────────────────────────────          ─────────────────────────────────────────
GET config/subscriptions.opml ──────────▶ opml-to-uri-list
                              ◀────────── text/uri-list

GET mut/feeds/{key} (validators)
GET origin, If-None-Match / -Modified-Since
wrap the response as one WARC record ───▶ feed-to-entries   (uniform now_unix_seconds)
                              ◀────────── multipart/form-data: one part per
                                          post, named {invTS}/{hash}, holding
                                          an Atom <entry>
PUT const/seen/{hash}, const/items/{invTS}/{hash}   If-None-Match: *

state lines + event lines ──────────────▶ feed-state        (uniform now_unix_seconds)
                              ◀────────── next state lines, or nothing
PUT mut/feeds/{key}   If-Match / If-None-Match: *    ← the commit point

LIST + GET ×25 const/items/, wrapped
as one Atom <feed> ─────────────────────▶ atom-to-html      (uniform now_unix_seconds)
                              ◀────────── text/html
PUT view/index.html
```

The host owns every request, the clock and the order of the writes. The
components see only the bytes they're given, so parsing untrusted feed XML
happens in a sandbox with fixed memory and nothing to reach. A component
can't break the `const/` and `mut/` rules, because it can't make a request.
The clock reaches it only as the `now_unix_seconds` uniform, so each call
is deterministic: the same input and time always give the same output.

## The components

Each one follows QIP's [Content contract](https://qip.dev/docs/content-component):
it exports its memory, `input_ptr`, its input and output capacities and
content types, and `render`. Bad input gets a recoverable rejection with an
offset and a failure mode, not a trap.

| component | input | output | notes |
| --- | --- | --- | --- |
| `opml-to-uri-list` | `text/x-opml` | `text/uri-list` | every `<outline xmlUrl>` at any depth, deduplicated, http(s) only |
| `feed-to-entries` | `application/warc` | `multipart/form-data` | RSS 2.0, RSS 1.0, Atom; UTF-8 or Latin-1; up to 8 MiB |
| `feed-state` | state + event lines | state lines | Idle, Failed with backoff, Dead after 7 days |
| `atom-to-html` | `application/atom+xml` | `text/html` | escapes everything; keeps only http(s) links |

- **Why WARC.** Uniforms are numeric only, so the feed's URL can't be one.
  A WARC response record carries the URL with the origin's response, and
  QIP already uses WARC. The URL resolves relative links, names the
  `<source>` and goes into each post's hash.
- **The multipart boundary** is QIP's UUID slot. The host writes a fresh
  UUID into it before each render, so a post can't forge a part delimiter.
  The component rejects any post that contains the delimiter anyway.
- **`feed-to-entries` names each part with its key**, `{invTS}/{hash}`:
  `9999999999` minus the post's Unix time (capped at `now_unix_seconds`),
  then the first 32 hex digits of SHA-256(feed URL + `"\n"` + guid, id or
  link). That's the same key the Go reader uses for the same post.
- **`feed-state`'s input** is the stored state, a blank line, then the
  event: `event=fetched` with `etag=` and `last_modified=`,
  `event=not_modified`, or `event=failed` with `error=` and `config=`.
  Each event also has `url=`. A New feed has no state lines, so its input
  starts with the blank line. Empty output means there's nothing to write.
  The host still reads `state`, `retry_at`, `config` and the validators
  itself, to decide whether a feed is due and to make the conditional
  fetch.
- **`atom-to-html`** takes the newest posts as one Atom `<feed>`. The host
  just concatenates the stored `<entry>` objects, so the view is a pure
  function of `const/items/`.

`components/shared` holds what they have in common: a lenient XML scanner,
entity decoding, tag stripping, RFC 822 and RFC 3339 dates, and a bounded
writer. Nothing allocates. Every buffer is a fixed global, and running out
of room is a rejection, not a truncated result.

## Try it

You need Odin, to build the components, and Node 22 or later.

```sh
cd examples/rss-reader-qip
make            # builds build/*.wasm

# In the repository root:
mkdir -p data && touch data/rss.sqlite3    # creates the rss bucket
FEATHERD_AUTH=none go run . --dir data &
curl -T examples/rss-reader-qip/subscriptions.opml \
  http://127.0.0.1:8333/rss/config/subscriptions.opml

node rss-reader.mjs --once
# rss-reader: … polled 2 feeds: 2 fetched, 0 not modified, 0 failed, 0 waiting; 68 new posts, 0 feeds retired
node rss-reader.mjs --once
# rss-reader: … polled 2 feeds: 1 fetched, 1 not modified, 0 failed, 0 waiting; 0 new posts, 0 feeds retired
```

A bucket is just the file `<dir>/<bucket>.sqlite3`, and featherd adds its
schema on the first write, so an empty file is enough. If featherd is
already running, `curl -X PUT http://127.0.0.1:8333/rss` does the same.

The flags and environment are the Go reader's: `--once`, `--interval 15m`,
`--view 25`, `--parallel 4`, `FEATHERD`, `BUCKET`, and
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` for `FEATHERD_AUTH=sigv4`.

Each component also runs on its own with `qipx`, QIP's Node CLI, so
nothing needs installing:

```sh
npx @qip.dev/qipx run build/opml-to-uri-list.wasm < subscriptions.opml
printf 'state=idle\nurl=https://example.com/feed\netag="v1"\n\nevent=failed\nurl=https://example.com/feed\nerror=HTTP 502\n' |
  npx @qip.dev/qipx run build/feed-state.wasm -u now_unix_seconds=1793000000
npx @qip.dev/qipx comply build/*.wasm   # or: make comply
```

`now_unix_seconds` is an i64 uniform; without `-u` it defaults to 0
(1970). The host passes the current time itself. Setting it needs qipx 0.5.0 or later.

## Tests

`make test` builds the components, then runs `node --test`. Like the Go
tests, they build featherd from the repository root, run it with SigV4 on,
and serve fake feeds:

- `refresh` is the Go reader's walkthrough: a re-dated post keeps its key,
  the backoff, Dead and its revival, and retiring a feed.
- `crash between seen and item` checks that a missing item is repaired at
  the key recorded in `const/seen/`.
- The other tests call the components directly: feed formats and Latin-1,
  keys matching the Go reader's, rejections, the boundary changing between
  renders, state transitions, and OPML.

## Compared with the Go version

- Run on the same two real feeds in separate buckets, both readers stored
  the same 68 item keys and wrote a byte-identical `view/index.html`. The
  stored `<entry>` objects hold the same data, though the XML is escaped
  differently, and the Node reader omits the XML declaration. Both readers
  can share a bucket: the view strips that declaration from posts the Go
  reader stored.
- The Go reader is 1,750 lines and uses only its standard library. This
  version is about 3,500: 1,100 for the Node host and its tests, and 2,400
  of Odin, because Odin's freestanding target has no XML parser, date
  parser or URL resolver to lean on. The four `.wasm` files total about
  110 KB.
- HTML entities: Go's `html.UnescapeString` knows all of HTML5's, while
  `shared/text.odin` knows the forty or so feeds use most. Unknown ones are
  left as written.
- Links are resolved per RFC 3986 by `feed-to-entries`, and checked
  against WHATWG `URL` for the usual cases. Go's `net/url` normalises a
  little more.
