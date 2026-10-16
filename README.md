# featherd

featherd is a tiny SQLite-backed object store for small objects.

It is exploring a KISS subset of S3-shaped storage:

- one Go executable
- one SQLite database per bucket, at `<dir>/<bucket>.sqlite3`
- object bodies stored as SQLite BLOBs
- default object cap: 20 MiB
- strong single-node consistency through serialized SQLite transactions
- compare-and-swap writes with ETags

## Install

With Go 1.26 or newer:

```sh
go install github.com/patrickgwsmith/featherd@latest
```

This puts a `featherd` binary in `$(go env GOPATH)/bin`. Start it with
`featherd --dir data` with `FEATHERD_AUTH` set to `sigv4` (plus a key pair) or
`none`; see
[Authentication](#authentication) and [Run](#run).

## Current Contract

featherd currently supports:

- `PUT /{bucket}` (`CreateBucket`): returns 200 with `Location: /{bucket}`,
  or 409 `BucketAlreadyOwnedByYou` if the bucket exists. An optional
  `CreateBucketConfiguration` body is accepted, and its `LocationConstraint`
  ignored, since featherd has no regions; malformed XML returns 400
  `MalformedXML`
- `PUT /{bucket}/{key}`
- `GET /{bucket}/{key}`
- `HEAD /{bucket}/{key}`
- `DELETE /{bucket}/{key}`
- `GET /{bucket}?list-type=2&prefix={prefix}` with `max-keys` (capped at
  1000), `start-after`, `continuation-token` pagination, and
  `encoding-type=url` (also applied automatically when XML cannot represent a key)
- `If-None-Match: *` for create-if-absent (other `If-None-Match` values on
  `PUT` are rejected with 501 rather than ignored)
- `If-Match: "<etag>"` for compare-and-swap writes and deletes
- `If-Match: *` for update-if-present writes and deletes
- conditional `GET` and `HEAD`: `If-Match` (`*` or a list of ETags) returns
  412 `PreconditionFailed` when nothing matches, and `If-None-Match` (`*` or a
  list of ETags, weak `W/"…"` allowed) returns 304 Not Modified, with the
  object's `ETag` and `Last-Modified`, when one does. They are checked before
  `Range` and before any data is read
- single byte-range reads with `Range: bytes=start-end`, which read only the
  requested bytes from SQLite (except for zlib-compressed entries, below)
- `Content-MD5`, hex `x-amz-content-sha256` and base64 `x-amz-checksum-*`
  (`crc32`, `crc32c`, `crc64nvme`, `sha1`, `sha256`) are verified on `PUT`; a
  mismatch returns 400 (`BadDigest` or `XAmzContentSHA256Mismatch`) and
  nothing is stored. The `x-amz-*` values are also read from the query
  string, including presigned URLs.
  A malformed checksum, more than one checksum algorithm, or an
  `x-amz-sdk-checksum-algorithm` without its
  matching checksum returns 400 `InvalidRequest`. Checksums are not stored or
  returned on `GET`
- S3 XML error documents (`<Error><Code>…</Code><Message>…</Message>…`) with
  S3's codes, e.g. `NoSuchKey`, `PreconditionFailed`, `InvalidRange`,
  `EntityTooLarge` (400, as in S3) and `NotImplemented`; `HEAD` errors carry
  only the status, as in S3
- S3's general purpose bucket naming rules (3–63 characters of lowercase
  letters, digits, `.` and `-`; starting and ending with a letter or digit;
  no `..`; not an IPv4 address; no reserved prefixes such as `xn--` or
  suffixes such as `-s3alias`), enforced on every request with 400
  `InvalidBucketName`
- keys of at most 1024 UTF-8 bytes; longer keys return 400 `KeyTooLongError`

Requests that depend on unsupported S3 features return 501 rather than being
treated as plain object operations: subresource query parameters such as
`?tagging`, `?acl`, `?uploadId` or `?versionId`, a non-empty `delimiter`,
`x-amz-copy-source`, `x-amz-website-redirect-location`, `aws-chunked` streaming bodies and `x-amz-trailer`
checksums, object lock on
`CreateBucket`, and bucket operations other than `CreateBucket` and
`GET ?list-type=2` (including `ListBuckets` on `/` and `DeleteBucket`).

Successful writes are durable SQLite commits before the server acknowledges
success. Each bucket's operations are serialized through that bucket's mutex,
so competing CAS writers observe a single linear order. The tests assert that concurrent
create-if-absent and concurrent `If-Match` writes have exactly one winner.

As in S3, a bucket must be created with `CreateBucket` before use;
`CreateBucket` creates the bucket's database file. Object `PUT`, `GET`,
`HEAD`, `DELETE` and listing on a bucket that has no database file return 404
`NoSuchBucket` (`HEAD` with no body) and create no file. Each
bucket's database is an ordinary SQLite Archive, described below, so
it can be copied, backed up or queried with `sqlite3` on its own.

## Authentication

`FEATHERD_AUTH` is required and names the mode, so it's always written down
where featherd is deployed:

- **`FEATHERD_AUTH=sigv4`** requires every request to be signed with the key
  pair in `FEATHERD_ACCESS_KEY_ID` and `FEATHERD_SECRET_ACCESS_KEY` using
  [SigV4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html),
  as S3 checks it. Clients use the same pair as their `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`. Both must be set.
- **`FEATHERD_AUTH=none`** serves every request without authentication:
  anyone who can reach the listen address can read and write every object, so
  bind to a trusted interface. Neither key variable may be set.

featherd refuses to start (exit code 2) if `FEATHERD_AUTH` is unset, has any
other value, or doesn't match the key variables, so a missing or misspelled
variable can't leave it open.

- **Both forms are checked.** A signature can be in the `Authorization`
  header or in a presigned URL's `X-Amz-*` query parameters, but not both
  (400 `InvalidArgument`). Requests are checked before anything else,
  including the bucket name, and before the body is read.
- **What the signature covers.** The method, path, query string, `host`,
  every `x-amz-*` header sent (an unsigned one returns 403 `AccessDenied`),
  any other headers the client chose to sign, and `x-amz-content-sha256`.
  Header-signed requests must send `x-amz-content-sha256` (400
  `InvalidRequest` if missing). On writes, a hex digest there is checked
  against the body, as above, so the body is covered too; `UNSIGNED-PAYLOAD`
  leaves it uncovered, and presigned URLs are `UNSIGNED-PAYLOAD` unless they
  sign a digest.
- **Time limits.** A header-signed request's `X-Amz-Date` must be within 15
  minutes of the server's clock (403 `RequestTimeTooSkewed`). A presigned URL
  is valid from `X-Amz-Date` (15 minutes' leeway) until `X-Amz-Expires`
  seconds later, at most 7 days (403 `AccessDenied`, "Request has expired").
- **Any region.** featherd has no regions, so the credential scope may name
  any region, but its service must be `s3`.
- **Errors** use S3's codes: `AccessDenied` for unsigned requests,
  `InvalidAccessKeyId`, `SignatureDoesNotMatch`,
  `AuthorizationHeaderMalformed` and `AuthorizationQueryParametersError`.

curl can sign requests itself:

```sh
curl --aws-sigv4 aws:amz:us-east-1:s3 \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  http://127.0.0.1:8333/fonts/inter/4.1/SHA256SUMS
```

There is one key pair, with access to every bucket. Signing doesn't
encrypt anything, so serve featherd over TLS, e.g. behind a reverse proxy,
whenever requests cross an untrusted network: a signed request seen in
transit can be replayed until its time limit runs out.
`TestSigV4AWSExamples` checks the signatures against the examples in AWS's
documentation.

## Storage

Each bucket is a [SQLite Archive](https://sqlite.org/sqlar.html) (`schema.sql`):
a `sqlar` table holding the data, uncompressed, plus a `content_meta` table
keyed by name for `sha256` (the raw 32-byte digest the ETag is derived from)
and `content_type`. So
`sqlite3 data/fonts.sqlite3 -A -t -v` lists a bucket and
`sqlite3 data/fonts.sqlite3 -A -x -C out` extracts it.

- **Any archive can be served.** Copy it to `<dir>/<bucket>.sqlite3`.
  zlib-compressed data is inflated, but always whole: `Range` is ignored and
  the response is a 200 with `Accept-Ranges: none`. An entry without a `content_meta` row is
  served with an ETag computed from its data, `application/octet-stream` and
  its `mtime`, and directory and symlink entries are not objects.
- **Reading never modifies a bucket.** featherd opens each database read-only,
  so `GET`, `HEAD`, listing and deleting a missing key leave the file
  untouched, and a write-protected file can still be served. The first write
  reopens it read-write and creates `content_meta` and its triggers, in the
  same transaction as the write. A new bucket's file stays empty until then.
  The one exception is a write that crashed partway: the next read reopens
  the file read-write so SQLite can roll the write back.
- **No WAL.** featherd keeps SQLite's default rollback journal, so the
  `.sqlite3` file alone holds every committed write, with no `-wal` or
  `-shm` files beside it. If another tool switches a bucket to WAL, which
  isn't supported, featherd keeps using WAL: it can't open the bucket for
  reads until something with write access has created the `-wal` and `-shm`
  files, and writes can stay in `-wal` after featherd stops. Run
  `sqlite3 bucket.sqlite3 'PRAGMA journal_mode = DELETE'` to switch back.
  `TestServesDatabaseSwitchedToWAL` checks this.
- **No stale ETags.** Triggers drop an entry's `content_meta` row whenever
  anything writes the entry, including `sqlite3 -A`. If the triggers are
  missing, e.g. after `sqlite3 -A -c` recreated the archive, featherd ignores
  `content_meta` and drops it at the next write.

## Not S3 Yet

featherd does not yet claim full S3 compatibility.

Missing pieces include:

- more than one key pair, and per-bucket or per-key permissions
- SigV4 with the `Date` header instead of `X-Amz-Date`, signed `aws-chunked`
  streaming uploads, and SigV4a; the older SigV2 isn't planned
- delimiters/common prefixes
- multipart upload
- `If-Modified-Since` and `If-Unmodified-Since` (ignored, so the read
  proceeds as if they were absent)
- bucket management APIs other than `CreateBucket`
- object versioning (TODO): keep `sqlar` as the current version, so
  `sqlite3 -A` still sees an ordinary archive, and record history in a
  separate `object_versions` table (`name`, `version_id`, `mtime`, `sz`,
  `data`, `sha256`, `content_type`, `is_delete_marker`) filled by `sqlar`
  UPDATE/DELETE triggers alongside the `content_meta` ones, so overwrites by
  the CLI are captured too. On top of that: a per-bucket Enabled/Suspended
  setting via `PUT`/`GET ?versioning`, `x-amz-version-id` on `PUT` and `GET`,
  `GET`/`HEAD`/`DELETE ?versionId=`, delete markers on plain `DELETE`,
  `GET ?versions`, and version ID `null` for objects written before
  versioning was enabled. Every overwrite keeps a full copy until lifecycle
  pruning exists, and `sqlite3 -A -c` would turn every row into history.
- write-access proof (TODO), like ACME's HTTP-01 challenge: a verifier gives
  an actor a random nonce, the actor writes it to
  `.well-known/challenge/<nonce>` in the bucket with the root key or a
  presigned `PUT`, and the verifier reads it back through a presigned `GET`
  (over TLS) and checks the content. The key and a short expiry are fixed in
  the signed URL so it can't be replayed elsewhere. Until there are
  per-actor scoped credentials it only proves the root key approved the
  write, not that a particular actor has access.

The goal is to grow compatibility by declaring a small subset, testing it
against real clients, and only then expanding the contract.

## Run

The schema is embedded in the executable, so it can run outside the source
directory.

Require signed requests (see [Authentication](#authentication)), with a
secret made once by e.g. `openssl rand -hex 32` and given to clients too:

```sh
FEATHERD_AUTH=sigv4 \
FEATHERD_ACCESS_KEY_ID=featherd \
FEATHERD_SECRET_ACCESS_KEY=<secret> \
  go run . \
  --addr 127.0.0.1:8333 \
  --dir data
```

Or, on a trusted machine, serve every request without authentication:

```sh
FEATHERD_AUTH=none go run . --dir data
```

Set a smaller cap while testing:

```sh
FEATHERD_AUTH=none go run . --max-object-bytes 10485760
```

Long options take two dashes, with the value after a space or `=`
(`--dir data` and `--dir=data` are the same). A single dash groups one-letter
flags, so `-addr` is rejected as `unknown option -a`. Run `go run . -h` for the
full list.

## Examples

- [`examples/atomic-publish`](examples/atomic-publish): publish a
  directory, such as a static site, so readers see the whole old release
  or the whole new one. The `current` pointer is switched with `If-Match`,
  which stops one publisher from overwriting another, and old releases are
  deleted below a floor that rollbacks can't cross.
- [`examples/claim-once`](examples/claim-once): claim a key per (subject,
  time window) with `If-None-Match: *`, e.g. one confirmation email per
  address every 15 minutes, one run of a cron job per day or hour across
  many workers, and sweep old claims.
- [`examples/fonts`](examples/fonts): store official font releases (e.g.
  Inter) and look files up by version or by SHA-256 digest.
- [`examples/sqlar`](examples/sqlar): pack a directory into a bucket with
  `sqlite3 -A`, serve and update it while featherd runs, and unpack it again.
- [`examples/tz`](examples/tz): serve the IANA time zone database, one
  object per zone, and look zones up by name or country.

## Test

```sh
go test ./...
```

Benchmark the store:

```sh
go test -run '^$' -bench Store -benchmem -count=6
```
