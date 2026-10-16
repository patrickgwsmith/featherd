# Fonts by version and by digest

Store official releases of open source fonts such as
[Inter](https://github.com/rsms/inter) in a `fonts` bucket, then fetch any
file either by family, version and path or by its SHA-256 digest.

`fonts.sh` needs only `curl` and `shasum`/`sha256sum`.

## Layout

```
fonts bucket  →  data/fonts.sqlite3
├── sha256/<hex>                one object per distinct file, keyed by its digest
└── <family>/<version>/SHA256SUMS
                                the release's paths and digests, in the format
                                `shasum -a 256 -c` reads
```

- File bytes are stored once. A file shipped unchanged in several releases,
  or under several paths in one release, is one `sha256/` object.
- Every write is create-if-absent (`If-None-Match: *`) with
  `x-amz-content-sha256`, so featherd rejects bytes that don't match their
  digest key, and releases can't be silently replaced. Re-running `put` with
  the same files is a no-op; putting different files under an existing
  version fails.
- `put` creates the bucket if it doesn't exist yet (`PUT /fonts`); a 409
  `BucketAlreadyOwnedByYou` just means it already does.
- Blobs are uploaded before the manifest, so a manifest never names a digest
  that isn't stored.
- Reads re-hash what they download before writing it out.

## Try it with Inter 4.1

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests

curl -LO https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip
unzip -q Inter-4.1.zip -d Inter-4.1

examples/fonts/fonts.sh put inter 4.1 Inter-4.1
# stored   sha256/693b77d4…  web/InterVariable.woff2
# …
# stored   inter/4.1/SHA256SUMS (152 files)
```

Look up by version:

```sh
examples/fonts/fonts.sh versions inter
# 4.1

examples/fonts/fonts.sh files inter 4.1 | grep 'web/InterVariable'
# 693b77d4…  web/InterVariable.woff2
# …

examples/fonts/fonts.sh get inter 4.1 web/InterVariable.woff2
# InterVariable.woff2  sha256:693b77d4…
```

Look up by digest:

```sh
examples/fonts/fonts.sh get-sha256 693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3 InterVariable.woff2

# Which releases ship this file, and under what path?
examples/fonts/fonts.sh find 693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3
# inter/4.1  web/InterVariable.woff2
```

Any S3 client or plain `curl` works too, since these are ordinary objects:

```sh
curl -s http://127.0.0.1:8333/fonts/inter/4.1/SHA256SUMS
curl -s http://127.0.0.1:8333/fonts/sha256/693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3 -o InterVariable.woff2
```

`get` and `get-sha256` write to stdout when the output is `-`.
`FEATHERD` (default `http://127.0.0.1:8333`) and `BUCKET` (default `fonts`)
choose the server and bucket.

## Querying the bucket's database directly

The bucket is a single SQLite file, so questions that HTTP listing can't
answer are one query away. For example, how much the deduplicated store
holds:

```sh
sqlite3 data/fonts.sqlite3 \
  "SELECT count(*), sum(sz) FROM sqlar WHERE name LIKE 'sha256/%'"
```

## Limits

- Family and version names are limited to letters, digits, `.`, `_` and
  `-`. Paths inside a release can be anything without a newline, since they
  only appear in the manifest.
- Files are limited by featherd's object cap (20 MiB by default). Inter's
  largest file, `Inter.ttc`, is 13 MB.
- If `put` fails partway, the blobs it uploaded stay. They're harmless, and
  re-running `put` finishes the job.
