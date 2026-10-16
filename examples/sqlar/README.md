# SQLite Archives as buckets

Every featherd bucket is a [SQLite Archive](https://sqlite.org/sqlar.html), so
an archive made with the `sqlite3` shell is a bucket too: put it in the data
directory as `<bucket>.sqlite3` and featherd serves its files as objects. No
`CreateBucket` and no upload step are needed.

`sqlar.sh` wraps the few commands involved, and needs only `sqlite3` and
`curl`.

## Try it with a static site

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests

mkdir -p site/css
echo '<link rel=stylesheet href=css/site.css><p>hello</p>' > site/index.html
echo 'p { color: teal }' > site/css/site.css

examples/sqlar/sqlar.sh pack site site
# /…/data/site.sqlite3: 2 files, 70 bytes

examples/sqlar/sqlar.sh ls site
# css/site.css
# index.html

examples/sqlar/sqlar.sh get site index.html -
# <link rel=stylesheet href=css/site.css><p>hello</p>
```

`pack` is just `sqlite3 -A -c` run inside the directory, so keys are paths
relative to it:

```sh
(cd site && sqlite3 ../data/site.sqlite3 -A -c *)
```

Running `sqlite3 data/site.sqlite3 -A -c -C site .` instead would prefix every
key with `./`.

Any HTTP client can read the bucket, including byte ranges:

```sh
curl -s http://127.0.0.1:8333/site/css/site.css
curl -s -r 0-3 http://127.0.0.1:8333/site/index.html
curl -s 'http://127.0.0.1:8333/site?list-type=2'
```

## Change it while featherd is running

featherd notices changes the next time it reads, so there's no need to stop it:

```sh
echo '<p>hello again</p>' > site/index.html
examples/sqlar/sqlar.sh update site site     # sqlite3 -A -u
examples/sqlar/sqlar.sh get site index.html -
# <p>hello again</p>
```

`update` adds new files and replaces changed ones, but doesn't remove deleted
files. A file counts as changed when its mtime, in whole seconds, differs from
the archive's, so an edit made in the same second as the last `pack` is
skipped. `pack` again to replace everything in the bucket. Both write the
archive in place, never as a new file renamed over the old one: featherd keeps
the bucket's file open, so it would keep serving the replaced file.

Objects can also be written over HTTP as usual. The archive is still an
ordinary one afterwards, and featherd's extra `content_meta` table (content
types and digests) doesn't get in the way of the `sqlite3` shell.

## Get the files back

```sh
examples/sqlar/sqlar.sh unpack site out     # sqlite3 -A -x -C out
sqlite3 data/site.sqlite3 -A -t -v          # list with sizes and dates
```

## What to expect

- **Compression.** `sqlite3 -A` zlib-compresses a file when that makes it
  smaller. featherd inflates these files on read, but always whole: a `Range`
  request for one gets the whole file with a 200 and `Accept-Ranges: none`.
  Files that don't compress, like images and fonts, are stored as they are,
  so ranges read only the requested bytes. Files featherd itself writes are
  never compressed.
- **Metadata.** A file added by `sqlite3` is served as
  `application/octet-stream`, with `Last-Modified` from its mtime and an ETag
  computed from its contents. When `sqlite3` overwrites an object featherd
  wrote, the object's content type is dropped too, so its ETag always matches
  its data.
- **Directories and symlinks** in the archive aren't objects. They don't
  appear in listings and return `NoSuchKey`.
- **Reading never changes the file.** featherd opens the archive read-only
  until the first write over HTTP, so a write-protected archive, or one on
  read-only storage, can be served as is.
- `FEATHERD` (default `http://127.0.0.1:8333`) and `DATA` (default `data`)
  choose the server and data directory. `pack` and `update` skip dotfiles.
  `get` sends the key as is, so keys with spaces or `?` need URL-encoding.
