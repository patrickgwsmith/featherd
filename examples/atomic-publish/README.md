# Publish a release atomically

Publish a directory of files, such as a static site, a config bundle or a
set of feature flags, so that every reader sees either the whole old
release or the whole new one. Copying the files over the old ones in place
gets several things wrong, and each one is easy to miss:

- **Torn reads.** A reader that loads `index.html` from the new release and
  `site.css` from the old one, or a config reader that gets half of each.
- **Lost deploys.** Two CI jobs publish at once, or a slow job for an older
  commit finishes after a newer one, and silently replaces it.
- **Rollback races.** A rollback overwrites a publish that landed while
  the person rolling back was reading the old state.
- **Deleting what's still needed.** Cleanup removes the release that is
  current, the one a rollback is about to switch to, or one a reader is
  still loading.
- **Corruption.** A truncated upload ends up live.

featherd has no transactions across keys, so the release is made atomic
the usual way: upload every file under a new prefix that nothing reads yet,
then switch one small pointer with compare-and-swap. It's the same idea as
a `current` symlink swapped with `rename`, or a Git branch moved with
`--force-with-lease`.

`publish.sh` needs `curl` and `openssl`, plus `sqlite3` for `gc`.

## Layout

```
site bucket  →  data/site.sqlite3
├── current                        {"release", "previous", "floor", "updated_at", "host"}
├── manifests/<release>            "<sha256>  <path>" per file, as sha256sum prints it
└── releases/<release>/<path>      the files, never changed once written
                                   release: UTC start of the publish and a random suffix,
                                   e.g. 20261013T141502Z-9f2c4e1a
```

Release IDs start with the time, so they sort by age as strings, and all
the releases older than a given one are one range of sqlar's `name` key.

## Flow

1. **Publish.**
   1. `GET current` and remember its release as the base.
   2. `PUT` every file to `releases/<new>/<path>` with `If-None-Match: *`,
      so a release is never written twice, and with
      `x-amz-checksum-sha256`, which featherd checks before storing
      anything, so a truncated upload is rejected.
   3. `PUT manifests/<new>` last. A release with a manifest is complete.
   4. **Switch.** `GET current` again. If its release is no longer the base,
      someone published in the meantime, so stop. Otherwise `PUT current`
      with the new release, the base as `previous`, and `If-Match: <etag>`.
      Of all the publishers that read the same pointer, only one gets 200.
      The others get 412 and read the pointer again: if gc only raised the
      floor, they retry; if the release changed, they stop.
   A publisher that stops leaves its release complete and unused. You can
   roll back to it to publish it anyway, or leave it for gc, which deletes
   it once a later release moves the floor past it.
2. **Read.** Resolve `current` once, then read every file of that request,
   page or config load from `releases/<release>/`. Files of a release never
   change, so they can be cached forever. Resolving each file separately
   would bring torn reads back.
3. **Roll back.** The same switch, with the old release as the target:
   `GET current`, check that the target's manifest exists, and `PUT` with
   `If-Match`. A publish that landed in between makes it fail, so it doesn't
   undo a release nobody looked at.
4. **Garbage-collect.** featherd has no TTLs, so a cron job deletes old
   releases straight from the bucket's database. It keeps the newest `KEEP`
   releases, the current one and anything published in the last `MINUTES`,
   so a reader that resolved `current` a moment ago can finish. The oldest
   release it keeps is the **floor**, and the floor is written into
   `current` with `If-Match` *before* anything is deleted:
   - a rollback that read the pointer earlier gets 412, reads the new floor,
     and refuses to switch to a release below it;
   - a publish whose ID is below the floor (a slow job, or a skewed clock)
     refuses to switch to it.

   The floor never goes down, and gc deletes only below it, in one
   transaction:

   ```sql
   DELETE FROM sqlar WHERE name >= 'manifests/' AND name < 'manifests/<floor>';
   DELETE FROM sqlar WHERE name >= 'releases/' AND name < 'releases/<floor>';
   ```

   That also removes the files of publishes that crashed before writing
   their manifest. The `sqlar_delete_drops_meta` trigger removes the
   matching `content_meta` rows, so ETags stay right.

## Try it

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests

mkdir -p v1/css v2/css
echo '<h1>v1</h1>' >v1/index.html; echo 'a{color:red}' >v1/css/site.css
echo '<h1>v2</h1>' >v2/index.html; echo 'a{color:blue}' >v2/css/site.css

examples/atomic-publish/publish.sh publish v1
# publish.sh: published 2 files as 20261013T065702Z-251188e1, replacing nothing
examples/atomic-publish/publish.sh publish v2
# publish.sh: published 2 files as 20261013T065703Z-1c78e451, replacing 20261013T065702Z-251188e1

examples/atomic-publish/publish.sh cat index.html
# <h1>v2</h1>
examples/atomic-publish/publish.sh fetch out   # the whole current release, checked against its manifest
# publish.sh: fetched 2 files of 20261013T065703Z-1c78e451 into out

examples/atomic-publish/publish.sh rollback
# publish.sh: rolled back from 20261013T065703Z-1c78e451 to 20261013T065702Z-251188e1

for i in 1 2 3; do examples/atomic-publish/publish.sh publish v2 >/dev/null & done; wait
# publish.sh: published 2 files as 20261013T065704Z-04ab75eb, replacing 20261013T065702Z-251188e1
# publish.sh: current moved from 20261013T065702Z-251188e1 to 20261013T065704Z-04ab75eb while this ran; not replacing it (…)
# publish.sh: current moved from 20261013T065702Z-251188e1 to 20261013T065704Z-04ab75eb while this ran; not replacing it (…)

examples/atomic-publish/publish.sh releases
# 20261013T065704Z-d7945168
# 20261013T065704Z-265dbff1
# 20261013T065704Z-04ab75eb current
# 20261013T065703Z-1c78e451
# 20261013T065702Z-251188e1

examples/atomic-publish/publish.sh gc 2 0
# publish.sh: deleted 2 releases (4 files) below 20261013T065704Z-04ab75eb
examples/atomic-publish/publish.sh rollback
# publish.sh: no complete release 20261013T065702Z-251188e1
```

Run `gc` from cron, e.g. hourly. It uses the `sqlite3` shell alongside
featherd, as in [`examples/sqlar`](../sqlar), and waits up to 5 s if
featherd is writing.

## Notes

- A publish fails rather than overwriting a release it didn't start from.
  Run it again to publish on top of the new release. Retrying
  automatically would bring the lost-deploy problem back.
- Readers that hold a release ID for longer than `MINUTES` (default 60)
  can find it deleted, and should resolve `current` again on a 404.
- Paths are limited to letters, digits and `._-/`, with no empty, `.` or
  `..` segments. Symlinks and other special files are refused, not skipped,
  so nothing is left out silently.
- The pointer guards against lost updates, not against rolling back to a
  release that is broken. Point `rollback` at a release you know is good.
- There's no server-side copy, so every publish uploads every file, even
  unchanged ones. That keeps gc a pair of range deletes, with no reference
  counting between releases.
- `TestAtomicPublish` in `atomicpublish_test.go` tests the pattern: of two
  publishers that read the same pointer only one wins, a rollback that read
  the pointer before gc raised the floor gets 412, and gc deletes only the
  releases below the floor.
- `FEATHERD` (default `http://127.0.0.1:8333`), `BUCKET` (default `site`)
  and `DATA` (default `data`) choose the server, the bucket and the
  directory holding its database.
