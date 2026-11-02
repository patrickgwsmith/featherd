# CVE mirror

Mirror the CVE records in
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) into a
featherd bucket, one JSON object per CVE, at the same path as in the
repository. `cve-sync` is a standalone Go program (its own module, standard
library only). It writes through featherd's S3 API, so featherd stores each
record's sha256 ETag and `Content-Type: application/json` as it does for
any `PUT`.

It never clones the repository or parses git packs. It needs only HEAD's
commit, and after that everything is a plain file read from
raw.githubusercontent.com pinned to that commit:

```
cve-sync                    github.com / raw.githubusercontent.com      featherd
  │ GET mut/sync ─────────────────────────────────────────────────────────▶│ commit C0, fetch_time T0, ETag E
  │ GET cvelistV5.git/info/refs ──▶│ pkt-lines: "C1 HEAD"                   │
  │   (C1 == C0: up to date, stop)                                          │
  │ GET C1/cves/deltaLog.json ────▶│ newest delta first;                    │
  │   read until fetchTime <= T0, then hang up                              │
  │ for each record new or updated since T0, once, -parallel at a time:     │
  │   GET C1/cves/2026/120xxx/CVE-2026-120339.json ──▶│                     │
  │   PUT cves/2026/120xxx/CVE-2026-120339.json ──────────────────────────▶│
  │ PUT mut/sync commit=C1 fetch_time=T1   If-Match: E ───────────────────▶│ ← commit point
```

## Layout

```
cve bucket  →  data/cve.sqlite3
├── cves/{year}/{n/1000}xxx/CVE-{year}-{n}.json   one record, as in the repository
└── mut/sync                                     the commit and newest delta synced
```

```
commit=8c0afd8e6690f268088105f7052ff97a33553290
fetch_time=2026-11-02T04:16:50.952Z
synced_at=2026-11-02T04:18:49Z
```

## Consistency

- **Records first, state last.** `mut/sync` moves only after every record
  from the deltas it covers is stored. If a fetch or `PUT` fails, the state
  stays put, and the next run repeats those deltas. Storing a record again
  just replaces it.
- **One snapshot.** `deltaLog.json` and every record are read at the same
  commit. A record changed in several deltas is fetched once, at its newest
  version.
- **Two syncers** both store the same records; the second to write
  `mut/sync` gets 412 and reports it.
- **Keys come only from `recordPath`**, which accepts nothing but
  `cves/YYYY/NNNxxx/CVE-YYYY-N.json`, so `deltaLog.json` can't write
  anywhere else in the bucket.

## Limits

- `deltaLog.json` covers about 30 days. **A first sync without a seed**
  stores only the records changed in that time (about 29,000, one GitHub
  request each), not all 300,000+. Seed first instead.
- **A gap**: if a sync hasn't run for more than 30 days, the log no longer
  reaches back to `fetch_time`. cve-sync stores what the log has, moves on
  and reports the gap. To fill it, delete `mut/sync` and seed again.
- A record listed in a delta but missing at the commit is logged and
  skipped. cvelistV5 keeps rejected CVEs as records with
  `"state": "REJECTED"`, so nothing is deleted.
- Entries under `"error"` in a delta are counted, not fetched.

## Seeding from the midnight zip

Each of cvelistV5's hourly releases carries that day's
`*_all_CVEs_at_midnight.zip` (about 650 MB): a zip holding `cves.zip`,
which holds every record. `cve-sync -seed FILE` PUTs every record in it to
featherd, then writes `mut/sync` with `commit=seed` and a `fetch_time` an
hour before the newest record's `dateUpdated`. The next sync then applies
only the deltas after the snapshot, a few hours' worth, instead of 30 days.

```
make seed ──▶ api.github.com  releases/latest → the midnight zip's URL      (1 request)
          ──▶ github.com      download it to cache/, unless already there   (1 request)
          ──▶ featherd        PUT cves/…/CVE-….json for every record        (local)
          ──▶ featherd        PUT mut/sync  If-None-Match: *                 ← commit point
make sync ──▶ as above, from fetch_time
```

- The `fetch_time` comes from the records, not the zip's name, so any
  release's zip works, including the 0000Z one, which still carries the
  previous day's zip. The hour of margin covers skew between the clocks
  behind `dateUpdated` and `fetchTime`. Overlap only refetches a few records.
- **It refuses if `mut/sync` exists.** The zip's records are older than
  the ones a sync stored, so seeding over them would roll them back. To
  seed again, delete `mut/sync`. The sync after it catches up from the new
  snapshot.
- If a PUT fails, nothing is written to `mut/sync`, so running it again
  starts over. If a cve-sync writes `mut/sync` during the seed, the seed's
  `If-None-Match: *` fails and it says so.
- Only entries matching `cves/YYYY/NNNxxx/CVE-….json` are stored. The rest
  (`deltaLog.json`, `delta.json`) are counted and skipped.

## Try it

```sh
mkdir -p data && touch data/cve.sqlite3     # creates the cve bucket
FEATHERD_AUTH=none go run . --dir data &

cd examples/cve
make seed
# seed: downloading https://github.com/CVEProject/cvelistV5/releases/download/…_all_CVEs_at_midnight.zip.zip
# cve-sync: seed: 25000 of … records stored
# cve-sync: seeded … records (… other files skipped); the next sync applies deltas after …
make sync
# cve-sync: synced …: … deltas, … records stored, 0 missing, 0 upstream errors
make sync
# cve-sync: up to date at 8c0afd8e6690

curl -s http://127.0.0.1:8333/cve/cves/2024/3xxx/CVE-2024-3094.json
```

| target      | does                                                                  |
| ----------- | --------------------------------------------------------------------- |
| `make seed` | download the latest midnight zip to `cache/` (once) and seed from it  |
| `make sync` | `cve-sync -once`                                                      |
| `make run`  | `cve-sync`, syncing every 15 minutes                                  |
| `make test` | `go test`                                                             |
| `make clean`| remove the binary and `cache/`                                        |

`RELEASE=cve_2026-11-02_0100Z` picks another release's zip, `PARALLEL`
sets `-parallel`, and `CACHE` the download directory. `FEATHERD`, `BUCKET`
and the AWS keys pass through the environment.

To try the sync without seeding or the full 30 days, start from a few hours
ago:

```sh
printf 'commit=seed\nfetch_time=%s\n' "$(date -u -v-4H +%FT%TZ)" |
  curl -T - http://127.0.0.1:8333/cve/mut/sync
go run . -once
# cve-sync: synced 8c0afd8e6690: 21 deltas, 108 records stored, 0 missing, 0 upstream errors
```

Without `-once` it syncs every `-interval` (default 15 min). cvelistV5
commits about hourly. `FEATHERD`, `BUCKET` (default `cve`),
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` work as for
[rss-reader](../rss-reader/README.md).

## Deploying

`deploy.conf` deploys it with [`../deploy.sh`](../deploy.sh) to the `cve`
bucket:

```sh
git push exe main
ssh featherd.exe.xyz bash -s -- cve < examples/deploy.sh
```

Each run checks for `mut/sync`. If it's missing, the run first does
`make seed` and then deletes the zip, so the server needs about 650 MB free
once. Every run then does `cve-sync -once`, and `mut/sync` is published at
`:8000/cve/sync.txt`. Because the seed happens inside the first run, the
deploy's first run takes a few minutes.

## Notes

- `go test` here builds featherd from the repository root and runs it with
  SigV4 on, against a fake GitHub. It covers a first sync, an up-to-date
  run, a failed record leaving the state alone, a record missing at the
  commit, a gap, and two syncers racing on `mut/sync`. For seeding, it
  covers a nested zip like the release's, the sync picking up after it,
  refusing a synced bucket, and a bad record leaving no state.
- `s3.go` is rss-reader's client without LIST.
