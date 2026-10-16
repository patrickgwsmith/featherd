# Claim once per window

Create a key named by (subject, UTC time window) only if it doesn't exist
yet. Whoever creates it has the claim, and everyone else in that window is
turned away. With featherd that's one request: `PUT` with
`If-None-Match: *` returns 200 if this request created the key and 412 if
it already existed. It's the same idea as an `INSERT` into a primary key,
Redis `SET NX` or an S3 conditional `PUT`. HTTP is only how featherd exposes it.

The example here is newsletter sign-up: send at most one confirmation email
per address every 15 minutes, and subscribe the address when its link is
clicked. The same pattern covers password-reset and magic-link tokens,
idempotency keys (key = request ID) and leases. The second example,
[cron jobs](#cron-jobs-once-per-day-or-hour), runs a job once per UTC day or
hour however many workers start it. [`examples/webhook-once`](../webhook-once)
applies the same claim to webhooks, handling each event once however many
times it's delivered.

`claim.sh` needs `curl` and `openssl`, plus `sqlite3` for `sweep`.
`run-once.sh` needs `curl`, plus `sqlite3` for `sweep`.

## Layout

```
claims bucket  →  data/claims.sqlite3
├── pending/<window>/<hmac>    {"email", "token_sha256", "used"}
│                              window: UTC start of the 15 minutes, e.g. 20261013T1415
│                              hmac: HMAC-SHA256(CLAIM_SECRET, email), in hex
└── subscribers/<email>        {"email", "confirmed_at"}
```

The window comes before the HMAC so that keys sort by time. Zero-padded UTC
timestamps sort as strings, so a whole day of claims is one range of
sqlar's `name` primary key. The HMAC keeps addresses out of the pending
keys. The token is stored only as its SHA-256, so reading the bucket
doesn't give you working links.

## Flow

1. **Claim.** `PUT pending/<window>/<hmac>` with `If-None-Match: *` and the
   token's hash. 200: email the link `/confirm?k=<window>/<hmac>&t=<token>`.
   412: one was already sent this window, so send nothing.
2. **Confirm.** Check that `k` is exactly a window and 64 hex digits so a
   link can't name any other key, and reject it once the window start plus
   `TTL` has passed. Expiry comes from the key, so it isn't stored. `GET`
   the claim, which also returns its ETag, and compare the token's hash.
   A 404 or a mismatch means the link is invalid. If the claim is already
   `used`, report success.
3. **Subscribe.** `PUT subscribers/<email>` with `If-None-Match: *`. A 412
   means an earlier link subscribed the address, which is still success.
4. **Mark used.** `PUT` the claim back with `"used": true` and
   `If-Match: <etag>`. Don't delete it: the key has to stay until the window
   is long past, or another email could be sent straight away.
5. **Sweep.** featherd has no TTLs, so a cron job deletes old claims straight
   from the bucket's database with a single range delete on the name index:

   ```sql
   DELETE FROM sqlar WHERE name >= 'pending/' AND name < 'pending/<yesterday>'
   ```

   This keeps yesterday and today, much more than one `TTL`. The
   `sqlar_delete_drops_meta` trigger removes the matching `content_meta`
   rows, so ETags stay right.

Each step is a single-key atomic operation. A crash between steps 3 and 4
leaves the claim unused, and clicking the link again finishes the job,
because every step is safe to repeat.

## Try it

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests
export CLAIM_SECRET=$(openssl rand -hex 32)

link=$(examples/claim-once/claim.sh claim ann@example.com)
echo "$link"
# /confirm?k=20261013T1415/e2724f22…d049&t=c6eb1a2a…8c84

examples/claim-once/claim.sh claim ann@example.com
# claim.sh: already sent to ann@example.com in window 20261013T1415 UTC; try again in 11 min

examples/claim-once/claim.sh confirm "$link"
# confirmed ann@example.com
examples/claim-once/claim.sh confirm "$link"
# ann@example.com already confirmed

examples/claim-once/claim.sh ls
# pending/20261013T1415/e2724f22…d049
# subscribers/ann@example.com

examples/claim-once/claim.sh sweep
# deleted 0 claims from before 20261012
```

Run `sweep` from cron, e.g. hourly. It uses the `sqlite3` shell alongside
featherd, as in [`examples/sqlar`](../sqlar), and waits up to 5 s if
featherd is writing.

## Cron jobs: once per day or hour

Put the same crontab on several machines, and each job still runs once per
period. Every worker claims `runs/<job>/<period>` with `If-None-Match: *`,
and only the one that gets 200 runs the job. The period is just the claim's
window, so the period's format picks how often the job runs:

```
jobs bucket  →  data/jobs.sqlite3
└── runs/<job>/<period>    {"status", "host", "started", "attempt", "finished", "exit"}
                           daily:  20261013       (%Y%m%d, UTC)
                           hourly: 20261013T14    (%Y%m%dT%H, UTC)
```

Daily and hourly keys both start with the day, so they sort together and a
day of runs is one range of the name index, whichever period a job uses.
The key isn't secret this time, so the job name goes in as is: it's one key
segment, which keeps every run of a job under `runs/<job>/` and lets
`history` list them by prefix.

1. **Claim.** `PUT runs/<job>/<period>` with `If-None-Match: *` and
   `"status": "running"`. 200: run the job.
2. **Someone else has it.** On 412, `GET` the record and its ETag.
   `done`: skip. `running` and started less than `LEASE` ago: skip.
   `running` for longer, meaning the worker probably crashed, or `failed`:
   take it over by `PUT`ting a new `running` record with `If-Match: <etag>`.
   Every worker that read the same record sends the same ETag, so only one
   of them gets 200. The rest get 412 and skip.
3. **Record the result.** `PUT` `done` or `failed` with the exit code and
   `If-Match` the ETag of this worker's own claim. A 412 means the job ran
   longer than `LEASE` and another worker took over, so this result is
   dropped.
4. **Sweep.** Runs are history worth keeping for a while, so the sweep is per
   job and keeps the last `DAYS` days (default 30):

   ```sql
   DELETE FROM sqlar WHERE name >= 'runs/<job>/' AND name < 'runs/<job>/<cutoff>'
   ```

   This takes daily and hourly runs alike. The trailing `/` keeps
   `runs/backup-db/` out of the range for `backup`, because `-` sorts before
   `/`.

Skipping exits 0, because for cron a run another worker covered is success.
Otherwise `run-once.sh` exits with the job's exit code.

Because failed runs can be retried, a crontab can try more often than the
job runs. This runs `backup` once a day, retrying every hour until it
succeeds, and `rotate` once an hour:

```crontab
5 * * * *    run-once.sh daily backup /usr/local/bin/backup
*/10 * * * * run-once.sh hourly rotate /usr/local/bin/rotate-logs
```

### Try it

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests

examples/claim-once/run-once.sh daily backup echo backing up
# backing up
examples/claim-once/run-once.sh daily backup echo backing up
# run-once.sh: skipped runs/backup/20261013: already done on build-1

examples/claim-once/run-once.sh hourly rotate echo rotating
# rotating

examples/claim-once/run-once.sh daily report false
examples/claim-once/run-once.sh daily report echo report ok
# run-once.sh: retrying runs/report/20261013, which failed on build-1
# report ok

for i in 1 2 3; do examples/claim-once/run-once.sh daily race sh -c 'sleep 1; echo ran' & done; wait
# run-once.sh: skipped runs/race/20261013: running on build-1 for 0s
# run-once.sh: skipped runs/race/20261013: running on build-1 for 0s
# ran

examples/claim-once/run-once.sh history report
# 20261013  done  build-1  attempt 2  exit 0

examples/claim-once/run-once.sh sweep backup 30
# deleted 0 runs of backup from before 20260913
```

## Notes

- Two emails a few seconds apart are possible at a window boundary. It still
  averages one per 15 minutes per address, and both links work.
- `TTL` (default 3600 s) must stay under a day, since the sweep keeps only
  yesterday and today.
- Always build windows in UTC so keys don't shift with the server's time
  zone.
- `claim.sh` compares token hashes with `=`. That doesn't leak the token
  through timing, but in Go use `subtle.ConstantTimeCompare` anyway.
- Addresses are lowercased and limited to letters, digits and `._+-@` so
  they're safe in the JSON and the keys without escaping.
- `TestClaimOnce` in `claimonce_test.go` tests the pattern: the first claim
  gets 200, a second gets 412, marking it used with a stale ETag gets 412,
  and the sweep deletes only the earlier days. `TestRunOnce` does the same
  for cron jobs: daily and hourly keys are claimed once each, only one of
  two take-overs with the same ETag succeeds, and the sweep removes earlier
  days of one job only.
- Schedule jobs a few minutes past the hour (or past midnight UTC for daily
  jobs). Workers pick the period from their own clocks, so a worker a
  second slow at the boundary would claim the previous period.
- `LEASE` (default 3600 s) must be longer than the job ever takes,
  otherwise a slow run gets taken over and the job runs twice. A run can't
  tell another worker it's still alive, since this example has no
  heartbeat.
- A job should keep one period. `daily backup` and `hourly backup` claim
  different keys, so both would run.
- `FEATHERD` (default `http://127.0.0.1:8333`), `BUCKET` (default `claims`,
  or `jobs` for `run-once.sh`) and `DATA`
  (default `data`) choose the server, the bucket and the directory holding
  its database.
