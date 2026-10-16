# Webhooks once per event

Handle each webhook event once, however many times it's delivered.
Providers deliver webhooks at least once: they retry after a timeout or a
5xx, a delivery can be resent by hand, and behind a load balancer the copies
can reach different workers at the same time. Each event carries an ID that
stays the same across deliveries, such as GitHub's `X-GitHub-Delivery`
header, Stripe's `evt_…` ID or the Standard Webhooks `webhook-id` header.

With featherd the dedup is one request: `PUT` the event's key with
`If-None-Match: *`, which returns 200 if this request created the key and
412 if it already existed. Only the delivery that gets 200 runs the
handler. It's the same idea as an `INSERT` into a primary key, Redis
`SET NX` or an S3 conditional `PUT`, and the same claim as the cron jobs in
[`examples/claim-once`](../claim-once), with an event in place of a period.

`webhook-once.sh` needs `curl`, plus `sqlite3` for `sweep`.

## Layout

```
webhooks bucket  →  data/webhooks.sqlite3
└── events/<provider>/<event-id>    {"status", "host", "started", "attempt", "finished", "exit"}
```

## Flow

The handler gets the payload on stdin:

1. **Claim.** `PUT events/<provider>/<event-id>` with `If-None-Match: *` and
   `"status": "processing"`. 200: run the handler.
2. **Already delivered.** On 412, `GET` the record and its ETag. `done`:
   exit 0, so the endpoint answers 2xx and the provider stops. `processing`
   and started less than `LEASE` ago: exit 75 (`EX_TEMPFAIL`), so the
   endpoint answers 503 and the provider tries again later. Answering 2xx
   here would lose the event if that other worker then fails. `processing`
   for longer, meaning the worker probably crashed, or `failed`: take it
   over by `PUT`ting a new `processing` record with `If-Match: <etag>`.
   Every worker that read the same record sends the same ETag, so only one
   of them gets 200. The rest exit 75.
3. **Record the result.** `PUT` `done` or `failed` with the exit code and
   `If-Match` the ETag of this worker's own claim, and exit with the
   handler's status. A failure should become a 5xx, so the provider's retry
   gets a fresh attempt. A 412 means the handler ran longer than `LEASE` and
   another worker took over, so this result is dropped.
4. **Sweep.** featherd has no TTLs, so a cron job deletes old records
   straight from the bucket's database. The key holds no date, because a
   retry has to find the same key the next day. The sweep uses sqlar's
   `mtime` instead, which featherd sets on every write, so it keeps records
   that were written recently:

   ```sql
   DELETE FROM sqlar WHERE name >= 'events/<provider>/' AND name < 'events/<provider>0'
     AND mtime < <cutoff>
   ```

   The name range keeps it to one provider, and `0` is the character after
   `/`, so `events/stripe-test/` stays out of the range for `stripe`. It
   scans that provider's records rather than seeking to a date, which is
   fine for the few days of events it holds. The `sqlar_delete_drops_meta`
   trigger removes the matching `content_meta` rows, so ETags stay right.

Verify the delivery's signature before calling `webhook-once.sh`. Otherwise
anyone who can reach the endpoint can claim a real event's ID first, and the
real delivery is then skipped as a duplicate.

Your endpoint calls it like this, here as shell, and turns the exit status
into the response:

```sh
printf '%s' "$body" | webhook-once.sh handle github "$delivery" ./on-push.sh
case $? in
0) status=200 ;;
75) status=503 ;; # another worker has it; deliver again later
*) status=500 ;;
esac
```

## Try it

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests

echo '{"type":"invoice.paid"}' | examples/webhook-once/webhook-once.sh handle stripe evt_1NG8Du2eZvKYlo2C cat
# {"type":"invoice.paid"}
echo '{"type":"invoice.paid"}' | examples/webhook-once/webhook-once.sh handle stripe evt_1NG8Du2eZvKYlo2C cat
# webhook-once.sh: skipped events/stripe/evt_1NG8Du2eZvKYlo2C: already handled on build-1

examples/webhook-once/webhook-once.sh handle stripe evt_2 false </dev/null; echo "exit $?"
# exit 1
examples/webhook-once/webhook-once.sh handle stripe evt_2 cat </dev/null
# webhook-once.sh: retrying events/stripe/evt_2, which failed on build-1

for i in 1 2 3; do examples/webhook-once/webhook-once.sh handle github 1f2e3d4c sh -c 'sleep 1; echo handled' </dev/null & done; wait
# webhook-once.sh: skipped events/github/1f2e3d4c: processing on build-1 for 0s
# webhook-once.sh: skipped events/github/1f2e3d4c: processing on build-1 for 0s
# handled

examples/webhook-once/webhook-once.sh status stripe evt_2
# {"status":"done","host":"build-1","started":1791865702,"finished":1791865702,"attempt":2,"exit":0}

examples/webhook-once/webhook-once.sh sweep stripe 7
# deleted 0 events of stripe last written more than 7 days ago
```

Run `sweep` from cron, e.g. daily. It uses the `sqlite3` shell alongside
featherd, as in [`examples/sqlar`](../sqlar), and waits up to 5 s if
featherd is writing.

## Notes

- `DAYS` (default 7) must outlast the provider's retries and redeliveries,
  e.g. Stripe retries for up to 3 days, or an old event is handled again.
- `LEASE` (default 300 s) must be longer than the handler ever takes,
  otherwise a slow delivery gets taken over and the event is handled twice.
  Providers time out after seconds anyway, so a slow handler should queue
  its work and return.
- Event IDs keep their case and are limited to letters, digits and `._-`,
  up to 200 characters, which covers GUIDs and `evt_` IDs. Provider names
  are lowercase letters, digits and `._-`, so each provider is one key
  segment and one range for the sweep.
- `TestWebhookOnce` in `webhookonce_test.go` tests the pattern: a
  redelivery gets 412, only one of two retries of a failed event wins, and
  the sweep deletes only one provider's records with an old `mtime`.
- `FEATHERD` (default `http://127.0.0.1:8333`), `BUCKET` (default
  `webhooks`) and `DATA` (default `data`) choose the server, the bucket and
  the directory holding its database.
