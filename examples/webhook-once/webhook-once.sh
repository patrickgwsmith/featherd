#!/bin/sh
# Handle each webhook event at most once, however many times the provider
# delivers it and however many workers receive it: each worker claims
# events/<provider>/<event-id> with If-None-Match: *, and only the one that
# gets 200 runs the handler. The result is written back with If-Match, so a
# failed or crashed delivery can be retried by exactly one worker.
#
# Needs curl, and sqlite3 for sweep.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-webhooks}
DATA=${DATA:-data}
LEASE=${LEASE:-300} # seconds before a processing claim counts as crashed

# Exit status when another worker is still processing the event: answer the
# provider with a 503 so it delivers the event again later.
EX_TEMPFAIL=75

usage() {
	cat >&2 <<EOF
usage: $0 handle PROVIDER EVENT_ID COMMAND [ARG...]
                                    run COMMAND, with the payload on stdin, unless the event was handled
       $0 status PROVIDER EVENT_ID  print the event's record
       $0 sweep PROVIDER [DAYS]     delete PROVIDER's events last written before the last DAYS days (default 7)

handle exits 0 if the event is handled, now or before, $EX_TEMPFAIL if another worker
is handling it, and otherwise with COMMAND's exit status.

FEATHERD=$FEATHERD BUCKET=$BUCKET DATA=$DATA LEASE=$LEASE
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# skip REASON ends a delivery without running the handler, exiting 0 if the
# event is done and $EX_TEMPFAIL if it's still being handled elsewhere.
skip() {
	echo "$0: skipped $key: $2" >&2
	exit "$1"
}

# Provider names are one key segment, so one provider's events are one range
# of keys. The letters are spelled out because a-z can match capitals in
# some locales.
check_provider() {
	case $1 in
	'' | *[!abcdefghijklmnopqrstuvwxyz0123456789._-]* | .*) die "unsupported provider name '$1'" ;;
	esac
}

# Event IDs come from the provider, e.g. GitHub's X-GitHub-Delivery GUID or a
# Stripe evt_ ID, so they keep their case but are limited to characters that
# are safe in a key and in the JSON without escaping.
check_event() {
	case $1 in
	'' | *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]* | .*) die "unsupported event ID '$1'" ;;
	esac
	[ ${#1} -le 200 ] || die "event ID longer than 200 characters"
}

# field NAME FILE prints a field of the JSON this script writes. It relies on
# the values having no quotes, commas or braces, which the checks above and
# the script's own values ensure.
field() {
	sed -n "s/.*\"$1\":\"*\([^\",}]*\).*/\1/p" "$2"
}

# request METHOD KEY [CURL ARGS...] sends a request, saving the body to
# $tmp/body and the headers to $tmp/headers, and prints the status.
request() {
	_method=$1 _key=$2
	shift 2
	curl -sS -X "$_method" -D "$tmp/headers" -o "$tmp/body" -w '%{http_code}' "$@" "$FEATHERD/$BUCKET/$_key"
}

# put_json KEY JSON CONDITION stores JSON at KEY with an If-None-Match or
# If-Match header, and prints the status.
put_json() {
	printf '%s' "$2" >"$tmp/json"
	request PUT "$1" -H "$3" -H 'Content-Type: application/json' --data-binary "@$tmp/json"
}

# etag prints the ETag of the last response.
etag() {
	sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$tmp/headers" | tr -d '\r'
}

# processing ATTEMPT prints the record of a delivery being handled on this
# host.
processing() {
	echo "{\"status\":\"processing\",\"host\":\"$host\",\"started\":$now,\"attempt\":$1}"
}

cmd_handle() {
	[ $# -ge 3 ] || usage
	provider=$1 event=$2
	shift 2
	check_provider "$provider"
	check_event "$event"
	host=$(hostname | tr -cd 'A-Za-z0-9.-')
	now=$(date -u +%s)
	key=events/$provider/$event

	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac

	# The claim: 200 means this is the event's first delivery, and this
	# worker handles it.
	_status=$(put_json "$key" "$(processing 1)" 'If-None-Match: *')
	case $_status in
	200) ;;
	412) take_over ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
	claimed=$(etag)

	# The handler reads the payload from this script's stdin.
	code=0
	"$@" || code=$?

	if [ $code -eq 0 ]; then result=done; else result=failed; fi
	attempt=$(field attempt "$tmp/json")
	# If-Match the claim: 412 means the handler outlasted LEASE and another
	# worker has taken the event over.
	_status=$(put_json "$key" "{\"status\":\"$result\",\"host\":\"$host\",\"started\":$now,\"finished\":$(date -u +%s),\"attempt\":$attempt,\"exit\":$code}" "If-Match: $claimed")
	case $_status in
	200) ;;
	412) echo "$0: $key was taken over while processing; its result wasn't recorded" >&2 ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
	exit $code
}

# take_over reads the record of an earlier delivery of this event, and either
# skips or replaces it with this worker's claim. It returns only if this
# worker should run the handler.
take_over() {
	_status=$(request GET "$key")
	[ "$_status" = 200 ] || die "GET $key: HTTP $_status"
	cp "$tmp/body" "$tmp/claim"
	seen=$(etag)
	_host=$(field host "$tmp/claim")
	case $(field status "$tmp/claim") in
	done) skip 0 "already handled on $_host" ;;
	processing)
		_age=$((now - $(field started "$tmp/claim")))
		[ $_age -ge "$LEASE" ] || skip $EX_TEMPFAIL "processing on $_host for ${_age}s"
		echo "$0: taking over $key from $_host, silent for ${_age}s" >&2
		;;
	failed) echo "$0: retrying $key, which failed on $_host" >&2 ;;
	*) die "unexpected record at $key" ;;
	esac
	# If-Match the record just read, so of all the deliveries that saw it,
	# only one takes over.
	_status=$(put_json "$key" "$(processing $(($(field attempt "$tmp/claim") + 1)))" "If-Match: $seen")
	case $_status in
	200) ;;
	412) skip $EX_TEMPFAIL 'another worker took it over first' ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
}

cmd_status() {
	[ $# -eq 2 ] || usage
	check_provider "$1"
	check_event "$2"
	_status=$(request GET "events/$1/$2")
	case $_status in
	200) cat "$tmp/body"; echo ;;
	404) die "no record of events/$1/$2" ;;
	*) die "GET events/$1/$2: HTTP $_status" ;;
	esac
}

cmd_sweep() {
	[ $# -ge 1 ] && [ $# -le 2 ] || usage
	provider=$1 days=${2:-7}
	check_provider "$provider"
	case $days in '' | *[!0-9]*) die "DAYS must be a number, not '$days'" ;; esac
	command -v sqlite3 >/dev/null || die 'sweep needs sqlite3'
	db=$DATA/$BUCKET.sqlite3
	[ -f "$db" ] || die "no bucket database at $db"
	# Keys hold no date, since a redelivery has to find the same key on any
	# day, so this filters on sqlar's mtime, the record's last write, within
	# the provider's range of the name index. '0' sorts just after '/'.
	cutoff=$(($(date -u +%s) - days * 86400))
	n=$(sqlite3 "$db" '.timeout 5000' \
		"DELETE FROM sqlar WHERE name >= 'events/$provider/' AND name < 'events/${provider}0' AND mtime < $cutoff; SELECT changes();")
	echo "deleted $n events of $provider last written more than $days days ago" >&2
}

[ $# -ge 1 ] || usage
cmd=$1
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case $cmd in
handle) cmd_handle "$@" ;;
status) cmd_status "$@" ;;
sweep) cmd_sweep "$@" ;;
*) usage ;;
esac
