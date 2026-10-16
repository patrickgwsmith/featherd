#!/bin/sh
# Run a job at most once per UTC day or hour, however many workers' crontabs
# start it: each worker claims runs/<job>/<period> with If-None-Match: *, and
# only the one that gets 200 runs the job. The result is written back with
# If-Match, so a crashed or failed run can be taken over by exactly one
# worker.
#
# Needs curl, and sqlite3 for sweep.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-jobs}
DATA=${DATA:-data}
LEASE=${LEASE:-3600} # seconds before a running claim counts as crashed

usage() {
	cat >&2 <<EOF
usage: $0 daily JOB COMMAND [ARG...]    run COMMAND unless JOB already ran today (UTC)
       $0 hourly JOB COMMAND [ARG...]   run COMMAND unless JOB already ran this hour (UTC)
       $0 history JOB                   list JOB's runs and their results
       $0 sweep JOB [DAYS]              delete JOB's runs from before the last DAYS days (default 30)

FEATHERD=$FEATHERD BUCKET=$BUCKET DATA=$DATA LEASE=$LEASE
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# skip REASON ends a run that another worker has covered. It exits 0, since
# for cron that's success.
skip() {
	echo "$0: skipped $key: $*" >&2
	exit 0
}

# utc FORMAT EPOCH formats a Unix time in UTC (BSD date, then GNU date).
utc() {
	date -u -r "$2" "+$1" 2>/dev/null || date -u -d "@$2" "+$1"
}

# Job names are one key segment, so one job's runs are one range of keys.
# The letters are spelled out because a-z can match capitals in some locales.
check_job() {
	case $1 in
	'' | *[!abcdefghijklmnopqrstuvwxyz0123456789._-]* | .*) die "unsupported job name '$1'" ;;
	esac
}

# field NAME FILE prints a field of the JSON this script writes.
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

# running ATTEMPT prints the record of a run in progress on this host.
running() {
	echo "{\"status\":\"running\",\"host\":\"$host\",\"started\":$now,\"attempt\":$1}"
}

cmd_run() {
	case $1 in
	daily) format=%Y%m%d ;;
	hourly) format=%Y%m%dT%H ;;
	*) usage ;;
	esac
	[ $# -ge 3 ] || usage
	job=$2
	shift 2
	check_job "$job"
	host=$(hostname | tr -cd 'A-Za-z0-9.-')
	now=$(date -u +%s)
	period=$(utc "$format" "$now")
	key=runs/$job/$period

	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac

	# The claim: 200 means this worker created the key and runs the job.
	_status=$(put_json "$key" "$(running 1)" 'If-None-Match: *')
	case $_status in
	200) ;;
	412) take_over ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
	claimed=$(etag)

	code=0
	"$@" || code=$?

	if [ $code -eq 0 ]; then result=done; else result=failed; fi
	attempt=$(field attempt "$tmp/json")
	# If-Match the claim: 412 means this run outlasted LEASE and another
	# worker has taken the period over.
	_status=$(put_json "$key" "{\"status\":\"$result\",\"host\":\"$host\",\"started\":$now,\"finished\":$(date -u +%s),\"attempt\":$attempt,\"exit\":$code}" "If-Match: $claimed")
	case $_status in
	200) ;;
	412) echo "$0: $key was taken over while running; its result wasn't recorded" >&2 ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
	exit $code
}

# take_over reads a claim another worker made for this period, and either
# skips or replaces it with this worker's claim. It returns only if this
# worker should run the job.
take_over() {
	_status=$(request GET "$key")
	[ "$_status" = 200 ] || die "GET $key: HTTP $_status"
	cp "$tmp/body" "$tmp/claim"
	seen=$(etag)
	_host=$(field host "$tmp/claim")
	case $(field status "$tmp/claim") in
	done) skip "already done on $_host" ;;
	running)
		_age=$((now - $(field started "$tmp/claim")))
		[ $_age -ge "$LEASE" ] || skip "running on $_host for ${_age}s"
		echo "$0: taking over $key from $_host, silent for ${_age}s" >&2
		;;
	failed) echo "$0: retrying $key, which failed on $_host" >&2 ;;
	*) die "unexpected record at $key" ;;
	esac
	# If-Match the record just read, so of all the workers that saw it, only
	# one takes over.
	_status=$(put_json "$key" "$(running $(($(field attempt "$tmp/claim") + 1)))" "If-Match: $seen")
	case $_status in
	200) ;;
	412) skip 'another worker took it over first' ;;
	*) cat "$tmp/body" >&2; die "PUT $key: HTTP $_status" ;;
	esac
}

cmd_history() {
	[ $# -eq 1 ] || usage
	job=$1
	check_job "$job"
	token=
	while :; do
		url="$FEATHERD/$BUCKET?list-type=2&prefix=runs/$job/"
		[ -z "$token" ] || url="$url&continuation-token=$token"
		page=$(curl -sS --fail-with-body "$url") || die "listing failed: $page"
		printf '%s' "$page" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' >"$tmp/keys" || true
		while read -r k; do
			[ "$(request GET "$k")" = 200 ] || continue
			printf '%s\t%s\t%s\tattempt %s' "${k##*/}" "$(field status "$tmp/body")" \
				"$(field host "$tmp/body")" "$(field attempt "$tmp/body")"
			_exit=$(field exit "$tmp/body")
			[ -z "$_exit" ] || printf '\texit %s' "$_exit"
			echo
		done <"$tmp/keys"
		token=$(printf '%s' "$page" | grep -o '<NextContinuationToken>[^<]*' | sed 's/.*>//' || true)
		[ -n "$token" ] || break
	done
}

cmd_sweep() {
	[ $# -ge 1 ] && [ $# -le 2 ] || usage
	job=$1 days=${2:-30}
	check_job "$job"
	case $days in '' | *[!0-9]*) die "DAYS must be a number, not '$days'" ;; esac
	command -v sqlite3 >/dev/null || die 'sweep needs sqlite3'
	db=$DATA/$BUCKET.sqlite3
	[ -f "$db" ] || die "no bucket database at $db"
	# Keys end with their period, so every day before the cutoff, daily and
	# hourly runs alike, is one range of the name index. Today is always
	# kept, since its claims stop today's runs from repeating.
	cutoff=$(utc %Y%m%d $(($(date -u +%s) - days * 86400)))
	n=$(sqlite3 "$db" '.timeout 5000' \
		"DELETE FROM sqlar WHERE name >= 'runs/$job/' AND name < 'runs/$job/$cutoff'; SELECT changes();")
	echo "deleted $n runs of $job from before $cutoff" >&2
}

[ $# -ge 1 ] || usage
cmd=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case $cmd in
daily | hourly) cmd_run "$@" ;;
history) shift; cmd_history "$@" ;;
sweep) shift; cmd_sweep "$@" ;;
*) usage ;;
esac
