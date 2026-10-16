#!/bin/sh
# Claim-once keys in featherd: create a key named by (subject, UTC time
# window) only if it doesn't exist yet, so at most one claim per subject per
# window succeeds. The example is newsletter sign-up: at most one
# confirmation email per address every 15 minutes.
#
# Needs curl and openssl, and sqlite3 for sweep.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-claims}
DATA=${DATA:-data}
TTL=${TTL:-3600} # seconds a link stays valid after its window starts; under a day
WINDOW=900       # 15 minutes; windows start on the quarter hour UTC

usage() {
	cat >&2 <<EOF
usage: $0 claim EMAIL             claim this window for EMAIL and print its confirmation link
       $0 confirm LINK            confirm a link, subscribing its address
       $0 ls [PREFIX]             list keys, e.g. under pending/ or subscribers/
       $0 sweep                   delete pending claims from before yesterday (UTC)

CLAIM_SECRET must be set. FEATHERD=$FEATHERD BUCKET=$BUCKET DATA=$DATA TTL=$TTL
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# utc FORMAT EPOCH formats a Unix time in UTC (BSD date, then GNU date).
utc() {
	date -u -r "$2" "+$1" 2>/dev/null || date -u -d "@$2" "+$1"
}

hex() {
	sed 's/.*= *//'
}

# hmac DATA names a subject without putting it in the key.
hmac() {
	[ -n "${CLAIM_SECRET:-}" ] || die 'set CLAIM_SECRET, e.g. export CLAIM_SECRET=$(openssl rand -hex 32)'
	printf '%s' "$1" | openssl dgst -sha256 -hmac "$CLAIM_SECRET" | hex
}

sha256() {
	printf '%s' "$1" | openssl dgst -sha256 | hex
}

# Addresses are kept simple so they're safe in JSON and in keys as is.
check_email() {
	case $1 in
	*[!a-z0-9._+@-]* | *@*@* | @* | *@) die "unsupported address '$1'" ;;
	?*@?*) ;;
	*) die "unsupported address '$1'" ;;
	esac
}

# is_hex64 S succeeds if S is 64 lowercase hex digits.
is_hex64() {
	case $1 in *[!0-9a-f]*) return 1 ;; esac
	[ ${#1} -eq 64 ]
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

cmd_claim() {
	[ $# -eq 1 ] || usage
	email=$(printf '%s' "$1" | tr A-Z a-z)
	check_email "$email"
	now=$(date -u +%s)
	window=$(utc %Y%m%dT%H%M $((now - now % WINDOW)))
	key=$window/$(hmac "$email")
	token=$(openssl rand -hex 32)

	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac

	# The claim: 200 means this request created the key, 412 that an earlier
	# one in the same window did. Only the token's hash is stored.
	_status=$(put_json "pending/$key" "{\"email\":\"$email\",\"token_sha256\":\"$(sha256 "$token")\",\"used\":false}" 'If-None-Match: *')
	case $_status in
	200) ;;
	412) die "already sent to $email in window $window UTC; try again in $(((WINDOW - now % WINDOW + 59) / 60)) min" ;;
	*) cat "$tmp/body" >&2; die "PUT pending/$key: HTTP $_status" ;;
	esac
	# A real app would email this link instead of printing it.
	echo "/confirm?k=$key&t=$token"
}

cmd_confirm() {
	[ $# -eq 1 ] || usage
	k=${1#*k=} t=${1#*t=}
	k=${k%%&*} t=${t%%&*}
	# The key must be a window and an HMAC, so a link can't name anything
	# else in the bucket.
	window=${k%%/*} mac=${k#*/}
	case $window in
	[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9]) ;;
	*) die 'invalid link' ;;
	esac
	is_hex64 "$mac" && is_hex64 "$t" || die 'invalid link'

	# Expiry comes from the key: the window start plus TTL. As digits,
	# YYYYMMDDHHMMSS times compare as numbers.
	now=$(date -u +%s)
	[ "$(printf '%s' "$window" | tr -d T)00" -ge "$(utc %Y%m%d%H%M%S $((now - TTL)))" ] || die 'link expired'

	_status=$(request GET "pending/$k")
	case $_status in
	200) ;;
	404) die 'invalid link' ;;
	*) die "GET pending/$k: HTTP $_status" ;;
	esac
	cp "$tmp/body" "$tmp/pending"
	etag=$(sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$tmp/headers" | tr -d '\r')
	email=$(field email "$tmp/pending")
	# Comparing hashes leaks nothing useful about the token through timing; in
	# Go, use subtle.ConstantTimeCompare anyway.
	[ "$(sha256 "$t")" = "$(field token_sha256 "$tmp/pending")" ] || die 'invalid link'
	if [ "$(field used "$tmp/pending")" = true ]; then
		echo "$email already confirmed"
		return
	fi

	# 412: subscribed by an earlier link, which is still success.
	_status=$(put_json "subscribers/$email" "{\"email\":\"$email\",\"confirmed_at\":\"$(utc %Y-%m-%dT%H:%M:%SZ "$now")\"}" 'If-None-Match: *')
	case $_status in
	200 | 412) ;;
	*) cat "$tmp/body" >&2; die "PUT subscribers/$email: HTTP $_status" ;;
	esac
	# Mark the claim used rather than deleting it: the key has to stay until
	# the sweep, or another email could be sent in the same window. 412 means
	# a concurrent confirm got there first.
	_status=$(put_json "pending/$k" "$(sed 's/"used":false/"used":true/' "$tmp/pending")" "If-Match: $etag")
	case $_status in
	200 | 412) ;;
	*) cat "$tmp/body" >&2; die "PUT pending/$k: HTTP $_status" ;;
	esac
	echo "confirmed $email"
}

cmd_ls() {
	[ $# -le 1 ] || usage
	prefix=${1:-}
	case $prefix in *[!A-Za-z0-9/._+@-]*) die "invalid prefix '$prefix'" ;; esac
	token=
	while :; do
		url="$FEATHERD/$BUCKET?list-type=2&prefix=$prefix"
		[ -z "$token" ] || url="$url&continuation-token=$token"
		page=$(curl -sS --fail-with-body "$url") || die "listing failed: $page"
		printf '%s' "$page" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' || true
		token=$(printf '%s' "$page" | grep -o '<NextContinuationToken>[^<]*' | sed 's/.*>//' || true)
		[ -n "$token" ] || break
	done
}

cmd_sweep() {
	[ $# -eq 0 ] || usage
	command -v sqlite3 >/dev/null || die 'sweep needs sqlite3'
	db=$DATA/$BUCKET.sqlite3
	[ -f "$db" ] || die "no bucket database at $db"
	# Keys start with their window, so every day before yesterday is one
	# range of the name index. Yesterday is kept: a link lives at most TTL,
	# under a day, and its claim must outlive it.
	cutoff=$(utc %Y%m%d $(($(date -u +%s) - 86400)))
	n=$(sqlite3 "$db" '.timeout 5000' \
		"DELETE FROM sqlar WHERE name >= 'pending/' AND name < 'pending/$cutoff'; SELECT changes();")
	echo "deleted $n claims from before $cutoff" >&2
}

[ $# -ge 1 ] || usage
cmd=$1
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case $cmd in
claim) cmd_claim "$@" ;;
confirm) cmd_confirm "$@" ;;
ls) cmd_ls "$@" ;;
sweep) cmd_sweep "$@" ;;
*) usage ;;
esac
