#!/bin/sh
# Use SQLite Archives as featherd buckets: pack a directory into
# <data>/<bucket>.sqlite3 with the sqlite3 shell, read it over HTTP while
# featherd serves it, and unpack it again.
#
# Needs sqlite3 and curl.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
DATA=${DATA:-data}

usage() {
	cat >&2 <<EOF
usage: $0 pack DIR BUCKET         make BUCKET an archive of DIR's files, replacing its objects
       $0 update DIR BUCKET       add DIR's new and changed files to BUCKET
       $0 unpack BUCKET OUT       extract every object in BUCKET into OUT
       $0 ls BUCKET               list BUCKET's objects over HTTP
       $0 get BUCKET KEY [OUT]    fetch an object over HTTP, to stdout if OUT is -

FEATHERD=$FEATHERD DATA=$DATA
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# Bucket names become file names; featherd serves only S3-valid ones.
check_bucket() {
	case $1 in
	'' | *[!a-z0-9.-]* | [.-]* | *[.-] | *..*) die "invalid bucket '$1': use 3-63 lowercase letters, digits, '.' and '-'" ;;
	esac
	[ ${#1} -ge 3 ] && [ ${#1} -le 63 ] || die "invalid bucket '$1': use 3-63 lowercase letters, digits, '.' and '-'"
}

# archive DIR BUCKET MODE runs `sqlite3 -A MODE` on DIR's top-level entries
# from inside DIR, so keys are paths relative to DIR. (`-C DIR .` would prefix
# every key with "./".) Dotfiles are skipped.
archive() {
	[ -d "$1" ] || die "$1 is not a directory"
	check_bucket "$2"
	mkdir -p "$DATA"
	db=$(cd "$DATA" && pwd)/$2.sqlite3
	mode=$3
	(
		cd "$1"
		set -- *
		[ -e "$1" ] || die "no files under $PWD"
		sqlite3 "$db" -A "$mode" "$@"
	)
	echo "$db: $(sqlite3 "$db" "SELECT count(*) || ' files, ' || sum(sz) || ' bytes' FROM sqlar WHERE mode & 61440 = 32768")" >&2
}

cmd_pack() {
	[ $# -eq 2 ] || usage
	# Written in place, not renamed over the old file, which featherd may
	# have open: -c drops and recreates the sqlar table in one transaction.
	archive "$1" "$2" -c
}

cmd_update() {
	[ $# -eq 2 ] || usage
	[ -e "$DATA/$2.sqlite3" ] || die "$DATA/$2.sqlite3 does not exist; pack it first"
	# -u skips files whose mtime is unchanged.
	archive "$1" "$2" -u
}

cmd_unpack() {
	[ $# -eq 2 ] || usage
	check_bucket "$1"
	[ -e "$DATA/$1.sqlite3" ] || die "$DATA/$1.sqlite3 does not exist"
	mkdir -p "$2"
	sqlite3 "$DATA/$1.sqlite3" -A -x -C "$2"
}

cmd_ls() {
	[ $# -eq 1 ] || usage
	check_bucket "$1"
	token=
	while :; do
		url="$FEATHERD/$1?list-type=2"
		[ -z "$token" ] || url="$url&continuation-token=$token"
		page=$(curl -sS --fail-with-body "$url") || die "listing failed: $page"
		printf '%s' "$page" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' || true
		token=$(printf '%s' "$page" | grep -o '<NextContinuationToken>[^<]*' | sed 's/.*>//' || true)
		[ -n "$token" ] || break
	done
}

cmd_get() {
	[ $# -eq 2 ] || [ $# -eq 3 ] || usage
	check_bucket "$1"
	out=${3:-$(basename "$2")}
	if [ "$out" = - ]; then
		curl -sS --fail-with-body "$FEATHERD/$1/$2" || die "GET $2 failed"
	else
		curl -sS --fail-with-body -o "$out" "$FEATHERD/$1/$2" || { cat "$out" >&2; rm -f "$out"; die "GET $2 failed"; }
		echo "$out" >&2
	fi
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
pack) cmd_pack "$@" ;;
update) cmd_update "$@" ;;
unpack) cmd_unpack "$@" ;;
ls) cmd_ls "$@" ;;
get) cmd_get "$@" ;;
*) usage ;;
esac
