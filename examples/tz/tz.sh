#!/bin/sh
# Serve the IANA time zone database from featherd: one object per zone,
# holding its compiled TZif rules, plus the database's country tables.
#
# Needs curl and awk.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-tzdb}

usage() {
	cat >&2 <<EOF
usage: $0 put [ZONEINFO]          store every zone under ZONEINFO (default /usr/share/zoneinfo)
       $0 version                 print the stored release, e.g. 2026c
       $0 zones [PREFIX]          list zone names, e.g. under America/
       $0 country CC              print a country's name and zones, with coordinates
       $0 get ZONE [OUT]          fetch a zone's TZif file, to stdout if OUT is -
       $0 now ZONE...             print the current time in each zone

FEATHERD=$FEATHERD BUCKET=$BUCKET
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# Zone names are letters, digits and "/_+-" (Etc/GMT+5); they're used in URLs
# and file names as is.
check_zone() {
	case $1 in
	'' | /* | *[!A-Za-z0-9/_+-]*) die "invalid zone '$1'" ;;
	esac
}

# put KEY FILE TYPE stores FILE, failing with featherd's error body.
put() {
	_status=$(curl -sS -o "$tmp/err" -w '%{http_code}' -X PUT \
		-H "Content-Type: $3" --data-binary "@$2" "$FEATHERD/$BUCKET/$1")
	[ "$_status" = 200 ] || { cat "$tmp/err" >&2; die "PUT $1: HTTP $_status"; }
}

# fetch KEY prints an object.
fetch() {
	curl -sS --fail-with-body "$FEATHERD/$BUCKET/$1" || die "GET $1 failed"
}

cmd_put() {
	[ $# -le 1 ] || usage
	src=${1:-/usr/share/zoneinfo}
	[ -d "$src" ] || die "$src is not a directory"
	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac

	# Compiled zones are the files starting with the TZif magic; aliases such
	# as US/Eastern are separate files (or links) with the same bytes. Other
	# files (leapseconds, tzdata.zi) are skipped.
	n=0
	for f in $(cd "$src" && find . -type f -o -type l | sed 's|^\./||' | LC_ALL=C sort); do
		[ "$(head -c 4 "$src/$f")" = TZif ] || continue
		check_zone "$f"
		put "$f" "$src/$f" application/tzif # RFC 9636
		n=$((n + 1))
	done
	[ $n -gt 0 ] || die "no TZif files under $src"

	for f in zone1970.tab zone.tab iso3166.tab; do
		[ ! -f "$src/$f" ] || put "$f" "$src/$f" 'text/tab-separated-values; charset=utf-8'
	done
	[ -f "$src/zone.tab" ] && [ -f "$src/iso3166.tab" ] || echo "$0: no zone.tab/iso3166.tab under $src; 'country' won't work" >&2
	# +VERSION is stored as VERSION: a "+" in a URL is a space to some clients.
	[ ! -f "$src/+VERSION" ] || put VERSION "$src/+VERSION" 'text/plain; charset=utf-8'
	echo "stored $n zones from $src" >&2
}

cmd_version() {
	[ $# -eq 0 ] || usage
	fetch VERSION
}

cmd_zones() {
	[ $# -le 1 ] || usage
	prefix=${1:-}
	[ -z "$prefix" ] || check_zone "$prefix"
	token=
	while :; do
		url="$FEATHERD/$BUCKET?list-type=2&prefix=$prefix"
		[ -z "$token" ] || url="$url&continuation-token=$token"
		page=$(curl -sS --fail-with-body "$url") || die "listing failed: $page"
		# Zone names have no dots; the tables and VERSION are the other keys.
		printf '%s' "$page" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' |
			grep -v -e '\.' -e '^VERSION$' || true
		token=$(printf '%s' "$page" | grep -o '<NextContinuationToken>[^<]*' | sed 's/.*>//' || true)
		[ -n "$token" ] || break
	done
}

cmd_country() {
	[ $# -eq 1 ] || usage
	cc=$(printf '%s' "$1" | tr a-z A-Z)
	case $cc in [A-Z][A-Z]) ;; *) die "invalid country code '$1': want two letters, e.g. NZ" ;; esac
	fetch iso3166.tab >"$tmp/iso3166.tab"
	fetch zone.tab >"$tmp/zone.tab"
	# zone.tab's coordinates are ISO 6709, ±DDMM±DDDMM or ±DDMMSS±DDDMMSS;
	# print them as decimal degrees.
	awk -F '\t' -v cc="$cc" '
		function deg(s, n,   d) {
			d = substr(s, 2, n) + substr(s, n + 2, 2) / 60 + substr(s, n + 4, 2) / 3600
			return substr(s, 1, 1) == "-" ? -d : d
		}
		FNR == NR { if ($1 == cc) name = $2; next }
		$1 == cc {
			c = $2; i = length(c) == 11 ? 6 : 8
			printf "%-32s %9.4f %10.4f  %s\n", $3, deg(substr(c, 1, i - 1), 2), deg(substr(c, i), 3), $4
			n++
		}
		END {
			if (name == "") { print "unknown country " cc > "/dev/stderr"; exit 1 }
			print cc "\t" name > "/dev/stderr"
			if (!n) print "no zones" > "/dev/stderr"
		}' "$tmp/iso3166.tab" "$tmp/zone.tab"
}

cmd_get() {
	[ $# -eq 1 ] || [ $# -eq 2 ] || usage
	check_zone "$1"
	out=${2:-$(basename "$1")}
	if [ "$out" = - ]; then
		fetch "$1"
	else
		fetch "$1" >"$tmp/zone"
		mv "$tmp/zone" "$out"
		echo "$out" >&2
	fi
}

cmd_now() {
	[ $# -ge 1 ] || usage
	for zone; do
		check_zone "$zone"
		fetch "$zone" >"$tmp/zone"
		# TZ can name a TZif file by absolute path (POSIX, macOS and glibc).
		printf '%-32s %s\n' "$zone" "$(TZ="$tmp/zone" date '+%Y-%m-%d %H:%M:%S %Z (%z)')"
	done
}

[ $# -ge 1 ] || usage
cmd=$1
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case $cmd in
put) cmd_put "$@" ;;
version) cmd_version "$@" ;;
zones) cmd_zones "$@" ;;
country) cmd_country "$@" ;;
get) cmd_get "$@" ;;
now) cmd_now "$@" ;;
*) usage ;;
esac
