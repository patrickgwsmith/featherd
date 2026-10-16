#!/bin/sh
# Publish a directory of files, such as a static site or a config bundle, so
# that readers see the whole old release or the whole new one, never a mix.
# Each release is uploaded under its own prefix and never changed; publishing
# is a single If-Match PUT of the `current` pointer, so of two publishers
# that started from the same release only one wins, and an older deploy
# can't silently replace a newer one. Old releases are deleted only below a
# floor recorded in `current`, which rollbacks can't cross.
#
# Needs curl and openssl, and sqlite3 for gc.
set -eu

# C collation, so ranges in patterns and sort order are byte-wise.
LC_ALL=C
export LC_ALL

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-site}
DATA=${DATA:-data}

usage() {
	cat >&2 <<EOF
usage: $0 publish DIR             upload DIR as a new release and make it current
       $0 rollback [RELEASE]      make RELEASE (default: the previous one) current again
       $0 current                 print the current release's pointer
       $0 releases                list releases, marking the current one
       $0 cat PATH [RELEASE]      print a file of RELEASE (default: the current one)
       $0 fetch DEST [RELEASE]    download a whole release into the new directory DEST
       $0 gc [KEEP] [MINUTES]     delete releases older than the newest KEEP (default 5),
                                  the current one and the last MINUTES (default 60)

FEATHERD=$FEATHERD BUCKET=$BUCKET DATA=$DATA
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

# Release IDs are the UTC time the publish started plus a random suffix, so
# they sort by time as strings, e.g. 20261013T141502Z-9f2c4e1a.
ID_TIME=%Y%m%dT%H%M%SZ

check_release() {
	case $1 in
	[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
	*) die "not a release ID: '$1'" ;;
	esac
}

# Paths in a release are limited to characters that are safe in a key, in a
# manifest line and in a shell word, with no empty, . or .. segments.
check_path() {
	case /$1/ in
	*[!A-Za-z0-9._/-]* | *//* | */./* | */../*) die "unsupported path '$1'" ;;
	esac
}

# field NAME FILE prints a field of the JSON this script writes. It relies on
# the values having no quotes, commas or braces, which the checks above
# ensure.
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

# etag prints the ETag of the last response.
etag() {
	sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$tmp/headers" | tr -d '\r'
}

# min A B prints whichever of two release IDs (or prefixes of one) sorts
# first.
min() {
	if expr "x$1" \< "x$2" >/dev/null; then echo "$1"; else echo "$2"; fi
}

sha256_hex() {
	openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}

content_type() {
	case $1 in
	*.html) echo 'text/html; charset=utf-8' ;;
	*.css) echo 'text/css; charset=utf-8' ;;
	*.js) echo 'text/javascript; charset=utf-8' ;;
	*.json) echo 'application/json' ;;
	*.txt) echo 'text/plain; charset=utf-8' ;;
	*.svg) echo 'image/svg+xml' ;;
	*.png) echo 'image/png' ;;
	*.jpg | *.jpeg) echo 'image/jpeg' ;;
	*.woff2) echo 'font/woff2' ;;
	*) echo 'application/octet-stream' ;;
	esac
}

# read_current reads the pointer into $tmp/current and sets cur_status,
# cur_etag, cur_release, cur_previous and cur_floor. A missing pointer means
# nothing has been published yet.
read_current() {
	cur_status=$(request GET current)
	cur_etag='' cur_release='' cur_previous='' cur_floor=''
	case $cur_status in
	200)
		cp "$tmp/body" "$tmp/current"
		cur_etag=$(etag)
		cur_release=$(field release "$tmp/current")
		cur_previous=$(field previous "$tmp/current")
		cur_floor=$(field floor "$tmp/current")
		check_release "$cur_release"
		[ -z "$cur_previous" ] || check_release "$cur_previous"
		[ -z "$cur_floor" ] || check_release "$cur_floor"
		;;
	404) ;;
	*) die "GET current: HTTP $cur_status" ;;
	esac
}

# put_current RELEASE PREVIOUS FLOOR replaces the pointer read last by
# read_current, If-Match its ETag (or If-None-Match: * if there was none),
# and prints the status.
put_current() {
	printf '{"release":"%s","previous":"%s","floor":"%s","updated_at":%s,"host":"%s"}' \
		"$1" "$2" "$3" "$(date -u +%s)" "$(hostname | tr -cd 'A-Za-z0-9.-')" >"$tmp/json"
	if [ "$cur_status" = 200 ]; then _cond="If-Match: $cur_etag"; else _cond='If-None-Match: *'; fi
	request PUT current -H "$_cond" -H 'Content-Type: application/json' --data-binary "@$tmp/json"
}

# switch_to RELEASE BASE makes RELEASE current, as long as BASE (empty for
# none) still is. A 412 means someone else wrote the pointer since it was
# read: if they changed the release, give up rather than overwrite it; if
# only gc raised the floor, read it again and retry.
switch_to() {
	_new=$1 _base=$2
	for _try in 1 2 3 4 5; do
		read_current
		[ "$cur_release" = "$_base" ] ||
			die "current moved from ${_base:-nothing} to $cur_release while this ran; not replacing it (release $_new is uploaded; roll back to it to publish it anyway)"
		# The floor check is part of the same compare-and-swap: gc raises the
		# floor with If-Match before deleting anything below it.
		[ -z "$cur_floor" ] || [ "$(min "$_new" "$cur_floor")" = "$cur_floor" ] ||
			die "release $_new is below the gc floor $cur_floor and may be partly deleted"
		_status=$(put_current "$_new" "$cur_release" "$cur_floor")
		case $_status in
		200) return ;;
		412) ;;
		*) cat "$tmp/body" >&2; die "PUT current: HTTP $_status" ;;
		esac
	done
	die "current kept changing; giving up"
}

cmd_publish() {
	[ $# -eq 1 ] || usage
	src=${1%/}
	[ -d "$src" ] || die "no directory '$src'"
	_bad=$(find "$src" ! -type d ! -type f | head -n 1)
	[ -z "$_bad" ] || die "not a regular file: '$_bad'"
	_bad=$(find "$src" -name '*[!A-Za-z0-9._-]*' | head -n 1)
	[ -z "$_bad" ] || die "unsupported name: '$_bad'"
	(cd "$src" && find . -type f) | sed 's|^\./||' | sort >"$tmp/paths"
	[ -s "$tmp/paths" ] || die "no files in '$src'"

	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac

	# The base is the release current when the publish starts, so a deploy
	# that took a while can't replace one that finished in the meantime.
	read_current
	base=$cur_release
	id=$(utc "$ID_TIME" "$(date -u +%s)")-$(openssl rand -hex 4)
	[ -z "$cur_floor" ] || [ "$(min "$id" "$cur_floor")" = "$cur_floor" ] || die "release $id is below the gc floor $cur_floor; check the clock"

	# Upload every file under releases/<id>/ with If-None-Match: *, so a
	# release is never written twice, and with its SHA-256, which featherd
	# checks before storing anything.
	: >"$tmp/manifest"
	while IFS= read -r path; do
		check_path "$path"
		_hex=$(sha256_hex "$src/$path")
		_b64=$(openssl dgst -sha256 -binary "$src/$path" | openssl base64)
		_status=$(request PUT "releases/$id/$path" -H 'If-None-Match: *' \
			-H "Content-Type: $(content_type "$path")" \
			-H "x-amz-checksum-sha256: $_b64" --data-binary "@$src/$path")
		[ "$_status" = 200 ] || { cat "$tmp/body" >&2; die "PUT releases/$id/$path: HTTP $_status"; }
		printf '%s  %s\n' "$_hex" "$path" >>"$tmp/manifest"
	done <"$tmp/paths"

	# The manifest is written last, so a release with a manifest is complete.
	_status=$(request PUT "manifests/$id" -H 'If-None-Match: *' \
		-H 'Content-Type: text/plain; charset=utf-8' --data-binary "@$tmp/manifest")
	[ "$_status" = 200 ] || { cat "$tmp/body" >&2; die "PUT manifests/$id: HTTP $_status"; }

	switch_to "$id" "$base"
	echo "$0: published $(wc -l <"$tmp/manifest" | tr -d ' ') files as $id, replacing ${base:-nothing}" >&2
	echo "$id"
}

cmd_rollback() {
	[ $# -le 1 ] || usage
	read_current
	[ "$cur_status" = 200 ] || die "nothing is published"
	base=$cur_release target=${1:-$cur_previous}
	[ -n "$target" ] || die "release $base has no previous release"
	check_release "$target"
	[ "$target" != "$base" ] || die "$target is already current"
	_status=$(request GET "manifests/$target")
	case $_status in
	200) ;;
	404) die "no complete release $target" ;;
	*) die "GET manifests/$target: HTTP $_status" ;;
	esac
	switch_to "$target" "$base"
	echo "$0: rolled back from $base to $target" >&2
}

cmd_current() {
	[ $# -eq 0 ] || usage
	read_current
	[ "$cur_status" = 200 ] || die "nothing is published"
	cat "$tmp/current"
	echo
}

cmd_releases() {
	[ $# -eq 0 ] || usage
	read_current
	_status=$(curl -sS -o "$tmp/body" -w '%{http_code}' "$FEATHERD/$BUCKET?list-type=2&prefix=manifests/")
	[ "$_status" = 200 ] || die "listing manifests: HTTP $_status"
	tr '<' '\n' <"$tmp/body" | sed -n 's|^Key>manifests/||p' | sort -r | while IFS= read -r r; do
		if [ "$r" = "$cur_release" ]; then echo "$r current"; else echo "$r"; fi
	done
}

# resolve [RELEASE] sets release to RELEASE, or to the current release. A
# reader resolves once and reads every file from that release, so a publish
# in between can't give it files from two releases.
resolve() {
	if [ -n "${1:-}" ]; then
		check_release "$1"
		release=$1
		return
	fi
	read_current
	[ "$cur_status" = 200 ] || die "nothing is published"
	release=$cur_release
}

cmd_cat() {
	[ $# -ge 1 ] && [ $# -le 2 ] || usage
	check_path "$1"
	resolve "${2:-}"
	_status=$(request GET "releases/$release/$1")
	case $_status in
	200) cat "$tmp/body" ;;
	404) die "no $1 in release $release" ;;
	*) die "GET releases/$release/$1: HTTP $_status" ;;
	esac
}

cmd_fetch() {
	[ $# -ge 1 ] && [ $# -le 2 ] || usage
	dest=${1%/}
	[ ! -e "$dest" ] || die "'$dest' already exists"
	resolve "${2:-}"
	_status=$(request GET "manifests/$release")
	case $_status in
	200) cp "$tmp/body" "$tmp/manifest" ;;
	404) die "no complete release $release" ;;
	*) die "GET manifests/$release: HTTP $_status" ;;
	esac
	# Download next to DEST and rename it at the end, so DEST is either
	# missing or the whole release.
	partial=$(mktemp -d "$dest.XXXXXX")
	while read -r _hex path; do
		check_path "$path"
		mkdir -p "$partial/$(dirname "$path")"
		_status=$(request GET "releases/$release/$path")
		[ "$_status" = 200 ] || die "GET releases/$release/$path: HTTP $_status"
		[ "$(sha256_hex "$tmp/body")" = "$_hex" ] || die "releases/$release/$path doesn't match its manifest"
		mv "$tmp/body" "$partial/$path"
	done <"$tmp/manifest"
	mv "$partial" "$dest"
	partial=''
	echo "$0: fetched $(wc -l <"$tmp/manifest" | tr -d ' ') files of $release into $dest" >&2
}

cmd_gc() {
	[ $# -le 2 ] || usage
	keep=${1:-5} minutes=${2:-60}
	case $keep in '' | *[!0-9]* | 0) die "KEEP must be a number above 0, not '$keep'" ;; esac
	case $minutes in '' | *[!0-9]*) die "MINUTES must be a number, not '$minutes'" ;; esac
	command -v sqlite3 >/dev/null || die 'gc needs sqlite3'
	db=$DATA/$BUCKET.sqlite3
	[ -f "$db" ] || die "no bucket database at $db"

	raised=''
	for _try in 1 2 3 4 5; do
		read_current
		[ "$cur_status" = 200 ] || die "nothing is published"
		# The floor is the oldest of the KEEP-th newest release, the current
		# one and the start of the last MINUTES, and it never goes down:
		# rollback refuses anything below it, and that is all gc deletes.
		floor=''
		kth=$(sqlite3 "$db" '.timeout 5000' \
			"SELECT substr(name, 11) FROM sqlar WHERE name >= 'manifests/' AND name < 'manifests0' ORDER BY name DESC LIMIT 1 OFFSET $((keep - 1))")
		if [ -n "$kth" ]; then # otherwise there are KEEP or fewer releases
			check_release "$kth"
			floor=$(min "$kth" "$cur_release")
			# The lowest ID of the grace period's first second, so the floor
			# is always a valid release ID.
			floor=$(min "$floor" "$(utc "$ID_TIME" $(($(date -u +%s) - minutes * 60)))-00000000")
		fi
		if [ -z "$floor" ] || { [ -n "$cur_floor" ] && [ "$(min "$floor" "$cur_floor")" = "$floor" ]; }; then
			floor=$cur_floor raised=no
			break
		fi
		# Raise the floor with If-Match before deleting anything, so a
		# rollback or publish that read the old pointer gets 412 and reads
		# the new floor.
		_status=$(put_current "$cur_release" "$cur_previous" "$floor")
		case $_status in
		200) raised=yes; break ;;
		412) ;;
		*) cat "$tmp/body" >&2; die "PUT current: HTTP $_status" ;;
		esac
	done
	[ -n "$raised" ] || die "current kept changing; giving up"
	[ -n "$floor" ] || { echo "$0: nothing to delete" >&2; return; }

	# Everything below the floor is two ranges of the name index. A release
	# whose ID equals the floor has keys after 'releases/<floor>', so it stays.
	n=$(sqlite3 "$db" '.timeout 5000' "BEGIN;
DELETE FROM sqlar WHERE name >= 'manifests/' AND name < 'manifests/$floor'; SELECT changes();
DELETE FROM sqlar WHERE name >= 'releases/' AND name < 'releases/$floor'; SELECT changes();
COMMIT;" | tr '\n' ' ')
	set -- $n
	echo "$0: deleted $1 releases ($2 files) below $floor" >&2
}

[ $# -ge 1 ] || usage
cmd=$1
shift
tmp=$(mktemp -d)
partial=''
trap 'rm -rf "$tmp" ${partial:+"$partial"}' EXIT
case $cmd in
publish) cmd_publish "$@" ;;
rollback) cmd_rollback "$@" ;;
current) cmd_current "$@" ;;
releases) cmd_releases "$@" ;;
cat) cmd_cat "$@" ;;
fetch) cmd_fetch "$@" ;;
gc) cmd_gc "$@" ;;
*) usage ;;
esac
