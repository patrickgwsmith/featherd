#!/bin/sh
# Store official font releases in featherd and look files up by version or by
# SHA-256 digest. Each file's bytes are stored once, under sha256/<hex>; each
# release is a SHA256SUMS manifest at <family>/<version>/SHA256SUMS listing
# the release's paths and digests.
#
# Needs curl and shasum (macOS) or sha256sum (Linux).
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-fonts}

usage() {
	cat >&2 <<EOF
usage: $0 put FAMILY VERSION DIR       store every file under DIR as a release
       $0 versions FAMILY              list stored versions of FAMILY
       $0 files FAMILY VERSION         print the release's SHA256SUMS
       $0 get FAMILY VERSION PATH [OUT]
                                       fetch a file by version and path
       $0 get-sha256 HEX [OUT]         fetch a file by digest
       $0 find HEX                     list releases containing a digest

FEATHERD=$FEATHERD BUCKET=$BUCKET
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

# Family and version names become key segments; keep them URL-safe.
check_name() {
	case $1 in
	'' | *[!A-Za-z0-9._-]*) die "invalid $2 '$1': use letters, digits, '.', '_' and '-'" ;;
	esac
}

check_digest() {
	case $1 in
	*[!0-9a-f]*) die "invalid digest '$1': want 64 lowercase hex characters" ;;
	esac
	[ ${#1} -eq 64 ] || die "invalid digest '$1': want 64 lowercase hex characters"
}

content_type() {
	case $1 in
	*.woff2) echo font/woff2 ;;
	*.woff) echo font/woff ;;
	*.ttf) echo font/ttf ;;
	*.otf) echo font/otf ;;
	*.ttc) echo font/collection ;;
	*.txt | */SHA256SUMS) echo 'text/plain; charset=utf-8' ;;
	*) echo application/octet-stream ;;
	esac
}

# put_once KEY FILE DIGEST prints the HTTP status of a create-if-absent PUT.
# featherd checks the body against x-amz-content-sha256 and stores nothing on
# a mismatch.
put_once() {
	curl -sS -o /dev/null -w '%{http_code}' -X PUT \
		-H 'If-None-Match: *' \
		-H "x-amz-content-sha256: $3" \
		-H "Content-Type: $(content_type "$2")" \
		--data-binary "@$2" "$FEATHERD/$BUCKET/$1"
}

# ensure_bucket creates the bucket; 409 BucketAlreadyOwnedByYou means it exists.
ensure_bucket() {
	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200) echo "created  bucket $BUCKET" >&2 ;;
	409) ;;
	*) die "PUT /$BUCKET returned $_status" ;;
	esac
}

# fetch KEY OUT downloads an object to OUT, or to stdout if OUT is -, and
# prints featherd's XML error on failure.
fetch() {
	_out=$2
	[ "$_out" != - ] || _out=$(mktemp)
	if ! curl -sS --fail-with-body -o "$_out" "$FEATHERD/$BUCKET/$1"; then
		cat "$_out" >&2 2>/dev/null
		echo >&2
		rm -f "$_out"
		die "GET $1 failed"
	fi
	if [ "$2" = - ]; then
		cat "$_out"
		rm -f "$_out"
	fi
}

# list_keys PREFIX prints every key under PREFIX, following pagination.
list_keys() {
	token=
	while :; do
		url="$FEATHERD/$BUCKET?list-type=2&prefix=$1"
		[ -z "$token" ] || url="$url&continuation-token=$token"
		page=$(curl -sS --fail-with-body "$url") || die "listing failed: $page"
		printf '%s' "$page" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' || true
		token=$(printf '%s' "$page" | grep -o '<NextContinuationToken>[^<]*' | sed 's/.*>//' || true)
		[ -n "$token" ] || break
	done
}

# fetch_verified DIGEST OUT downloads sha256/DIGEST and checks its bytes.
fetch_verified() {
	if [ "$2" = - ]; then
		_part=$(mktemp)
	else
		_part="$2.part.$$"
	fi
	fetch "sha256/$1" "$_part"
	_got=$(sha256 "$_part")
	if [ "$_got" != "$1" ]; then
		rm -f "$_part"
		die "sha256/$1 has digest $_got"
	fi
	if [ "$2" = - ]; then
		cat "$_part"
		rm -f "$_part"
	else
		mv "$_part" "$2"
	fi
}

cmd_put() {
	[ $# -eq 3 ] || usage
	family=$1 version=$2 dir=$3
	check_name "$family" family
	check_name "$version" version
	[ -d "$dir" ] || die "$dir is not a directory"
	ensure_bucket

	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	manifest="$work/SHA256SUMS"
	(cd "$dir" && find . -type f ! -name '.*' | sed 's|^\./||' | LC_ALL=C sort) >"$work/paths"
	# Blobs go up first, so a manifest never names a digest that isn't stored.
	# The loop reads a file rather than a pipe so die exits the script.
	while IFS= read -r path; do
		digest=$(sha256 "$dir/$path")
		status=$(put_once "sha256/$digest" "$dir/$path" "$digest")
		case $status in
		200) echo "stored   sha256/$digest  $path" >&2 ;;
		# The key is the digest featherd verified, so the stored bytes are identical.
		412) echo "present  sha256/$digest  $path" >&2 ;;
		*) die "PUT sha256/$digest ($path) returned $status" ;;
		esac
		printf '%s  %s\n' "$digest" "$path" >>"$manifest"
	done <"$work/paths"
	[ -s "$manifest" ] || die "no files under $dir"

	key="$family/$version/SHA256SUMS"
	status=$(put_once "$key" "$manifest" "$(sha256 "$manifest")")
	case $status in
	200) echo "stored   $key ($(wc -l <"$manifest" | tr -d ' ') files)" >&2 ;;
	412)
		# Releases are immutable: re-running with the same files is fine,
		# different files for an existing version is not.
		fetch "$key" "$work/existing"
		cmp -s "$work/existing" "$manifest" || die "$key already exists with different files"
		echo "present  $key" >&2
		;;
	*) die "PUT $key returned $status" ;;
	esac
}

cmd_versions() {
	[ $# -eq 1 ] || usage
	check_name "$1" family
	# Listed before piping, so a failed listing (e.g. NoSuchBucket) exits non-zero.
	keys=$(list_keys "$1/")
	printf '%s\n' "$keys" | sed -n "s|^$1/\([^/]*\)/SHA256SUMS\$|\1|p"
}

cmd_files() {
	[ $# -eq 2 ] || usage
	check_name "$1" family
	check_name "$2" version
	fetch "$1/$2/SHA256SUMS" -
}

cmd_get() {
	[ $# -eq 3 ] || [ $# -eq 4 ] || usage
	check_name "$1" family
	check_name "$2" version
	out=${4:-$(basename "$3")}
	sums=$(fetch "$1/$2/SHA256SUMS" -)
	digest=$(printf '%s\n' "$sums" | awk -v p="$3" '{ d = $1; sub(/^[0-9a-f]+  /, ""); if ($0 == p) { print d; exit } }')
	[ -n "$digest" ] || die "$1 $2 has no file $3"
	fetch_verified "$digest" "$out"
	[ "$out" = - ] || echo "$out  sha256:$digest" >&2
}

cmd_get_sha256() {
	[ $# -eq 1 ] || [ $# -eq 2 ] || usage
	check_digest "$1"
	out=${2:-$1}
	fetch_verified "$1" "$out"
	[ "$out" = - ] || echo "$out" >&2
}

cmd_find() {
	[ $# -eq 1 ] || usage
	check_digest "$1"
	keys=$(list_keys "")
	{ printf '%s\n' "$keys" | grep '/SHA256SUMS$' || true; } | while IFS= read -r key; do
		fetch "$key" - | awk -v d="$1" -v k="${key%/SHA256SUMS}" '$1 == d { sub(/^[0-9a-f]+  /, ""); print k "  " $0 }'
	done
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
put) cmd_put "$@" ;;
versions) cmd_versions "$@" ;;
files) cmd_files "$@" ;;
get) cmd_get "$@" ;;
get-sha256) cmd_get_sha256 "$@" ;;
find) cmd_find "$@" ;;
*) usage ;;
esac
