#!/bin/sh
# Sign in with GitHub, keeping the OAuth client's state in featherd: start
# stores a single-use state record with the PKCE verifier under
# oauth-client/github.com/state/, and callback consumes it with a GET and an
# If-Match DELETE, exchanges the code, and links the GitHub user to a local
# user under oauth-client/github.com/users/.
#
# Needs curl, jq and openssl, and sqlite3 for sweep.
set -eu

FEATHERD=${FEATHERD:-http://127.0.0.1:8333}
BUCKET=${BUCKET:-app}
DATA=${DATA:-data}
GITHUB=${GITHUB:-https://github.com}
GITHUB_API=${GITHUB_API:-https://api.github.com}
SCOPE=${SCOPE:-read:user}
STATE_TTL=${STATE_TTL:-600} # seconds a sign-in may take, as RFC 6749 suggests for codes

PREFIX=oauth-client/github.com

usage() {
	cat >&2 <<EOF
usage: $0 start REDIRECT_URI BROWSER_ID
                          store a state record and print the URL to send the browser to
       $0 callback STATE CODE BROWSER_ID
                          consume the state, exchange the code and print the local user ID
       $0 user GITHUB_ID  print the GitHub user's record, without its tokens
       $0 sweep [MINUTES] delete state records older than MINUTES (default 10)

BROWSER_ID is a random value the app keeps in a cookie for the browser that
starts the sign-in; the callback must come from the same browser.
start and callback need GITHUB_CLIENT_ID, and callback GITHUB_CLIENT_SECRET.

FEATHERD=$FEATHERD BUCKET=$BUCKET DATA=$DATA
GITHUB=$GITHUB GITHUB_API=$GITHUB_API SCOPE=$SCOPE STATE_TTL=$STATE_TTL
EOF
	exit 2
}

die() {
	echo "$0: $*" >&2
	exit 1
}

# sha256 prints the hex SHA-256 of its stdin.
sha256() {
	openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
}

# base64url prints its stdin as unpadded base64url (RFC 4648 §5).
base64url() {
	openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# request METHOD KEY [CURL ARGS...] sends a request to featherd, saving the
# body to $tmp/body and the headers to $tmp/headers, and prints the status.
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

create_bucket() {
	_status=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$FEATHERD/$BUCKET")
	case $_status in
	200 | 409) ;; # 409 BucketAlreadyOwnedByYou: it already exists
	*) die "creating bucket $BUCKET: HTTP $_status" ;;
	esac
}

cmd_start() {
	[ $# -eq 2 ] || usage
	redirect_uri=$1 browser=$2
	[ -n "${GITHUB_CLIENT_ID:-}" ] || die 'GITHUB_CLIENT_ID is not set'
	[ -n "$browser" ] || die 'empty BROWSER_ID'
	create_bucket

	# 256 random bits each: the state names the record, so it must be
	# unguessable (RFC 6749 §10.10), and the PKCE verifier is 64 characters
	# of base64url (RFC 7636 §4.1).
	state=$(openssl rand -hex 32)
	verifier=$(openssl rand 48 | base64url)
	challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | base64url)
	# Only a hash of the browser ID is stored, so reading the bucket doesn't
	# reveal the cookie.
	json=$(jq -cn --arg r "$redirect_uri" --arg v "$verifier" --arg b "$(printf '%s' "$browser" | sha256)" \
		--argjson now "$(date -u +%s)" '{redirect_uri: $r, code_verifier: $v, browser: $b, created_at: $now}')
	# If-None-Match: * so a state is only ever issued once, however unlikely
	# a repeat is.
	_status=$(put_json "$PREFIX/state/$state" "$json" 'If-None-Match: *')
	[ "$_status" = 200 ] || { cat "$tmp/body" >&2; die "PUT $PREFIX/state/$state: HTTP $_status"; }

	jq -rn --arg base "$GITHUB" --arg c "$GITHUB_CLIENT_ID" --arg r "$redirect_uri" --arg s "$SCOPE" \
		--arg st "$state" --arg ch "$challenge" \
		'"\($base)/login/oauth/authorize?client_id=\($c|@uri)&redirect_uri=\($r|@uri)&scope=\($s|@uri)&state=\($st)&code_challenge=\($ch)&code_challenge_method=S256"'
}

cmd_callback() {
	[ $# -eq 3 ] || usage
	state=$1 code=$2 browser=$3
	[ -n "${GITHUB_CLIENT_ID:-}" ] || die 'GITHUB_CLIENT_ID is not set'
	[ -n "${GITHUB_CLIENT_SECRET:-}" ] || die 'GITHUB_CLIENT_SECRET is not set'
	# The state comes back in the URL, so check it's one of ours before
	# using it in a key.
	case $state in *[!0123456789abcdef]*) die 'malformed state' ;; esac
	[ ${#state} -eq 64 ] || die 'malformed state'
	[ -n "$code" ] && [ ${#code} -le 512 ] || die 'malformed code'
	key=$PREFIX/state/$state

	# Consume the state: read it, then delete it If-Match its ETag. Of any
	# callbacks racing with the same state, only one gets 204 (RFC 6749
	# §10.12: the state is used once).
	_status=$(request GET "$key")
	case $_status in
	200) ;;
	404) die 'unknown or already used state' ;;
	*) die "GET $key: HTTP $_status" ;;
	esac
	cp "$tmp/body" "$tmp/state"
	_status=$(request DELETE "$key" -H "If-Match: $(etag)")
	case $_status in
	204) ;;
	412) die 'state already used' ;;
	*) die "DELETE $key: HTTP $_status" ;;
	esac
	# Checked after the delete, so a state that fails them can't be retried.
	[ $(($(jq .created_at "$tmp/state") + STATE_TTL)) -ge "$(date -u +%s)" ] || die 'state expired'
	[ "$(printf '%s' "$browser" | sha256)" = "$(jq -r .browser "$tmp/state")" ] ||
		die 'state was issued to a different browser'

	# Exchange the code. The form goes in a file so the secret, the code and
	# the verifier stay out of ps.
	jq -jn --arg c "$GITHUB_CLIENT_ID" --arg s "$GITHUB_CLIENT_SECRET" --arg code "$code" \
		--arg r "$(jq -r .redirect_uri "$tmp/state")" --arg v "$(jq -r .code_verifier "$tmp/state")" \
		'"client_id=\($c|@uri)&client_secret=\($s|@uri)&code=\($code|@uri)&redirect_uri=\($r|@uri)&code_verifier=\($v|@uri)"' >"$tmp/form"
	curl -sS -o "$tmp/token" -H 'Accept: application/json' --data-binary "@$tmp/form" "$GITHUB/login/oauth/access_token" ||
		die 'exchanging the code failed'
	# GitHub answers 200 with an "error" field when the code is bad.
	jq -e '.access_token | strings' "$tmp/token" >/dev/null ||
		die "exchanging the code: $(jq -r '"\(.error // "no access_token"): \(.error_description // "")"' "$tmp/token" 2>/dev/null || echo 'not JSON')"

	jq -r '"Authorization: Bearer \(.access_token)"' "$tmp/token" >"$tmp/auth"
	_status=$(curl -sS -o "$tmp/user" -w '%{http_code}' -H "@$tmp/auth" \
		-H 'Accept: application/vnd.github+json' "$GITHUB_API/user")
	[ "$_status" = 200 ] || die "GET $GITHUB_API/user: HTTP $_status"
	id=$(jq -r '.id | numbers' "$tmp/user")
	[ -n "$id" ] || die 'GitHub user has no numeric id'

	link "$id"
	echo "$local_user"
}

# link GITHUB_ID upserts the GitHub user's record, keeping the local user it
# already points at or linking a new one, and sets $local_user.
link() {
	_key=$PREFIX/users/$1
	_now=$(date -u +%s)
	_tries=0
	while [ $_tries -lt 5 ]; do
		_tries=$((_tries + 1))
		_status=$(request GET "$_key")
		case $_status in
		200)
			# Seen before: update the profile and tokens If-Match what was
			# read, so a concurrent sign-in of the same user isn't lost.
			local_user=$(jq -r .local_user "$tmp/body")
			_created=$(jq .created_at "$tmp/body")
			_condition="If-Match: $(etag)"
			;;
		404)
			# First sign-in: If-None-Match: * so that of two racing first
			# sign-ins, only one picks the local user.
			local_user=users/$(openssl rand -hex 16)
			_created=$_now
			_condition='If-None-Match: *'
			;;
		*) die "GET $_key: HTTP $_status" ;;
		esac
		json=$(jq -c --slurpfile t "$tmp/token" --arg l "$local_user" --argjson c "$_created" --argjson now "$_now" '
			{id, login, name, email, local_user: $l,
			 access_token: $t[0].access_token, scope: $t[0].scope,
			 refresh_token: $t[0].refresh_token,
			 token_expires_at: (if $t[0].expires_in then $now + $t[0].expires_in else null end),
			 created_at: $c, updated_at: $now}' "$tmp/user")
		_status=$(put_json "$_key" "$json" "$_condition")
		case $_status in
		200) break ;;
		412) continue ;; # changed since it was read; read it again
		*) cat "$tmp/body" >&2; die "PUT $_key: HTTP $_status" ;;
		esac
	done
	[ "$_status" = 200 ] || die "PUT $_key kept conflicting"

	# Create the local user if it's new. The link is written first, so a
	# crash between the two leaves a link this repairs on the next sign-in,
	# and never a local user nothing points at. 412: it exists.
	_status=$(put_json "$local_user" "$(jq -cn --argjson now "$_now" --argjson g "$1" '{created_at: $now, github: $g}')" 'If-None-Match: *')
	case $_status in
	200 | 412) ;;
	*) cat "$tmp/body" >&2; die "PUT $local_user: HTTP $_status" ;;
	esac
}

cmd_user() {
	[ $# -eq 1 ] || usage
	case $1 in '' | *[!0123456789]*) die "GitHub user IDs are numbers, not '$1'" ;; esac
	_status=$(request GET "$PREFIX/users/$1")
	case $_status in
	200) jq -c 'del(.access_token, .refresh_token)' "$tmp/body" ;;
	404) die "no record of $PREFIX/users/$1" ;;
	*) die "GET $PREFIX/users/$1: HTTP $_status" ;;
	esac
}

cmd_sweep() {
	[ $# -le 1 ] || usage
	minutes=${1:-10}
	case $minutes in '' | *[!0-9]*) die "MINUTES must be a number, not '$minutes'" ;; esac
	command -v sqlite3 >/dev/null || die 'sweep needs sqlite3'
	db=$DATA/$BUCKET.sqlite3
	[ -f "$db" ] || die "no bucket database at $db"
	# State records are written once, so sqlar's mtime is when the sign-in
	# started. '0' sorts just after '/', so the range is exactly the state
	# records.
	cutoff=$(($(date -u +%s) - minutes * 60))
	n=$(sqlite3 "$db" '.timeout 5000' \
		"DELETE FROM sqlar WHERE name >= '$PREFIX/state/' AND name < '$PREFIX/state0' AND mtime < $cutoff; SELECT changes();")
	echo "deleted $n sign-ins started more than $minutes minutes ago" >&2
}

[ $# -ge 1 ] || usage
cmd=$1
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case $cmd in
start) cmd_start "$@" ;;
callback) cmd_callback "$@" ;;
user) cmd_user "$@" ;;
sweep) cmd_sweep "$@" ;;
*) usage ;;
esac
