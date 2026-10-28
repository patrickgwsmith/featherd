#!/usr/bin/env bash
# Deploy one or more examples to a Linux server with systemd: one shared
# featherd, a timer per example, and a Caddy site serving each example's
# published pages at http://<host>:$PORT/<example>/.
#
#   git push exe main
#   ssh featherd.exe.xyz bash -s -- rss-reader rss-reader-qip < examples/deploy.sh
#
# An example is deployable if it has a deploy.conf, which this script
# sources in the example's directory. It sets:
#
#   bucket    its own bucket, $DATA/$bucket.sqlite3 [the example's name]
#   seed      KEY=FILE pairs, each uploaded only while KEY is missing
#   publish   KEY=PATH pairs, each copied to $WWW/<example>/PATH after a run
#   check()   optional: stop with die if the server can't run it
#   build()   optional: build it, writing any one binary to $bin
#   run()     poll once; $bin, FEATHERD and BUCKET are set
#
# Safe to run again: it pulls, rebuilds, rewrites only the files that
# changed, restarts only what they affect, and never overwrites a seeded
# key once it's in the bucket. Examples left off the command line keep
# running; stop one with
#   sudo systemctl disable --now featherd-example@<example>.timer
#
# featherd listens on 127.0.0.1 only and, by default, requires SigV4. The
# key pair is made once into /etc/featherd/auth.env (root, 0600), which
# systemd gives to featherd and every example, and which this script reads
# with sudo to sign its own requests. AUTH=none runs featherd without
# authentication instead; the key file is kept for switching back.
# Caddy serves copies of the published keys from $WWW, not featherd itself.
#
# Environment (defaults in brackets):
#   AUTH   featherd's FEATHERD_AUTH, sigv4 or none [sigv4]
#   REPO   bare repo to clone [~/featherd.git]
#   SRC    checkout [~/featherd]
#   DATA   featherd's --dir [~/featherd-data]
#   WWW    Caddy's site root [/var/www/featherd]
#   PORT   Caddy's port [8000]
#   EVERY  time between runs of each example [15min]

main() {
	set -euo pipefail
	export PATH="$PATH:/usr/local/go/bin"
	export SRC=${SRC:-$HOME/featherd}
	export DATA=${DATA:-$HOME/featherd-data}
	export WWW=${WWW:-/var/www/featherd}
	export FEATHERD=http://127.0.0.1:8333
	local repo=${REPO:-$HOME/featherd.git}
	local port=${PORT:-8000}
	local every=${EVERY:-15min}
	local auth=${AUTH:-sigv4}
	local keys=/etc/featherd/auth.env
	local user group name
	user=$(id -un)
	group=$(id -gn)

	(($#)) || die "usage: deploy.sh EXAMPLE..."
	[[ $auth == sigv4 || $auth == none ]] || die "AUTH=$auth: use sigv4 or none"
	if [[ $auth == sigv4 ]]; then
		[[ $(curl --help all) == *--aws-sigv4* ]] ||
			die "curl needs --aws-sigv4 support for AUTH=sigv4"
	fi

	# Go 1.26 or newer, for featherd.
	local v
	v=$(go env GOVERSION) || die "Go isn't installed; install Go 1.26 or newer"
	v=${v#go}
	local major=${v%%.*} rest=${v#*.}
	local minor=${rest%%.*}
	((major > 1 || (major == 1 && minor >= 26))) || die "found Go $v; need 1.26 or newer"

	# The checkout.
	if [[ -d $SRC/.git ]]; then
		git -C "$SRC" pull --ff-only -q </dev/null
	else
		git clone -q "$repo" "$SRC" </dev/null
	fi

	# Check every example before changing anything else.
	for name; do
		[[ -f $SRC/examples/$name/deploy.conf ]] || die "examples/$name has no deploy.conf"
		(
			load "$name"
			if declare -F check >/dev/null; then check; fi
		) </dev/null
	done

	# Caddy.
	if ! command -v caddy >/dev/null; then
		log "installing caddy"
		sudo apt-get update -q </dev/null
		sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq caddy </dev/null
	fi

	# Binaries, replaced only if the build differs. A failed build stops
	# here, before anything is replaced.
	mkdir -p "$SRC/bin" "$DATA"
	rm -f "$SRC/bin/.featherd.new"
	(cd "$SRC"; go build -o "$SRC/bin/.featherd.new" .) </dev/null
	replace "$SRC/bin/.featherd.new" "$SRC/bin/featherd" && restart_featherd=1
	for name; do
		rm -f "$SRC/bin/.$name.new"
		(
			load "$name"
			touch "$DATA/$bucket.sqlite3"
			bin=$SRC/bin/.$name.new
			if declare -F build >/dev/null; then build; fi
		) </dev/null
		if [[ -e $SRC/bin/.$name.new ]]; then
			replace "$SRC/bin/.$name.new" "$SRC/bin/$name" || true
		fi
	done
	sudo install -d -o "$user" -g "$group" -m 755 "$WWW"

	# The key pair, made once. featherd reads FEATHERD_*, the examples and
	# fcurl AWS_*. Under AUTH=none it's left alone and not loaded, since
	# featherd refuses to start with both.
	local env_file=
	if [[ $auth == sigv4 ]]; then
		if ! sudo test -s "$keys"; then
			log "making a key pair in $keys"
			local secret
			secret=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
			((${#secret} == 64)) || die "couldn't make a secret"
			sudo install -d -m 700 "${keys%/*}"
			# Create or reset the file with restricted permissions before writing
			# the secret; tee must never create it with the default umask.
			sudo install -m 600 /dev/null "$keys"
			printf '%s\n' \
				FEATHERD_ACCESS_KEY_ID=featherd \
				"FEATHERD_SECRET_ACCESS_KEY=$secret" \
				AWS_ACCESS_KEY_ID=featherd \
				"AWS_SECRET_ACCESS_KEY=$secret" |
				sudo tee "$keys" >/dev/null
		fi
		set -a
		. <(sudo cat "$keys")
		set +a
		[[ -n ${AWS_ACCESS_KEY_ID:-} && -n ${AWS_SECRET_ACCESS_KEY:-} ]] ||
			die "$keys has no AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
		env_file="EnvironmentFile=$keys"
	else
		unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
	fi

	# featherd.
	put /etc/systemd/system/featherd.service <<-EOF && restart_featherd=1
		[Unit]
		Description=featherd
		After=network.target

		[Service]
		User=$user
		Environment=FEATHERD_AUTH=$auth
		$env_file
		ExecStart=$SRC/bin/featherd --addr 127.0.0.1:8333 --dir $DATA
		Restart=on-failure

		[Install]
		WantedBy=multi-user.target
	EOF

	# The examples: one run, then copy its published keys into the site
	# root. The runner is this script's run_example, written out on its own.
	put /usr/local/lib/featherd/run-example < <(
		echo '#!/usr/bin/env bash'
		echo '# Written by examples/deploy.sh.'
		declare -f run_example load fcurl log die
		echo 'run_example "$@"'
	) || true
	put /etc/systemd/system/featherd-example@.service <<-EOF || true
		[Unit]
		Description=featherd example %i
		Requires=featherd.service
		After=featherd.service

		[Service]
		Type=oneshot
		User=$user
		Environment="PATH=$PATH" SRC=$SRC WWW=$WWW FEATHERD=$FEATHERD
		$env_file
		ExecStart=/bin/bash /usr/local/lib/featherd/run-example %i
	EOF
	put /etc/systemd/system/featherd-example@.timer <<-EOF && restart_timers=1
		[Unit]
		Description=Run featherd example %i every $every

		[Timer]
		OnBootSec=1min
		OnUnitInactiveSec=$every

		[Install]
		WantedBy=timers.target
	EOF

	# Caddy. This replaces the default Caddyfile. / lists the examples.
	put /etc/caddy/Caddyfile <<-EOF && restart_caddy=1
		:$port {
			root * $WWW
			file_server browse {
				hide .*
			}
		}
	EOF

	local timers=()
	for name; do
		timers+=("featherd-example@$name.timer")
	done
	sudo systemctl daemon-reload
	sudo systemctl enable -q --now featherd.service caddy.service "${timers[@]}"
	if [[ -n ${restart_featherd:-} ]]; then
		log "restarting featherd"
		sudo systemctl restart featherd.service
	fi
	if [[ -n ${restart_timers:-} ]]; then
		log "restarting timers"
		sudo systemctl restart "${timers[@]}"
	fi
	if [[ -n ${restart_caddy:-} ]]; then
		log "reloading caddy"
		sudo systemctl reload-or-restart caddy.service
	fi
	wait_for "$FEATHERD/"

	# Seed each bucket.
	for name; do
		(
			load "$name"
			local s
			for s in "${seed[@]}"; do
				seed_key "${s%%=*}" "${s#*=}"
			done
		) </dev/null
	done

	# Run each example now rather than waiting for its timer.
	local failed=()
	for name; do
		log "running $name"
		if sudo systemctl start "featherd-example@$name.service"; then
			curl -fsS -o /dev/null "http://127.0.0.1:$port/$name/" || failed+=("$name")
		else
			failed+=("$name")
		fi
		journalctl -q -u "featherd-example@$name.service" -n 3 -o cat --no-pager </dev/null || true
	done
	((${#failed[@]} == 0)) ||
		die "failed: ${failed[*]}; see journalctl -u featherd-example@<example>.service"
	for name; do
		log "serving $name at :$port/$name/"
	done
}

# run_example NAME: run examples/NAME once, then copy each published key
# into $WWW/NAME/, renamed into place so Caddy never serves half a file.
# featherd-example@.service runs it.
run_example() {
	set -euo pipefail
	local name=$1 p key path
	load "$name"
	run </dev/null
	for p in "${publish[@]}"; do
		key=${p%%=*}
		path=$WWW/$name/${p#*=}
		mkdir -p "${path%/*}"
		fcurl -fsS -o "${path%/*}/.${path##*/}" "$FEATHERD/$bucket/$key"
		mv "${path%/*}/.${path##*/}" "$path"
	done
}

# load NAME: change to examples/NAME and read its deploy.conf.
load() {
	cd "$SRC/examples/$1"
	bucket=$1 bin=$SRC/bin/$1 seed=() publish=()
	unset -f check build run
	. ./deploy.conf
	declare -F run >/dev/null || die "examples/$1/deploy.conf defines no run"
	export BUCKET=$bucket bin
}

# seed_key KEY FILE: upload FILE to KEY in $bucket if KEY is missing.
seed_key() {
	local url=$FEATHERD/$bucket/$1 status
	status=$(fcurl -sS -I -o /dev/null -w '%{http_code}' "$url") || die "couldn't check $bucket/$1"
	case $status in
		200) ;;
		404)
			log "uploading $2 to $bucket/$1"
			fcurl -fsS -o /dev/null -T "$2" "$url" || die "couldn't upload $bucket/$1"
			;;
		*) die "checking $bucket/$1 returned HTTP $status" ;;
	esac
}

# fcurl ARG...: curl a featherd URL, signed with SigV4 when the key pair
# is in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The payload header is
# sent explicitly because older curls don't add it; featherd requires it.
fcurl() {
	if [[ -n ${AWS_ACCESS_KEY_ID:-} ]]; then
		curl --aws-sigv4 "aws:amz:${AWS_REGION:-us-east-1}:s3" \
			--user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
			-H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' "$@"
	else
		curl "$@"
	fi
}

# replace NEW OUT: move NEW to OUT if they differ. Succeeds only if OUT
# changed.
replace() {
	if cmp -s "$1" "$2"; then
		rm -f "$1"
		return 1
	fi
	chmod 755 "$1" && mv "$1" "$2" || die "couldn't install $2"
	log "built $2"
}

# put FILE: write stdin to FILE as root if it differs. Succeeds only if
# FILE changed.
put() {
	local tmp
	tmp=$(mktemp) || die "mktemp failed"
	cat >"$tmp" || die "couldn't write a temp file for $1"
	if sudo cmp -s "$tmp" "$1"; then
		rm -f "$tmp"
		return 1
	fi
	if ! sudo install -D -m 644 "$tmp" "$1"; then
		rm -f "$tmp"
		die "couldn't write $1"
	fi
	rm -f "$tmp"
	log "wrote $1"
}

# wait_for URL: wait up to 10s for URL to answer at all.
wait_for() {
	local i
	for i in $(seq 50); do
		curl -s -o /dev/null "$1" && return
		sleep 0.2
	done
	die "nothing answered at $1"
}

log() { echo "deploy: $*" >&2; }
die() {
	log "$*"
	exit 1
}

# main is called on the last line so that, under `bash -s`, the whole
# script is read before anything runs and nothing it runs eats stdin.
main "$@"
