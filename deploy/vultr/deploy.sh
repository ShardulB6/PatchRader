#!/bin/sh
# Build the latest main in its own release folder while the current one keeps
# serving, switch to it, and switch back if it fails the health check.
# Run as root on the server.
set -eu

BASE=/srv/patchrader
REPO=https://github.com/ShardulB6/PatchRader.git
BUILD=$BASE/releases/.building
as_app() { sudo -u patchrader -H "$@"; }

check() {
	i=0
	while [ "$i" -lt 60 ]; do
		code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1" || true)
		[ "$code" = 200 ] && return 0
		i=$((i + 1))
		sleep 1
	done
	echo "$1 returned ${code:-nothing} after 60 s" >&2
	return 1
}
# Releases from before the API existed have no backend/, so only check and
# run the API when the served release has one.
has_api() { [ -d "$BASE/current/backend" ]; }
# /ready loads the dataset, so it fails if the API can't read it.
healthy() {
	check http://127.0.0.1:3000/story || return 1
	has_api || return 0
	check http://127.0.0.1:8000/ready
}
restart() {
	if has_api; then
		systemctl restart patchrader patchrader-api
	else
		systemctl restart patchrader
		systemctl stop patchrader-api
	fi
}

exec 9>/run/patchrader-deploy.lock
flock -n 9 || { echo "Another deploy is already running" >&2; exit 1; }

rm -rf "$BUILD"
as_app git clone -q --depth 1 "$REPO" "$BUILD"
sha=$(as_app git -C "$BUILD" rev-parse --short=12 HEAD)
new=$BASE/releases/$sha

# Reuse a release only if it was fully built, including the API's venv.
if [ -x "$new/backend/.venv/bin/python" ]; then
	rm -rf "$BUILD"
else
	as_app ln -s "$BASE/shared/.env.local" "$BUILD/apps/web/.env.local"
	cd "$BUILD"
	as_app env CI=true pnpm install --frozen-lockfile
	as_app env NODE_ENV=production pnpm build
	as_app python3 -m venv backend/.venv
	as_app backend/.venv/bin/pip install -q --disable-pip-version-check -r backend/requirements-ai.txt
	# The dataset is shared by every release. Download it once.
	if [ ! -f "$BASE/shared/data/scoreboard_2026.csv" ]; then
		as_app python3 scripts/fetch_data.py
		rm -rf "$BASE/shared/data"
		mv data "$BASE/shared/data"
	fi
	cd /
	# An incomplete build of this commit may be the one being served, so move
	# it aside rather than deleting it under the running app.
	[ -d "$new" ] && mv "$new" "$BASE/releases/.incomplete-$sha-$$"
	mv "$BUILD" "$new"
fi

prev=""
[ -L "$BASE/current" ] && prev=$(readlink -f "$BASE/current")
ln -sfn "$new" "$BASE/current.next"
mv -T "$BASE/current.next" "$BASE/current"
restart

if ! healthy; then
	if [ -n "$prev" ] && [ "$prev" != "$new" ]; then
		echo "Rolling back to $(basename "$prev")" >&2
		ln -sfn "$prev" "$BASE/current.next"
		mv -T "$BASE/current.next" "$BASE/current"
		restart
		healthy && echo "Rollback is serving" >&2
	fi
	exit 1
fi

rm -rf "$BASE"/releases/.incomplete-*
# Keep the three newest releases, never the one being served or the previous one.
ls -1dt "$BASE"/releases/*/ | tail -n +4 | while read -r dir; do
	dir=${dir%/}
	[ "$dir" = "$new" ] || [ "$dir" = "$prev" ] || rm -rf "$dir"
done

echo "Deployed $sha: $(as_app git -C "$new" log -1 --format=%s)"
