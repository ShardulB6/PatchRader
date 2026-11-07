#!/bin/sh
# Build the latest main in its own release folder while the current one keeps
# serving, switch to it, and switch back if it fails the health check.
# Run as root on the server.
set -eu

BASE=/srv/patchrader
REPO=https://github.com/ShardulB6/PatchRader.git
BUILD=$BASE/releases/.building
as_app() { sudo -u patchrader -H "$@"; }

healthy() {
	i=0
	while [ "$i" -lt 30 ]; do
		code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/story || true)
		[ "$code" = 200 ] && return 0
		i=$((i + 1))
		sleep 1
	done
	echo "/story returned ${code:-nothing} after 30 s" >&2
	return 1
}

exec 9>/run/patchrader-deploy.lock
flock -n 9 || { echo "Another deploy is already running" >&2; exit 1; }

rm -rf "$BUILD"
as_app git clone -q --depth 1 "$REPO" "$BUILD"
sha=$(as_app git -C "$BUILD" rev-parse --short=12 HEAD)
new=$BASE/releases/$sha

if [ -d "$new" ]; then
	rm -rf "$BUILD"
else
	as_app ln -s "$BASE/shared/.env.local" "$BUILD/apps/web/.env.local"
	cd "$BUILD"
	as_app env CI=true pnpm install --frozen-lockfile
	as_app env NODE_ENV=production pnpm build
	cd /
	mv "$BUILD" "$new"
fi

prev=""
[ -L "$BASE/current" ] && prev=$(readlink -f "$BASE/current")
ln -sfn "$new" "$BASE/current.next"
mv -T "$BASE/current.next" "$BASE/current"
systemctl restart patchrader

if ! healthy; then
	if [ -n "$prev" ] && [ "$prev" != "$new" ]; then
		echo "Rolling back to $(basename "$prev")" >&2
		ln -sfn "$prev" "$BASE/current.next"
		mv -T "$BASE/current.next" "$BASE/current"
		systemctl restart patchrader
		healthy && echo "Rollback is serving" >&2
	fi
	exit 1
fi

# Keep the three newest releases, never the one being served or the previous one.
ls -1dt "$BASE"/releases/*/ | tail -n +4 | while read -r dir; do
	dir=${dir%/}
	[ "$dir" = "$new" ] || [ "$dir" = "$prev" ] || rm -rf "$dir"
done

echo "Deployed $sha: $(as_app git -C "$new" log -1 --format=%s)"
