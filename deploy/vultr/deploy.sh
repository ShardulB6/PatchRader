#!/bin/sh
# Pull the latest main, rebuild, and restart the dashboard. Run as root on the server.
set -eu

APP=/srv/patchrader/app
as_app() { sudo -u patchrader -H "$@"; }

as_app git -C "$APP" pull --ff-only
cd "$APP"
as_app env CI=true pnpm install --frozen-lockfile
as_app env NODE_ENV=production pnpm build
systemctl restart patchrader

sleep 3
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/story)
echo "Deployed $(as_app git -C "$APP" log --oneline -1); /story returned $code"
[ "$code" = 200 ]
