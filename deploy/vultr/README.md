# Vultr deployment

The dashboard runs on a Vultr Shared CPU server (`vc2-2c-4gb`, Toronto, Ubuntu 26.04 LTS) at
https://155-138-145-151.sslip.io. [sslip.io](https://sslip.io) maps that name to the server's IP so it can have an HTTPS certificate before the project has its own domain.

| File                 | Installed as                             | What it does                                                                                                    |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `patchrader.service` | `/etc/systemd/system/patchrader.service` | Runs the built app with `srvx` on `127.0.0.1:3000`, read-only and sandboxed, and restarts it on crash or reboot |
| `patchrader-api.service` | `/etc/systemd/system/patchrader-api.service` | Runs the AI analyst API (`backend/`, FastAPI) on `127.0.0.1:8000`, sandboxed the same way                  |
| `Caddyfile`          | `/etc/caddy/Caddyfile`                   | Serves HTTPS on ports 80 and 443, sends `/api/*` to the API and everything else to the app                     |
| `deploy.sh`          | `/usr/local/bin/patchrader-deploy`       | Builds `main` in a new release folder, switches to it, and switches back if `/story` or the API's `/ready` doesn't return 200 |

On the server, `/srv/patchrader` holds:

- `releases/<commit>/`: one full build per deploy. The three newest are kept.
- `current`: a link to the release being served.
- `shared/.env.local`: settings that aren't in git. Every release links to it.
- `shared/data/`: the IBM track dataset the API reads. `deploy.sh` downloads it on the first deploy.

The API's watsonx.ai credentials and limits are in `/etc/patchrader/api.env` (root only, not in git). Its keys are listed in `backend/.env.example`. After changing it, run `systemctl restart patchrader-api`.

The API allows each visitor `CHAT_PER_MINUTE` questions a minute (default 6). It uses watsonx.ai for at most `WATSONX_DAILY_LIMIT` questions a UTC day (default 100). After that, answers come from the keyword router without watsonx.ai, so the Lite token allowance isn't used up.

## Update the live site

The server runs its own copy of `deploy.sh`, `Caddyfile` and the unit files. When a PR changes any of them, install the new copies before deploying:

```sh
scp deploy/vultr/deploy.sh root@155.138.145.151:/usr/local/bin/patchrader-deploy
scp deploy/vultr/*.service root@155.138.145.151:/etc/systemd/system/
scp deploy/vultr/Caddyfile root@155.138.145.151:/etc/caddy/Caddyfile
ssh root@155.138.145.151 'systemctl daemon-reload && systemctl enable patchrader-api && patchrader-deploy && systemctl reload caddy'
```

Otherwise:

After a PR merges into `main`:

```sh
ssh root@155.138.145.151 patchrader-deploy
```

The current release keeps serving while the new one builds, so a failed build doesn't touch the live site. If the new release fails its health check, the script switches back and exits with an error.

To go back to an earlier release by hand:

```sh
ls -t /srv/patchrader/releases
ln -sfn /srv/patchrader/releases/<commit> /srv/patchrader/current && systemctl restart patchrader patchrader-api
```

## Database

When a page needs Tiger Cloud, put the connection string in the shared settings file (not in git) and restart:

```sh
sudo -u patchrader tee /srv/patchrader/shared/.env.local >/dev/null <<'EOF'
DATABASE_URL=postgres://USER:PASSWORD@HOST:PORT/tsdb?sslmode=require
EOF
systemctl restart patchrader
```

## Logs

```sh
journalctl -u patchrader -f       # the app
journalctl -u patchrader-api -f   # the AI analyst API
journalctl -u caddy -f        # HTTPS and proxy
```

## Rebuild the server from scratch

On a fresh Ubuntu server, as root:

1. `apt-get install python3-venv` for the API. Install Node 26.13 from nodejs.org into `/opt/node` and link `node`, `npm` and `npx` into `/usr/local/bin`. Then run `npm install -g pnpm@12.18.0 srvx@1.0.8` and link `pnpm` and `srvx` the same way.
2. Create the app user and its folders:
   ```sh
   useradd --system --create-home --home-dir /srv/patchrader --shell /usr/sbin/nologin patchrader
   install -d -o patchrader -g patchrader -m 750 /srv/patchrader/releases /srv/patchrader/shared
   install -o patchrader -g patchrader -m 600 /dev/null /srv/patchrader/shared/.env.local
   ```
3. `apt-get install caddy`, then copy the four files above to their installed paths. Create `/etc/patchrader/api.env` (mode 600) with the watsonx.ai settings from `backend/.env.example`. Change the IP in `Caddyfile` if the new server has a different one.
4. `systemctl daemon-reload && systemctl enable patchrader patchrader-api`
5. `patchrader-deploy` to build the first release and start the app.
6. `systemctl reload caddy` so Caddy picks up the new `Caddyfile`, since installing it started Caddy with its default config.
7. `ufw allow 80/tcp && ufw allow 443/tcp`

When the GoDaddy domain is registered, point its A record at the server's IP, add the domain to the first line of `Caddyfile`, and run `systemctl reload caddy`.
