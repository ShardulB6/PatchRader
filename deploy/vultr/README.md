# Vultr deployment

The dashboard runs on a Vultr Shared CPU server (`vc2-2c-4gb`, Toronto, Ubuntu 26.04 LTS) at
https://155-138-145-151.sslip.io. [sslip.io](https://sslip.io) maps that name to the server's IP so it can have an HTTPS certificate before the project has its own domain.

| File                 | Installed as                             | What it does                                                                                                    |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `patchrader.service` | `/etc/systemd/system/patchrader.service` | Runs the built app with `srvx` on `127.0.0.1:3000`, read-only and sandboxed, and restarts it on crash or reboot |
| `Caddyfile`          | `/etc/caddy/Caddyfile`                   | Serves HTTPS on ports 80 and 443 and proxies to the app                                                         |
| `deploy.sh`          | `/usr/local/bin/patchrader-deploy`       | Builds `main` in a new release folder, switches to it, and switches back if `/story` doesn't return 200         |

On the server, `/srv/patchrader` holds:

- `releases/<commit>/`: one full build per deploy. The three newest are kept.
- `current`: a link to the release being served.
- `shared/.env.local`: settings that aren't in git. Every release links to it.

## Update the live site

After a PR merges into `main`:

```sh
ssh root@155.138.145.151 patchrader-deploy
```

The current release keeps serving while the new one builds, so a failed build doesn't touch the live site. If the new release fails its health check, the script switches back and exits with an error.

To go back to an earlier release by hand:

```sh
ls -t /srv/patchrader/releases
ln -sfn /srv/patchrader/releases/<commit> /srv/patchrader/current && systemctl restart patchrader
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
journalctl -u patchrader -f   # the app
journalctl -u caddy -f        # HTTPS and proxy
```

## Rebuild the server from scratch

On a fresh Ubuntu server, as root:

1. Install Node 26.13 from nodejs.org into `/opt/node` and link `node`, `npm` and `npx` into `/usr/local/bin`. Then run `npm install -g pnpm@12.18.0 srvx@1.0.8` and link `pnpm` and `srvx` the same way.
2. Create the app user and its folders:
   ```sh
   useradd --system --create-home --home-dir /srv/patchrader --shell /usr/sbin/nologin patchrader
   install -d -o patchrader -g patchrader -m 750 /srv/patchrader/releases /srv/patchrader/shared
   install -o patchrader -g patchrader -m 600 /dev/null /srv/patchrader/shared/.env.local
   ```
3. `apt-get install caddy`, then copy the three files above to their installed paths. Change the IP in `Caddyfile` if the new server has a different one.
4. `systemctl daemon-reload && systemctl enable patchrader`
5. `patchrader-deploy` to build the first release and start the app.
6. `systemctl reload caddy` so Caddy picks up the new `Caddyfile`, since installing it started Caddy with its default config.
7. `ufw allow 80/tcp && ufw allow 443/tcp`

When the GoDaddy domain is registered, point its A record at the server's IP, add the domain to the first line of `Caddyfile`, and run `systemctl reload caddy`.
