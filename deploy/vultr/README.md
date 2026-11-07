# Vultr deployment

The dashboard runs on a Vultr Shared CPU server (`vc2-2c-4gb`, Toronto, Ubuntu 26.04 LTS) at
https://155-138-145-151.sslip.io. [sslip.io](https://sslip.io) maps that name to the server's IP so it can have an HTTPS certificate before the project has its own domain.

| File                 | Installed as                             | What it does                                                                           |
| -------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------- |
| `patchrader.service` | `/etc/systemd/system/patchrader.service` | Runs the built app with `srvx` on `127.0.0.1:3000`, and restarts it on crash or reboot |
| `Caddyfile`          | `/etc/caddy/Caddyfile`                   | Serves HTTPS on ports 80 and 443 and proxies to the app                                |
| `deploy.sh`          | `/usr/local/bin/patchrader-deploy`       | Pulls `main`, installs, builds, restarts, and checks that `/story` returns 200         |

## Update the live site

After a PR merges into `main`:

```sh
ssh root@155.138.145.151 patchrader-deploy
```

## Database

When a page needs Tiger Cloud, put the connection string on the server (not in git) and restart:

```sh
sudo -u patchrader tee /srv/patchrader/app/apps/web/.env.local <<'EOF'
DATABASE_URL=postgres://USER:PASSWORD@HOST:PORT/tsdb?sslmode=require
EOF
chmod 600 /srv/patchrader/app/apps/web/.env.local
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
2. `useradd --system --create-home --home-dir /srv/patchrader --shell /usr/sbin/nologin patchrader`
3. `sudo -u patchrader git clone https://github.com/ShardulB6/PatchRader.git /srv/patchrader/app`
4. `apt-get install caddy`, then copy the three files above to their installed paths.
5. Change the IP in `Caddyfile` if the new server has a different one.
6. `systemctl daemon-reload && systemctl enable --now patchrader caddy`
7. `ufw allow 80/tcp && ufw allow 443/tcp`
8. `patchrader-deploy`

When the GoDaddy domain is registered, point its A record at the server's IP and add the domain to the first line of `Caddyfile`.
