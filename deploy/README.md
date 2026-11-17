# Deploying wash-web

This deployment follows `~/_ai/server_setup/notes/podman_design_template_notes.md`:
rootless podman with a dedicated `wash` user, quadlets with a local `.build`, sqlite
state in `/data-active/wash`, dumps in `/data/backups/wash`, and the port published on
`0.0.0.0`.

Only **wash-web** is a container. **washd** is not a service: it runs as each human
user, because it starts that user's shells. It connects to wash-web through the
published host port. Every user who wants web shells runs it with
`wash service install` (a systemd user unit) or with `wash up`.

```
deploy/
  quadlet/wash-web.container   -> /home/wash/.config/containers/systemd/
  quadlet/wash-web.build       -> /home/wash/.config/containers/systemd/
  systemd/wash-web-backup.{service,timer} -> /home/wash/.config/systemd/user/
  bin/wash-web-backup.sh       -> /home/wash/bin/
  env.example                  -> /home/wash/wash-web/.env   (0600)
  dev.sh                       local test of the same units as the current user
```

## 1. Test locally as yourself

`dev.sh` renders the same quadlet files into `~/.config/containers/systemd/` as
`wash-web-dev.*`. Only the paths and names change: state goes in
`~/.local/share/wash-dev`, the image builds from this checkout, and the port stays 8443.

```bash
deploy/dev.sh install          # render units + ~/.local/share/wash-dev/.env, daemon-reload
deploy/dev.sh start            # builds localhost/wash-web:dev, waits for (healthy)
wash enroll                    # code + cert pin straight from the container, starts washd
wash keys open                 # passkey creation is closed until you open it (1h)
# browser: https://ca-data:8443 -> Create passkey -> `wash keys approve ID` -> Sign in
deploy/dev.sh backup           # run the backup script against the dev paths
wash web keys                  # wash-web admin commands inside the container
deploy/dev.sh rebuild          # after code changes
deploy/dev.sh uninstall [--purge]
```

**TLS trust.** Browsers refuse passkeys on any page with a certificate error, so the
self-signed setup is a small private CA plus a leaf certificate, kept in `tls/`. On each
device, download `https://ca-data.tailnet.local:8443/ca.crt` once (`wash web ca`
prints it too) and import it as a trusted authority. The CA is name-constrained to
`WASH_TLS_HOSTS`, so it cannot vouch for any other site. washd pins the CA. The leaf
is reissued when it nears expiry or when a host is added; restart wash-web to pick
up a new leaf. Adding a name outside the constraint creates a new CA, and every
device and every washd then has to trust or enroll again. Opening the site by IP is
always refused, because WebAuthn has no RP ID for an IP address.

Every host name that people type in the browser must appear in `WASH_ORIGIN` in the
`.env`. Passkeys are bound to that name. A Tailscale MagicDNS name
(`ca-data.<tailnet>.ts.net`) is a different origin from `ca-data`. Add it to
`WASH_TLS_HOSTS` as well, so the self-signed certificate covers it.

Stop the dev instance before you publish. Both instances bind 8443.

## 2. Publish to the `wash` service user

These are the template's §9 checklist steps, filled in. **As built on 2026-11-16:**
uid 5012, gid **969** (`useradd --system` picks the gid from the system range),
subuid/subgid `1051968-1117503`, recorded in `storage-layout.md`. First start, including
the image build, takes about 30 s. When deploying elsewhere, re-read that table
before allocating.

```bash
SVC=wash
# 1-4: account, subuid range, linger, quadlet dir (prints a harmless SYS_UID_MAX warning)
sudo useradd --system --uid 5012 --create-home --home-dir /home/$SVC --shell /usr/sbin/nologin $SVC
sudo usermod --add-subuids 1051968-1117503 --add-subgids 1051968-1117503 $SVC
sudo loginctl enable-linger $SVC
sudo -u $SVC mkdir -p /home/$SVC/.config/containers/systemd /home/$SVC/.config/systemd/user /home/$SVC/bin

# 5: admin access (home stays wash:wash 0751; never change its group)
sudo chmod 0751 /home/$SVC && sudo chmod g-s /home/$SVC
sudo chgrp -R svcadm /home/$SVC/.config /home/$SVC/bin
sudo find /home/$SVC/.config /home/$SVC/bin -type d -exec chmod 2770 {} +

# state: private to wash (sqlite + TLS key), no `share` group needed
sudo install -d -o $SVC -g $SVC -m 2770 /data-active/$SVC
sudo install -d -o $SVC -g $SVC -m 2770 /data/backups/$SVC
# moving from the dev instance? stop it first (sqlite WAL), then keep its state so
# enrolled washd pins, devices that trust the CA and approved passkeys carry over:
#   systemctl --user stop wash-web-dev
#   sudo cp -a ~/.local/share/wash-dev/data/. /data-active/$SVC/
#   sudo chown -R $SVC:$SVC /data-active/$SVC && sudo chmod 2770 /data-active/$SVC   # cp -a copies the 0700 mode

# source checkout = the .build context (in version control, per template §3)
sudo git clone ~/_ai/wosh/repos/wash /home/$SVC/wash-web && sudo chown -R $SVC:$SVC /home/$SVC/wash-web

# units, script, env
sudo cp deploy/quadlet/wash-web.{container,build} /home/$SVC/.config/containers/systemd/
sudo cp deploy/systemd/wash-web-backup.{service,timer} /home/$SVC/.config/systemd/user/
sudo cp deploy/bin/wash-web-backup.sh /home/$SVC/bin/
sudo cp deploy/env.example /home/$SVC/wash-web/.env      # then edit WASH_ORIGIN / WASH_TLS_HOSTS
sudo chown $SVC:$SVC /home/$SVC/wash-web/.env && sudo chmod 0600 /home/$SVC/wash-web/.env
sudo chown $SVC:svcadm /home/$SVC/bin/wash-web-backup.sh && sudo chmod 0770 /home/$SVC/bin/wash-web-backup.sh
# files copied by root must be OWNED by wash (svcadm group only grants admins access);
# root:svcadm 0660 makes the quadlet generator fail with "permission denied"
sudo chown -R $SVC:svcadm /home/$SVC/.config /home/$SVC/bin
sudo find /home/$SVC/.config -type f -exec chmod 0660 {} +

# generator check, start, backup timer
sudo -u $SVC /usr/libexec/podman/quadlet -dryrun -user | grep -A3 -- '---wash-web'
uctl $SVC daemon-reload
uctl $SVC start wash-web.service          # first start builds the image (pulls golang:1.27.4-alpine)
upod $SVC ps                              # wash-web ... (healthy)  0.0.0.0:8443->8443/tcp
uctl $SVC enable --now wash-web-backup.timer
uctl $SVC start wash-web-backup.service && ls -l /data/backups/$SVC/
```

Verify the uid mapping with the §4 `stat` test:

```bash
stat -c '%U:%G %a' /data-active/wash/wash.db     # expect wash:wash, never a bare number
```

Move users from dev to prod. Each user enrolls again, because prod has its own
certificate and database:

```bash
deploy/dev.sh uninstall                    # frees 8443
wash enroll                                # as alice; finds wash-web via `upod wash` (sudo)
# users without sudo: an admin runs `wash web enroll alice` (or upod wash exec wash-web
# /wash-web enroll alice) and alice runs `wash enroll https://ca-data:8443 CODE`
```

Approved passkeys stay in each user's `~/.config/wash/keys.json` across instances. The
web side of prod starts empty, though, so users create their passkeys again and run
`wash keys approve` again. That is deliberate: the two key stores are independent.

Then record uid 5012 and subuid `1051968-1117503` in `storage-layout.md`, and move
"Next free" on by one slot.

⚠️ **Reboot is the operator's call.** Linger plus `WantedBy=default.target` is the
mechanism. At the next reboot, whatever the reason, check:

```bash
upod wash ps                                  # wash-web (healthy)
uctl wash status wash-web.service wash-web-backup.timer
wash status                                   # as a user with washd: "website ... connected"
```

## Operating

| task | command |
|---|---|
| logs | `uctl wash status wash-web` / `sudo -u wash XDG_RUNTIME_DIR=/run/user/5012 journalctl --user -u wash-web -f` |
| enroll a user | `wash enroll` as that user (sudo via upod), or `wash web enroll USER` + `wash enroll URL CODE` |
| list passkeys / managers | `wash web keys` / `wash web managers` |
| cert fingerprint | `wash web fingerprint` |
| update | `sudo git -C /home/wash/wash-web pull && sudo chown -R wash:wash /home/wash/wash-web && upod wash build -t localhost/wash-web:latest -f /home/wash/wash-web/Containerfile.build /home/wash/wash-web && uctl wash restart wash-web` |
| restore | stop wash-web; `cp /data/backups/wash/wash-STAMP.db /data-active/wash/wash.db`; delete `wash.db-wal` and `wash.db-shm`; unpack `wash-tls-STAMP.tar.gz` into `/data-active/wash`; start |

Notes:
- The image is built locally, so it has no `AutoUpdate=`. The builder tag is pinned in
  `Containerfile.build`.
- `HealthCmd` uses the exec form. The `scratch` image has no shell, so the string form
  (`CMD-SHELL`) would never report healthy, and `Notify=healthy` would time out the
  unit (see `gotchas.md`).
- **As built, 2026-11-16:** public at `https://ca.ffeineaddiction.com/wash/` through
  Caddy on `a-tinc` (tinc `10.0.0.1`) to `https://10.0.0.44:8443`. `.env` has the
  public origin in `WASH_ORIGIN` and `WASH_TRUST_PROXY=10.0.0.1`; Caddy trusts
  wash's CA (inline) and sends `X-Forwarded-Prefix /wash`:

  ```caddy
  redir /wash /wash/
  handle_path /wash/* {
          reverse_proxy https://10.0.0.44:8443 {
                  header_up X-Forwarded-Prefix /wash
                  transport http {
                          tls_server_name ca-data.tailnet.local
                          # wash's CA as base64 DER (Caddy runs in a container that only
                          # mounts the Caddyfile, so no file path):
                          #   upod wash exec wash-web /wash-web ca | openssl x509 -outform DER | base64 -w0
                          tls_trust_pool inline <BASE64-DER>
                  }
          }
  }
  ```
- Behind Caddy on the `ca` box, set `WASH_TLS=off`, `WASH_TRUST_PROXY=<Caddy's IP as
  wash-web sees it>` and `WASH_ORIGIN=https://<public name>` (its own host name, not a
  subpath; see the main README). `WASH_TRUST_PROXY=1` (any peer) is safe only with
  `PublishPort=127.0.0.1:8443:8443`. washd still needs a route to wash-web. Either
  enroll it against the Caddy URL, or keep `WASH_TLS=auto` and let Caddy proxy to
  `https://ca-data:8443` with `tls_insecure_skip_verify`.
- Published recordings (`wash watch host`) are served at `/playback/UUID` with no sign-in,
  so through the Caddy block above they are `https://ca.ffeineaddiction.com/wash/playback/UUID`.
  Set `WASH_PUBLIC_URL=https://ca.ffeineaddiction.com/wash` in `.env` so `wash watch host`
  prints that link. Files are in `/data-active/wash/playback` (`UUID.cast` + `UUID.json`);
  the backup tars them, and `wash-web unenroll USER` deletes that user's.
- Losing `/data-active/wash/tls` changes the certificate. Every washd then refuses the
  link (pin mismatch) until its user runs `wash enroll` again. That is why the backup
  includes it.
