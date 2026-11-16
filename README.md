# wash

A browser shell (in the spirit of butterfly) that uses the
[wosh](../wosh) protocol, with passkey sign-in and a canvas terminal that
supports truecolor and the kitty graphics protocol.

wash has three parts:

| part | runs as | does |
|---|---|---|
| **wash-web** | podman container, listens on `0.0.0.0:8443` | serves the page, passkey sign-in and creation (sqlite), hands each authenticated browser WebSocket to the right user's washd |
| **washd** | each unix user, persistent | the shell manager: owns N wosh sessions (`wosh _daemon`), keeps a link to wash-web, **verifies passkeys again on its own**, serves the browser |
| **wash** | each unix user, CLI | starts and stops washd, lists and kills sessions, lists and approves passkeys, changes settings, enrolls with wash-web |

```
browser ──https/wss──▶ wash-web (container) ◀──wss link (washd dials out)── washd ──unix sock──▶ wosh daemons ─ pty ─ shell
   │                                                                                                 ▲
   └────────────── WebRTC data channel "wosh" (DTLS), signaling relayed by wash-web + washd ──────────┘
                   fallback: the same frames over a WebSocket that washd bridges
```

## How a sign-in works

1. The browser asks for a sign-in for user `alice`. wash-web refuses at once
   if alice's washd is not connected ("no shell manager is running").
2. The WebAuthn challenge is `webNonce(32) ‖ managerNonce(32)`. wash-web
   makes the first half. washd makes the second half over the link.
3. The browser signs the challenge with its passkey.
4. **wash-web** checks the signature against its database (approved keys
   only) and its own nonce.
5. **washd** checks the same assertion against `~/.config/wash/keys.json`
   (only keys this user approved with `wash keys approve`), its own nonce,
   the origin, the RP ID and the sign counter.
6. If both pass, washd issues a single-use ticket and wash-web sets its
   session cookie. A browser WebSocket needs both: wash-web checks the
   cookie, and washd checks the ticket when wash-web sends `attach`.
7. washd dials wash-web back for that connection, and wash-web splices the
   two sockets together. washd then serves the session list and signaling.

A compromised web container cannot open a shell on its own. It cannot sign
a challenge that holds washd's nonce. A key that is "approved" only in the
web database is refused by washd (the e2e test checks this). Every page load
asks for the passkey again. A dropped connection resumes with a single-use
resume ticket that is kept only in page memory and is valid for 30 minutes.

## Passkey lifecycle

* Passkey creation on the website is **closed** by default. `wash keys open`
  opens it for your user only, for 1 hour (or less: `wash keys open 10m`).
  `wash keys close` ends it early. A wash-web restart closes every window.
  This stops strangers from filling your pending list with keys you might
  approve by mistake. `WASH_REGISTRATION=open` restores the old behaviour:
  anyone can create a passkey for any user name at any time.
* A new passkey is **pending**. It is **purged after 1 hour** unless that
  user approves it. Approve only the ID the website showed you.
  Limits: 5 pending per user, 200 in total, and a rate limit per IP.
* `wash keys` lists your approved and pending passkeys. `wash keys approve ID`
  works only for the user washd runs as (washd's link is bound to that user,
  and wash-web only shows a manager its own user's keys).
* `wash keys revoke ID` removes the key from keys.json at once. It also
  removes it on wash-web and closes the browser connections that signed in
  with it.

## Setup

Build (Go ≥ 1.27; `make` targets or `./build.sh` on hosts without make):

```sh
./build.sh image                # static wash-web + image localhost/wash-web (FROM scratch)
./build.sh install              # wash + washd into ~/.local/bin
```

Run the website: **see `deploy/README.md`**. It follows the server's podman design
template: a rootless `wash` service user, a quadlet with a local `.build`, sqlite in
`/data-active/wash` and nightly dumps. `deploy/dev.sh` runs the same units as your own
user for local testing first.

Passkeys need a secure context and an RP ID that is a **host name, not an IP
address**. Every name in use goes in `WASH_ORIGIN`. Browsers also block passkeys
on pages with certificate errors. `WASH_TLS=auto` therefore runs a private CA,
name-constrained to `WASH_TLS_HOSTS`. Import it on each device once from `/ca.crt`
(the login page links to it). The alternatives are `WASH_TLS=CERT,KEY`,
or `WASH_TLS=off` behind Caddy with `WASH_TRUST_PROXY=1`.
`WASH_REGISTRATION=open` lets anyone create passkeys at any time (default `closed`:
only inside a `wash keys open` window).

### Public deployment behind a reverse proxy

* Its own host name (`wash.example.com`) is safest. A path on a shared host
  name (`example.com/wash/`) works too: the page only uses relative URLs, and the
  proxy sends `X-Forwarded-Prefix` so the session cookie is scoped to that
  path. The cookie path does not isolate wash from other apps on the same host
  name, though: they share the origin, so script running in any of them can
  call wash's API with the browser's cookie. Only share a host name with apps
  you trust as much as wash.
* `WASH_ORIGIN` gets the public origin (`https://example.com`, no path) next
  to the internal ones, and `WASH_TRUST_PROXY` the proxy's address (IPs or
  CIDRs, comma separated). The proxy can talk to wash-web's own TLS
  (`WASH_TLS=auto`, trusting its CA) or plain HTTP (`WASH_TLS=off`).
  wash-web then believes `X-Forwarded-For`/`-Proto` only from those peers, and
  takes the right-most `X-Forwarded-For` entry that is not a proxy, so a client
  cannot pick its own address for the rate limit. `WASH_TRUST_PROXY=1` trusts any
  peer: only use it when the published port is bound to `127.0.0.1`.
* `/api/link` (washd's connection) goes through the same proxy and is
  protected by the manager token.
* Sign-in does not reveal whether a user exists, has passkeys, or runs washd:
  a user without approved passkeys gets a stable decoy challenge that always
  fails. Detailed errors (e.g. "no shell manager is running") appear only after
  a passkey that wash-web has approved was verified. Both sign-in requests take
  at least 100 ms, so response time does not tell real users from decoys.

### Accounts that can never use wash

Root, well-known default accounts (`ubuntu`, `pi`, `ec2-user`, `admin`, ...),
system names (`www-data`, `nobody`, `systemd-*`, ...) and service accounts are
refused, on both sides:

* **Host side** (washd and the `wash` CLI: `up`, `enroll`, `web enroll USER`):
  the account must not be on the built-in list, must not be uid 0, must have a
  uid inside `UID_MIN`..`UID_MAX` from `/etc/login.defs`, and must have a real
  login shell. Rootless podman service users have `/usr/sbin/nologin`, so they
  are refused.
* **wash-web** (it cannot see the host's passwd): the built-in name list plus
  `WASH_DENY_USERS`. A refused name gets the decoy at sign-in, cannot create
  passkeys or redeem an enrollment code, and an existing manager link for it is
  refused. List the host's service users there, e.g.
  `awk -F: '$7 ~ /nologin|false/ && $3 >= 1000 {printf "%s,", $1}' /etc/passwd`.

Link a user (each user that wants web shells does this once):

```sh
wash enroll        # as alice: gets a code + cert fingerprint from the wash-web container
                   # (podman wash-web / wash-web-dev, else `upod wash` with sudo), pins, starts washd
# without access to the container: an admin runs `wash web enroll alice` and alice runs
wash enroll https://ca-data:8443 CODE
```

Then run `wash keys open` as that user, create a passkey on the site, run
`wash keys approve ID`, and sign in.

washd keeps running after you log out if you start it from systemd:
`wash service install`, then `systemctl --user enable --now washd` and
`loginctl enable-linger $USER`.

## CLI

```
wash up | down [--kill-sessions] | restart | status | logs
wash sessions [list] | new [NAME] | kill ID...|--all | rename ID NAME     (wash ls)
wash keys [list] | open [DURATION] | close | approve ID | revoke ID
wash config | config get KEY | config set KEY VALUE
      wosh, command, stun, turn, relay, transport (auto|webrtc|bridge), max_sessions, term
wash enroll [URL [CODE]] [--fingerprint=SHA256] [--yes]
wash web keys|managers|unenroll USER|fingerprint|backup FILE   (wash-web admin, via podman/upod)
wash service install|uninstall
```

Sessions belong to washd, not to a browser. A session keeps running with no
browser attached, and also while washd itself is restarted (`wash down`,
then `wash up` finds the sessions again). washd needs a `wosh` binary: PATH,
`~/.local/bin`, `~/go/bin`, or `wash config set wosh PATH`.

Admin side: `wash web keys [USER] | managers | unenroll USER | fingerprint | backup FILE`.

## Transport

The browser is a wosh client. It speaks wosh's data channel frames
(`o i a r R p P x X k c e`, with byte offsets for output and input).

* **webrtc** (preferred): `RTCPeerConnection` straight to the user's wosh
  daemon. The SDP offer and answer go through wash-web and washd to the
  daemon's control socket. ICE servers come from `wash config set stun/turn`.
  This needs the browser to reach the shell host (LAN, STUN, or TURN).
* **bridge** (fallback when WebRTC does not connect within about 8 s, or
  when forced with `transport bridge`): a second handed-over WebSocket. washd
  is the WebRTC peer on the host and forwards the frames.

In both modes, reconnects resend input that was not acknowledged and replay
missed output (from the daemon's 4 MiB ring). A link is restarted after
6 s with no pong.

## Chained hops (`wosh HOST` inside a web session)

`wosh HOST` typed in a wash terminal works the way it does in wosh: you end up
connected directly to HOST and the intermediate session goes away.

1. The parked `wosh` prints an in-band hello with the session token and the ssh
   args it used to reach HOST. The browser checks the token against the daemon's
   `info` frame. A hello without a matching token asks first.
2. The browser opens WebRTC straight to HOST, signaling through the parent's
   terminal (`WOSH:` lines out, OSC answers back). If the middle host lacks a wosh
   build for HOST's platform, it asks the browser over a `build` stream, and
   washd supplies the build from wosh's `dist/` dir.
3. Once connected, the browser asks washd to **adopt** the hop. washd probes, in
   parallel, the ways it could reach the hop's daemon itself, and keeps the
   shortest one that works:
   - direct from here, with the ssh args the parent used;
   - direct by the target's host name;
   - every suffix of the chain;
   - the full chain (`ssh B` → B's own `ssh HOST` → perl attach stub, BatchMode
     at every hop, the same commands wosh uses).

   A probe only succeeds where that exact daemon socket and session id exist
   under your account, so a shortcut cannot land on another machine. washd
   records a **remote session** with the chosen route and ends the intermediate
   session, which is wosh's spin-down. The tab now *is* HOST, and reconnects
   and reloads go over that route.

   **Passphrase-protected hops:** a passphrase typed when you ran `wosh HOST` is
   needed only once. If washd can reach HOST directly, it never goes through
   that hop again.
4. washd's ssh uses your ssh-agent. `wash up` passes `$SSH_AUTH_SOCK`, and
   `wash agent` updates it, e.g. after logging in again. Opt-in:
   `wash config set forward_agent true` forwards the agent through the
   intermediate hops of a route, so they can use your local keys for the next
   ssh. While that short ssh is open, root on those hosts can use your agent.
5. If no route works non-interactively, adoption is refused, the terminal says
   why, and the parent stays as the signaling path. Hops from `wosh up` (no
   route) also keep their parent.

`wash ls` shows remote sessions with their route. `wash sessions kill` hangs them
up over the wosh protocol.

## Terminal

`web/static/term/` is a terminal emulator with no dependencies. It draws on
Canvas2D, and the renderer is its own module, so a pixi/WebGL renderer could
replace it. It supports xterm-style VT, 256-color and truecolor SGR (`;` and
`:` forms), the alternate screen, scroll regions, wide characters and emoji,
box drawing drawn as shapes, mouse modes 1000/1002/1003/1006, bracketed
paste, focus events, copy on select, Ctrl+C (with a selection) / Ctrl+V, synchronized output, OSC 8/52/10/11, and the **kitty
graphics protocol**: direct transmission, PNG, RGB(A), zlib, chunking,
place, delete and query. `kitten icat`, `timg`, `chafa -f kitty` and similar
tools work as long as they send the image data inline (`t=d`).

Sessions get `TERM=xterm-256color`, `COLORTERM=truecolor` and
`TERM_PROGRAM=wash`. `TERM` is not `xterm-kitty`, because the kitty keyboard
protocol is not implemented. Keys: Ctrl+Shift+C/V copy and paste,
Ctrl+Shift+T opens a new session, Ctrl+Shift+PgUp/PgDn switch tabs.
`/termdemo.html` shows the terminal with no backend.

## Tests

```sh
go test ./...                              # includes internal/e2e (needs ../wosh/bin/wosh or $WASH_TEST_WOSH)
node --test web/test/term/*.test.mjs web/test/wosh/*.test.mjs
```

The e2e test runs wash-web and washd with real wosh daemons, using a
software passkey. It covers enrollment, decoy sign-in challenges, the
`wash keys open` window (capped at 1h, per user, closable), pending keys, refusing to approve
another user's key, rejecting a key approved on the web side only, the
dual-verified sign-in, single-use tickets, the bridge with offset resume,
killing a session from the CLI, revocation closing a browser connection, and
purging pending keys after the TTL.

## Limitations / TODO

* Terminal: no reflow on resize. Kitty animation, unicode placeholders
  (`U=1`) and file/shm transmission are not supported. No kitty keyboard
  protocol.
* wosh's `src:` transfers, port forwards and agent forwarding are client
  features that the browser does not provide.
* Shared sessions (needs a wosh daemon with shared-session support, i.e.
  sessions started after updating wosh): several devices can show a session
  at once. One of them controls it (keyboard and size); the others watch,
  with a "Watching" bar and a **Take control** button. Whoever has the
  session first keeps it: opening it on another device (or reloading the
  page) only watches, unless nobody controls it. The **⌨ button** on a tab
  (green when this device has control) takes control of that session; the
  device that had it keeps watching. Clicking the tab itself only switches. Control
  is per session, so the desktop can type in one tab while the phone types
  in another. If the controlling device goes away for 10 s, the device that
  has watched longest gets control. The controller sets the terminal size:
  watchers draw the controller's grid, with the font shrunk to fit their
  screen (never larger than their own font setting).
* Phones get a smaller default font, the tabs get their own row that
  scrolls sideways, and text size and sign out move into a ☰ menu at the
  top right. The font size is chosen per device.
  A session whose daemon predates this falls back to one peer: opening it
  elsewhere takes it over, and the devices trade it back and forth.
* The wosh protocol types in `internal/wosh` mirror wosh's internal
  `wire` package (protocol v2). Keep them in sync.
