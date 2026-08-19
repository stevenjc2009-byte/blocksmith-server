# Blocksmith server

Self-hosted multiplayer for **Blocksmith**, a from-scratch Minecraft-like for
the Nintendo 3DS. Everything runs on your own box — there is no third-party
game server, and no third-party service ever sees game traffic in the clear.

**Security is the design centre of this repository, not an afterthought.**
Every choice below — no inbound port, default-deny egress, a stateless
cookie in front of any crypto work, a sandboxed systemd unit with an empty
capability set — exists because this is meant to sit on a home network and
be forgotten about, which is exactly the box that becomes a problem if it
isn't locked down first.

---

## The zero-inbound pitch

Something has to be reachable from the internet for remote friends to
connect. The usual answer is a router port forward — exposing your home IP,
hoping CGNAT doesn't get in the way, and leaving a hole open indefinitely.

This does the opposite. The [playit.gg](https://playit.gg/) agent runs
*inside* the container and dials **outbound** to playit's infrastructure.
`bsgate`, the process that actually terminates game traffic, binds
`127.0.0.1` only — it has no public address at all. The consequence:

- **No port forward.** Your router configuration never changes.
- **No DMZ.**
- **CGNAT is irrelevant.** Nothing is inbound, so it doesn't matter whether
  your ISP's WAN address is shared.
- **Your home IP is never exposed.** Friends connect to a playit-assigned
  address; traffic terminates at playit's edge and only reaches your house
  because the agent inside the container dialed out to fetch it — the same
  direction any browser tab on your LAN already talks.

## Topology

```
                3DS client (Wi-Fi)
                       |
                       |  UDP — Noise XX encrypted, Blocksmith wire
                       |  protocol (proto/bs_proto.h)
                       v
              playit.gg edge / relay
                       ^
                       |  outbound tunnel, DIALED FROM INSIDE the LXC —
                       |  nothing ever dials in
                       |
   +-------------- Proxmox LXC (unprivileged) -------------------+
   |                                                              |
   |   playit agent  (systemd: playit)                           |
   |         |                                                    |
   |         |  loopback UDP, PROXY protocol v2 header prepended  |
   |         |  (carries the player's real address through)       |
   |         v                                                    |
   |   bsgate  (systemd: bsgate)                                  |
   |         binds 127.0.0.1:<game port>/udp — no public address  |
   |         |                                                    |
   |         |  plaintext application bytes, /run/bsgate/game.sock|
   |         |  (unix datagram socket)                            |
   |         v                                                    |
   |   bsgame  (systemd: bsgame)                                  |
   |         authoritative game logic — validates every edit and  |
   |         position update, rebroadcasts at 10 Hz                |
   |                                                              |
   +---------------------------------------------------------------+
```

`bsgate` does no game logic; `bsgame` never touches a network socket. That
split means the only process facing the network is small enough to read end
to end, and a bug in game code can never be reached from the internet
directly — it can only be reached through bytes `bsgate` already decrypted,
authenticated, and matched to a known friend's key.

---

## Requirements

- A Proxmox VE host, with `pct` and `pvesm` available, run as root.
- A Debian 12/13 container template (the installer downloads one via `pveam`
  if none is cached).
- A network bridge for the container (default `vmbr0`).
- Outbound internet access from the container for: Debian's package
  mirrors, `github.com` (the pinned libhydrogen commit is fetched at build
  time — see `gateway/Makefile`), and the playit.gg apt repo + tunnel
  service.
- A free [playit.gg](https://playit.gg/) account, to approve the agent claim
  in a browser.

---

## Install

On the Proxmox host, as root, from inside this `server/` directory:

```bash
./install/proxmox-lxc-install.sh --ip 192.168.1.50/24 --gw 192.168.1.1
```

Other flags (all optional beyond `--ip`/`--gw`, which are strongly advised
over DHCP):

| Flag | Default | Meaning |
|---|---|---|
| `--ctid N` | next free id | container id |
| `--hostname NAME` | `blocksmith-gw` | container hostname |
| `--storage NAME` | autodetected | rootfs storage |
| `--bridge NAME` | `vmbr0` | network bridge |
| `--disk GB` | `4` | root disk size |
| `--memory MB` | `512` | RAM |
| `--cores N` | `1` | CPU cores |
| `--port N` | `41234` | game UDP port |
| `--playit-secret KEY` | — | claim playit non-interactively with an already-issued secret |
| `--skip-playit` | off | don't install/claim playit; `bsgate` stays LAN-reachable only |
| `--no-start` | off | create but don't start the container |

This creates an **unprivileged** Debian LXC (`--unprivileged 1`, `nesting=0`,
no device passthrough), copies the source in, and runs
`install/container-provision.sh` inside it, which:

1. Installs packages (`build-essential git ca-certificates nftables curl
   gnupg unattended-upgrades apt-listchanges`) and enables unattended
   security upgrades.
2. Installs and claims the playit.gg agent (unless `--skip-playit`).
3. Creates the `bsgate` and `bsgame` service accounts and the shared
   `bsgame` group.
4. Builds `bsgate` and `bsgame`, **runs both test suites, and refuses to
   install either if its suite fails** (`make -C gateway test`,
   `make -C game test`).
5. Runs `make -C gateway install-check` and `make -C game install-check` to
   confirm the built binaries actually have PIE, RELRO/BIND_NOW, and a
   non-executable stack — not just that the compiler flags were accepted.
6. Installs both as sandboxed systemd units (`systemd/bsgate.service`,
   `systemd/bsgame.service`) and enables them.
7. Installs the nftables ruleset described below, loads it, and refuses to
   enable it if `nft -c` rejects it.

If it fails partway — a test suite failing, a hardening check failing, an
invalid nftables ruleset — the script stops rather than installing something
that can't prove it's safe.

### The one step you do by hand: the playit tunnel

Creating the tunnel itself happens in the playit.gg dashboard and is **not
scriptable**. Claiming the agent (the browser-approval step) is handled by
the installer; adding the tunnel is not.

1. Claim the agent when the installer prompts (or pass `--playit-secret` to
   skip the browser step on a re-provision).
2. In the [playit.gg](https://playit.gg/) dashboard, add a tunnel:

   | Field | Value |
   |---|---|
   | protocol | **UDP** |
   | type | **`proxy-protocol-v2`** |
   | local IP | `127.0.0.1` |
   | local port | your `--port` (default `41234`) |

   **This must be exactly `proxy-protocol-v2`, not v1.** PROXY protocol v1
   on UDP writes no header at all — the agent doesn't even attempt it — and
   the failure is completely silent on both ends: no error, no connection,
   nothing to grep for in the logs. It just looks like a dead server. If
   friends can't connect and everything else looks fine, this is the first
   thing to check.

3. The dashboard shows the public address+port the tunnel assigns
   (something like `xyz.joinmc.link:12345`). That's what friends' 3DS
   clients connect to — never your home IP. You can also read the agent's
   own status:

   ```bash
   pct exec <ctid> -- systemctl status playit
   pct exec <ctid> -- journalctl -u playit -n 50
   ```

4. Get the credentials to bake into the 3DS client build:

   ```bash
   pct exec <ctid> -- bsgate-keys identity
   ```

---

## Adding friends

Friends are admitted by public key, not by IP or password. Run these inside
the container (`pct enter <ctid>`, or `pct exec <ctid> -- ...` from the
host):

```bash
bsgate-keys identity                   # server pubkey + network PSK, for a client build
bsgate-keys list                       # who is currently allowed
bsgate-keys add <64-hex-key> <label>   # allow someone
bsgate-keys revoke <label|64-hex-key>  # remove them — disconnects them NOW, not at next login
```

Each friend generates their own keypair in the client build and gives you
the public half (64 hex characters) to add. `bsgate-keys add`/`revoke`
validate the resulting allowlist against `bsgate`'s own parser before
installing it, then reload `bsgate` with `SIGHUP` — a malformed file is
refused outright rather than partially applied, so a bad edit can't
silently lock everyone out or leave a revoked key working.

---

## Updating

Once installed, updates are pulled and applied from inside the container —
there's no need to re-run the provisioning script.

```bash
pct enter <ctid>
update
```

- `update` checks GitHub for a newer release tag than the one currently
  installed. If there is one, it builds it and **runs the full test suites
  first** — only if both pass does it install the new binaries and restart
  the services. A failed build or a failed test suite is a **no-op**: the
  currently running server is left completely untouched.
- `update --check` reports whether a newer version is available without
  changing anything.
- `update --version` prints the currently installed version.
- If a service fails to come back up after an update, it rolls back to the
  previous binaries automatically.
- `/var/lib/bsgate` (server identity, the friend allowlist, world block
  diffs) and `/etc/playit/playit.toml` are **never touched** by an update —
  your friends, your keys, and your world survive every update.
- The update mechanism is pinned to this repository's remote and refuses to
  pull from anywhere else.

The installed version is tracked in this repository's `VERSION` file.

---

## Security model

Layers a packet must survive, outermost first:

| # | Layer | Stops |
|---|---|---|
| 1 | nftables: zero inbound, default-deny outbound | any network path in except the tunnel the container itself dialed out to open; a compromised process getting free egress |
| 2 | PROXY protocol v2, trusted only from `127.0.0.0/8` | a forged "real client address" header from anywhere but the loopback hop playit uses to reach `bsgate` |
| 3 | Stateless cookie exchange | spoofed source addresses — no state is allocated for an unproven address |
| 4 | Token-bucket rate limits (per-IP + global) | a proven-real address flooding handshakes |
| 5 | Network PSK | anyone without a client build — no handshake even starts |
| 6 | Noise XX (via libhydrogen) | passive capture and MITM; gives forward secrecy and mutual authentication |
| 7 | Public-key allowlist | anyone who has a build and the PSK but isn't a named friend |
| 8 | AEAD + sliding replay window | tampering, and re-sending a captured packet |

Design points worth knowing, all confirmed against the source:

- **`bsgate` binds loopback only** (`--listen 127.0.0.1:<port>`) and has
  no egress rule of its own in the nftables ruleset — it only ever speaks
  over loopback and a Unix socket, so a compromised gateway process has
  nowhere to phone home to.
- **Outbound is default-deny too.** Only loopback, established/related
  connections, DNS, `uid root` (for apt), and `uid playit` (whose
  control-plane/relay endpoints aren't a small fixed list) get broad
  egress.
- **There is no SSH rule, on purpose.** Administer the container with
  `pct enter <ctid>` from the Proxmox host — one fewer network-facing
  service to keep patched.
- **Rate limiting happens after the cookie check, not before** — charging a
  token before the address is proven would let a spoofed packet drain a
  real player's bucket.
- **The pre-authentication reply is smaller than the request that triggers
  it** (a 40-byte COOKIE reply to a 64-byte HELLO), so the gateway is a net
  amplification *reduction*, not a DDoS reflector.
- **Revocation is immediate.** `bsgate-keys revoke` disconnects the peer
  mid-session over `SIGHUP`, it does not wait for their next login.
- **`bsgame` trusts nothing it receives, even though it only ever hears from
  an already-authenticated session.** Every block edit and position update
  is re-validated server-side; a client sending a structurally malformed
  message gets kicked, not just ignored.
- **The systemd units run with almost nothing.** Empty capability bounding
  set, `NoNewPrivileges`, a read-only root filesystem
  (`ProtectSystem=strict`), no devices, restricted address families
  (`AF_INET`/`AF_UNIX` only), and a syscall filter that blocks privileged,
  mount, debug, and swap-related syscalls.

Known, accepted limits:

- **The PSK is extractable from a client build.** A 3DS has no secure
  storage. It keeps the service invisible to opportunistic scanning; it is
  not a secret from someone holding a CIA. The allowlist is what actually
  authorises a peer.
- **IPv4 only.** The 3DS has no IPv6 stack.

---

## Game-logic interface

`bsgate` and `bsgame` talk over a Unix datagram socket
(`/run/bsgate/game.sock`, group `bsgame`). Messages are
`[1 byte kind][4 byte session id][payload]`:

| kind | direction | meaning |
|---|---|---|
| 1 `JOIN` | gate → game | + 32-byte public key + 32-byte label |
| 2 `DATA` | both | plaintext application payload, max 1024 bytes |
| 3 `LEAVE` | gate → game | session ended |
| 4 `KICK` | game → gate | disconnect this session |

`bsgame` is the authoritative game server: block edits and position updates
arriving over this socket are validated (`game/validate.c`) before being
applied and rebroadcast at 10 Hz to every other connected player. Accepted
block edits persist to an append-only, magic-prefixed, fixed-16-byte-record
file (`game/diffstore.c`) so the world survives a restart; on join, a player
receives the full current diff set as a batch (`BS_APP_WORLD_SYNC`).

---

## Layout

```
proto/bs_proto.h        wire format — shared verbatim by the 3DS client,
                         bsgate, and bsgame
gateway/bsgate.c         the transport + authentication daemon
gateway/allowlist.[ch]   friend public-key list
gateway/ratelimit.[ch]   token buckets
gateway/replay.[ch]      sliding anti-replay window
gateway/proxyproto.[ch]  PROXY protocol v2 parsing
gateway/bsgate_test.c    end-to-end suite against a real bsgate process
game/bsgame.c            authoritative game-logic process
game/diffstore.[ch]      append-only block-diff store
game/players.[ch]        connected-player table
game/validate.[ch]       server-side edit/position validation
game/bsgame_test.c       host test suite
systemd/bsgate.service   sandboxed gateway unit
systemd/bsgame.service   sandboxed game-logic unit
tools/bsgate-keys        allowlist management
install/                 Proxmox host + in-container provisioning scripts
VERSION                  version the `update` command checks against
```

---

## Running the tests

```bash
make -C gateway test           # builds bsgate + bsgate_test, runs it
make -C gateway install-check  # confirms PIE / RELRO+BIND_NOW / NX stack in the built binary
make -C game test              # builds bsgame + bsgame_test, runs it
make -C game install-check     # same hardening check for bsgame
```

`gateway/Makefile`'s `test` target fetches the pinned libhydrogen commit
into `gateway/.deps/` on first run (see `deps`), builds `bsgate` and
`bsgate_test`, and runs the suite over real loopback UDP against a real
`bsgate` process — it is not a mock.

---

## Status / what is unverified

**Verified, by actually running these:**

- `gateway/bsgate_test.c`: **89/89 checks pass.**
- `game/bsgame_test.c`: **23/23 checks pass.**
- A 3DS client transport test suite: **19/19 checks pass**, run against a
  real, forked `bsgate` process.
- A block-diff-store test suite: **70/70 checks pass.**
- `make -C gateway install-check` and `make -C game install-check` both
  confirm RELRO/BIND_NOW, PIE, and a non-executable stack in the built
  binaries.

**Not verified — read this before assuming any of it works:**

- **Nothing here has ever run on a real Proxmox LXC.** All of the above was
  exercised off-target. The Proxmox-specific parts of the installer (`pct`,
  `pveam`, `pvesm` calls) have not been run against a real Proxmox host.
- The **playit claim flow**, `bsgate --proxy-protocol` actually running
  behind a real playit tunnel, and the **nftables firewall actually taking
  effect** in a live container are all untested on real hardware — only the
  rendered ruleset has been checked with `nft -c`.
- **No real 3DS console has connected to this server.** All transport
  testing so far is against a forked `bsgate`, not a live pairing between a
  console and a container.
- `bsgate` ↔ `bsgame` interop is verified only against the derived wire
  contract between the two test suites, not against a live process pair
  handling a real handshake end to end.
- `game/diffstore.c`'s full-table and torn-record recovery paths have no
  test coverage.

If you're standing this up for the first time, the honest summary is: the
crypto, the parsers, and the game logic have been exercised hard in
isolation, but the two things that make this a *server* — a real network
path through playit, and a real Proxmox container — have not yet been
proven end to end.
