#!/usr/bin/env bash
# container-provision.sh — set up bsgate inside the Debian container.
#
# Invoked by proxmox-lxc-install.sh via `pct exec`, but safe to run by hand
# and safe to re-run: every step is idempotent, and re-running never
# regenerates the server identity or the allowlist. Regenerating either would
# silently lock out every client that already has a build.
#
# No cloud service relays game traffic, but reachability depends on the
# playit.gg agent: it runs inside this container and dials OUTBOUND to
# playit's infrastructure, so there are zero inbound ports on your router.
# bsgate itself binds loopback only; the playit agent is what actually faces
# the internet, over a connection it initiated.
#
# Other network dependencies are Debian's package mirrors, the pinned
# libhydrogen checkout at build time, and the playit.gg apt repo.

set -euo pipefail

GAME_PORT=41234
LISTEN_IP=""
SRC_DIR="/opt/bsgate/src"
PLAYIT_SECRET=""
SKIP_PLAYIT=0

usage() {
    cat <<EOF
usage: $0 [options]

  --port N              game UDP port                 (default: ${GAME_PORT})
  --listen-ip IP        override bsgate's bind address (default: 127.0.0.1)
  --src DIR             source tree location           (default: ${SRC_DIR})
  --playit-secret KEY   claim the playit agent non-interactively with an
                         already-issued secret key, instead of running the
                         interactive claim-code flow. Use this to re-provision
                         a container without visiting the dashboard again.
  --skip-playit         do not install or claim the playit agent at all.
                         bsgate still binds loopback only, so the box is
                         reachable from the LAN only — useful for local testing.
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --port)           GAME_PORT=$2; shift 2 ;;
        --listen-ip)      LISTEN_IP=$2; shift 2 ;;
        --src)            SRC_DIR=$2; shift 2 ;;
        --playit-secret)  PLAYIT_SECRET=$2; shift 2 ;;
        --skip-playit)    SKIP_PLAYIT=1; shift ;;
        -h|--help)        usage ;;
        *) echo "container-provision: unknown option $1" >&2; exit 2 ;;
    esac
done

say()  { printf '  \033[1;36m->\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m/!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------- listen addr

# Bind loopback only. Nothing outside this container ever talks to bsgate
# directly: the playit agent is the only thing facing the internet, and it
# forwards to bsgate over loopback with a PROXY protocol v2 header. There is
# no eth0 address to detect or care about any more.
if [[ -z $LISTEN_IP ]]; then
    LISTEN_IP="127.0.0.1"
fi
say "bsgate will bind ${LISTEN_IP} (loopback only — playit forwards to it locally)"

# ------------------------------------------------------------- packages

say "installing packages"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential git ca-certificates \
    nftables \
    curl gnupg \
    unattended-upgrades apt-listchanges \
    >/dev/null

# This box is meant to sit downstairs and be forgotten about, which is exactly
# the box that ends up unpatched.
say "enabling unattended security upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/51bsgate-unattended <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

# ------------------------------------------------------------- playit agent

# playit.gg is the only thing in this box that faces the internet. It dials
# OUTBOUND from inside the container to playit's infrastructure, so there is
# no inbound port to open and nothing to forward on the router. bsgate stays
# on loopback and never sees a public address at all.
if [[ $SKIP_PLAYIT -eq 1 ]]; then
    warn "--skip-playit given: not installing the playit agent."
    warn "bsgate is bound to loopback only, so the box is reachable from the LAN only."
else
    say "adding the playit.gg apt repo"
    curl -fsSL https://packages.playit.gg/keys/playit.gpg \
        | gpg --dearmor -o /usr/share/keyrings/playit.gpg
    chmod 0644 /usr/share/keyrings/playit.gpg
    cat > /etc/apt/sources.list.d/playit.list <<'EOF'
deb [signed-by=/usr/share/keyrings/playit.gpg] https://packages.playit.gg/data/debian ./
EOF

    say "installing the playit agent"
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends playit >/dev/null

    PLAYIT_TOML=/etc/playit/playit.toml

    if [[ -f $PLAYIT_TOML ]] && grep -q '^secret_key = ' "$PLAYIT_TOML" 2>/dev/null; then
        say "playit already claimed (${PLAYIT_TOML} has a secret_key) — skipping claim"
    elif [[ -n $PLAYIT_SECRET ]]; then
        say "writing the supplied playit secret (non-interactive claim)"
        SECRET_VALUE=$PLAYIT_SECRET
    else
        say "claiming the playit agent — this needs one manual step in a browser"
        CLAIM_CODE=$(playit claim generate)
        [[ -n $CLAIM_CODE ]] || die "playit claim generate produced no code"
        CLAIM_URL=$(playit claim url --name "$(hostname)" --type self-managed "$CLAIM_CODE")
        printf '\n'
        printf '  \033[1;35m========================================================\033[0m\n'
        printf '  \033[1;35m Visit this URL and approve the agent within 5 minutes:\033[0m\n'
        printf '  \033[1;35m %s\033[0m\n' "$CLAIM_URL"
        printf '  \033[1;35m========================================================\033[0m\n\n'
        SECRET_VALUE=$(playit claim exchange --wait 300 "$CLAIM_CODE") \
            || die "playit claim was not approved within 300s — re-run this script, or pass --playit-secret once you have claimed it another way"
        [[ -n $SECRET_VALUE ]] || die "playit claim exchange produced no secret"
    fi

    if [[ -n ${SECRET_VALUE:-} ]]; then
        install -d -m 0750 -o playit -g playit /etc/playit
        TMP_TOML=$(mktemp /etc/playit/.playit.toml.XXXXXX)
        printf 'secret_key = "%s"\n' "$SECRET_VALUE" > "$TMP_TOML"
        chown playit:playit "$TMP_TOML"
        chmod 0600 "$TMP_TOML"
        mv -f "$TMP_TOML" "$PLAYIT_TOML"
        unset SECRET_VALUE
        say "playit secret written to ${PLAYIT_TOML}"
    fi

    say "enabling and starting playit"
    systemctl enable playit >/dev/null 2>&1
    systemctl restart playit
    sleep 2
    if systemctl is-active --quiet playit; then
        say "playit is running"
    else
        journalctl -u playit -n 30 --no-pager >&2
        die "playit failed to start"
    fi
fi

# ------------------------------------------------------------- accounts

# bsgame is both a shared group and, now that the game-logic daemon is
# actually deployed below, its own service account too. The bsgate user's
# home is /var/lib/bsgate (identity + allowlist); the bsgame user's is
# /var/lib/bsgame (block diffs) — the two state directories are never
# shared, so an update touching one can never brush against the other.
#
# Group membership is what lets the two processes meet at /run/bsgate: that
# directory and the socket files in it are owned by group bsgate (bsgate.
# service runs Group=bsgate, and bsgate.c umask(0007)s around its socket
# bind() calls — see systemd/bsgame.service's comment on SupplementaryGroups
# for the detail), so bsgame needs bsgate as a *supplementary* group to
# reach them, alongside its own primary group bsgame.
say "creating service accounts"
getent group bsgame >/dev/null || groupadd --system bsgame
getent group bsgate >/dev/null || groupadd --system bsgate
if ! getent passwd bsgate >/dev/null; then
    useradd --system --gid bsgate --groups bsgame \
            --home-dir /var/lib/bsgate --no-create-home \
            --shell /usr/sbin/nologin bsgate
fi
if ! getent passwd bsgame >/dev/null; then
    useradd --system --gid bsgame --groups bsgate \
            --home-dir /var/lib/bsgame --no-create-home \
            --shell /usr/sbin/nologin bsgame
fi

# ------------------------------------------------------------- build

say "building bsgate"
[[ -d ${SRC_DIR}/gateway ]] || die "no source at ${SRC_DIR}/gateway"
make -C "${SRC_DIR}/gateway" clean >/dev/null 2>&1 || true
make -C "${SRC_DIR}/gateway" >/dev/null

# The suite includes the negative cases — replay, forged cookie, unlisted key,
# wrong PSK. Installing a binary that cannot prove it rejects those is how a
# gateway ends up open without anyone noticing.
say "running the test suite before installing"
if ! make -C "${SRC_DIR}/gateway" test >/tmp/bsgate-test.log 2>&1; then
    tail -40 /tmp/bsgate-test.log >&2
    die "gateway test suite FAILED — refusing to install (full log: /tmp/bsgate-test.log)"
fi
say "$(grep -oE '(PASS|FAIL) [0-9]+ checks.*' /tmp/bsgate-test.log | tail -1)"

make -C "${SRC_DIR}/gateway" install-check >/dev/null \
    || die "the built binary is missing expected hardening (PIE / RELRO / NX)"

install -D -m 0755 -o root -g root "${SRC_DIR}/gateway/bsgate"    /opt/bsgate/bsgate
install -D -m 0755 -o root -g root "${SRC_DIR}/tools/bsgate-keys" /usr/local/sbin/bsgate-keys
install -D -m 0644 -o root -g root "${SRC_DIR}/README.md"         /opt/bsgate/README.md

say "building bsgame"
[[ -d ${SRC_DIR}/game ]] || die "no source at ${SRC_DIR}/game"
make -C "${SRC_DIR}/game" clean >/dev/null 2>&1 || true
make -C "${SRC_DIR}/game" >/dev/null

# Same stance as the gateway suite above: bsgame is the process a
# compromised or merely buggy client actually gets to talk to after
# bsgate lets it in (see game/bsgame.c's header comment) — installing a
# binary that cannot prove it validates and rate-limits that input is not
# an acceptable trade for saving a few seconds here.
say "running the game test suite before installing"
if ! make -C "${SRC_DIR}/game" test >/tmp/bsgame-test.log 2>&1; then
    tail -40 /tmp/bsgame-test.log >&2
    die "game test suite FAILED — refusing to install (full log: /tmp/bsgame-test.log)"
fi
say "$(grep -oE '(PASS|FAIL) [0-9]+ checks.*' /tmp/bsgame-test.log | tail -1)"

make -C "${SRC_DIR}/game" install-check >/dev/null \
    || die "the built bsgame binary is missing expected hardening (PIE / RELRO / NX)"

install -D -m 0755 -o root -g root "${SRC_DIR}/game/bsgame" /opt/bsgate/bsgame

# The version this provisioning run installed, and the self-update tool
# that later compares against it (tools/bs-update -> /usr/local/bin/update).
# Neither one is state: both are safe to overwrite on every re-provision,
# unlike /var/lib/bsgate and /var/lib/bsgame below.
install -D -m 0644 -o root -g root "${SRC_DIR}/VERSION"        /opt/bsgate/VERSION
install -D -m 0755 -o root -g root "${SRC_DIR}/tools/bs-update" /usr/local/bin/update

# ------------------------------------------------------------- state

install -d -m 0700 -o bsgate -g bsgate /var/lib/bsgate
install -d -m 0755 -o root   -g root   /etc/bsgate

if [[ ! -f /var/lib/bsgate/allowlist ]]; then
    say "creating an empty allowlist"
    cat > /var/lib/bsgate/allowlist <<'EOF'
# One friend per line:  <64 hex characters of their public key> <label>
#
#   bsgate-keys add <key> <label>      allow someone
#   bsgate-keys revoke <label>         remove them, disconnecting them now
#
# An empty allowlist means nobody can join. That is the correct default.
EOF
    chown bsgate:bsgate /var/lib/bsgate/allowlist
    chmod 0600 /var/lib/bsgate/allowlist
fi

cat > /etc/bsgate/bsgate.env <<EOF
# Bind address for bsgate, written by container-provision.sh.
# Loopback only — the playit agent is what faces the internet, and it
# forwards to this address with a PROXY protocol v2 header. There is no
# container-address detection to redo if the network changes.
BSGATE_LISTEN=${LISTEN_IP}:${GAME_PORT}
EOF
chmod 0644 /etc/bsgate/bsgate.env

# Generate the identity as the service user so the files land owned correctly
# and 0600 from the start, rather than being chowned after the fact.
if [[ ! -f /var/lib/bsgate/server.seed ]]; then
    say "generating the server identity"
    runuser -u bsgate -- /opt/bsgate/bsgate --state-dir /var/lib/bsgate --print-identity >/dev/null
fi

# ------------------------------------------------------------- firewall

# Zero inbound. There is no forwarded port and nothing listens on a public
# address: bsgate is loopback-only, and the playit agent reaches it only
# because IT dialled OUT first. The input chain therefore has no rule for the
# game port at all — that absence is the point, not an oversight.
#
# Outbound is default-deny too, on purpose: a compromised process on this box
# should not get free egress. The playit agent needs broad egress (its
# control-plane and relay endpoints are not a fixed, documented list), so its
# uid is allowed broadly rather than guessed at port-by-port. bsgate never
# needs egress at all — it only ever speaks over loopback and a unix socket —
# so it gets no rule and falls through to the drop policy.
if [[ $SKIP_PLAYIT -eq 1 ]]; then
    PLAYIT_EGRESS_RULE="        # --skip-playit: no playit uid exists, so no broad-egress rule for it.
        # bsgate stays loopback-only; there is no outbound path for game
        # traffic until this container is re-provisioned without --skip-playit."
else
    PLAYIT_EGRESS_RULE="        # playit dials outbound to its control plane and relays. Those
        # endpoints are not a small fixed list, so its uid is trusted broadly
        # rather than guessed at port-by-port.
        meta skuid playit accept"
fi

say "installing the nftables ruleset"
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Managed by container-provision.sh — edits are overwritten on re-provision.
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # No rule for the game port. bsgate is loopback-only and nothing
        # reaches it from outside this container — see the playit agent for
        # the only network path in, and it is outbound-only from here.

        # Rate-limited ping so the box stays diagnosable without being a
        # convenient amplifier.
        ip  protocol icmp   icmp   type echo-request limit rate 5/second accept
        ip6 nexthdr  icmpv6 icmpv6 type echo-request limit rate 5/second accept
        ip6 nexthdr  icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

        # No SSH rule, on purpose. Administer this container with
        # 'pct enter <ctid>' from the Proxmox host. One fewer network-facing
        # service is one fewer thing to keep patched.
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy drop;

        oif lo accept
        ct state established,related accept
        ct state invalid drop

        # Name resolution, for apt and for the playit agent's own connects.
        udp dport 53 accept
        tcp dport 53 accept

        # Root needs egress for apt-get and unattended-upgrades.
        meta skuid root accept

${PLAYIT_EGRESS_RULE}

        # bsgate itself gets no egress rule. It only ever speaks over
        # loopback and a unix socket, so it has nothing to reach outbound —
        # and if that ever changed unexpectedly, this is what would catch it.
    }
}
EOF
chmod 0644 /etc/nftables.conf

# Load it now and fail the install if the ruleset is invalid, rather than
# enabling a service that will fail at next boot.
nft -f /etc/nftables.conf || die "nftables ruleset was rejected — not enabling it"
systemctl enable nftables >/dev/null 2>&1 || true
say "firewall active (zero inbound ports, default-deny outbound)"

# ------------------------------------------------------------- service

say "installing the systemd units"
install -D -m 0644 "${SRC_DIR}/systemd/bsgate.service" /etc/systemd/system/bsgate.service
install -D -m 0644 "${SRC_DIR}/systemd/bsgame.service" /etc/systemd/system/bsgame.service
systemctl daemon-reload
systemctl enable bsgate >/dev/null
systemctl enable bsgame >/dev/null

# bsgate first, always: bsgame.service is After=/BindsTo= bsgate.service
# (it needs /run/bsgate to exist before it can bind anything there), so
# starting them in this order is belt-and-braces on top of what the unit
# files already enforce, not a substitute for it.
systemctl restart bsgate
sleep 1
if systemctl is-active --quiet bsgate; then
    say "bsgate is running on ${LISTEN_IP}:${GAME_PORT}/udp (loopback only)"
else
    journalctl -u bsgate -n 30 --no-pager >&2
    die "bsgate failed to start"
fi

systemctl restart bsgame
sleep 1
if systemctl is-active --quiet bsgame; then
    say "bsgame is running (unix sockets under /run/bsgate only, no network access)"
else
    journalctl -u bsgame -n 30 --no-pager >&2
    die "bsgame failed to start"
fi

if [[ $SKIP_PLAYIT -eq 0 ]]; then
    warn "REMEMBER: when you create the tunnel in the playit.gg dashboard, it"
    warn "must be UDP with type 'proxy-protocol-v2', not v1. The v1 header"
    warn "format is silently dropped by this agent version — it looks exactly"
    warn "like a dead connection, with no error on either side."
fi

say "provisioning complete"
