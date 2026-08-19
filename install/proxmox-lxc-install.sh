#!/usr/bin/env bash
# proxmox-lxc-install.sh — create and provision the Blocksmith gateway container.
#
# Run this ON THE PROXMOX HOST, as root, from inside the `server/` directory:
#
#     ./install/proxmox-lxc-install.sh --ip 192.168.1.50/24 --gw 192.168.1.1
#
# EVERYTHING RUNS ON YOUR PROXMOX BOX. There is no cloud service that touches
# game traffic, no third-party account beyond playit.gg's free tunnel, and no
# outbound dependency beyond Debian's package mirrors, the pinned libhydrogen
# checkout at build time, and the playit.gg apt repo.
#
# Reachability comes from the playit.gg agent running INSIDE this container.
# It dials OUTBOUND to playit's infrastructure — there is ZERO inbound port,
# no router port forward, and no DMZ. bsgate itself binds loopback only and
# is never reachable except through that outbound tunnel. You still have to
# create the tunnel yourself in the playit.gg dashboard (that step is not
# scriptable); this installer gets the container to the point of being ready
# for it and tells you exactly what to click.
#
# Nothing here touches the host's networking, firewall, or SSH configuration.

set -euo pipefail

# ---------------------------------------------------------------- defaults

CTID=""
HOSTNAME="blocksmith-gw"
STORAGE=""
TEMPLATE_STORAGE="local"
DISK_GB=4
MEMORY_MB=512
SWAP_MB=256
CORES=1
BRIDGE="vmbr0"
GAME_PORT=41234
STATIC_IP=""
GATEWAY_IP=""
START_AFTER=1
PLAYIT_SECRET=""
SKIP_PLAYIT=0

usage() {
    cat <<EOF
usage: $0 [options]

  --ip CIDR             static address, e.g. 192.168.1.50/24  (STRONGLY advised)
  --gw ADDR             default gateway, e.g. 192.168.1.1     (required with --ip)
  --ctid N              container id            (default: next free)
  --hostname NAME       container hostname      (default: ${HOSTNAME})
  --storage NAME        rootfs storage          (default: autodetected)
  --bridge NAME         network bridge          (default: ${BRIDGE})
  --disk GB             root disk size          (default: ${DISK_GB})
  --memory MB           RAM                     (default: ${MEMORY_MB})
  --cores N             cpu cores               (default: ${CORES})
  --port N              game UDP port           (default: ${GAME_PORT})
  --playit-secret KEY   claim the playit agent non-interactively with an
                         already-issued secret key instead of the interactive
                         claim-code flow. Passed straight through to
                         container-provision.sh.
  --skip-playit         do not install or claim the playit agent. bsgate
                         still binds loopback only, so the container is
                         reachable from the LAN only — useful for local
                         testing before you are ready to make it public.
  --no-start            create but do not start

Without --ip the container uses DHCP. That works, but the playit agent inside
the container reconnects on its own IP regardless — a DHCP change does not
break the tunnel the way it would break a router port forward. A static
address is still recommended so LAN administration (pct enter, SSH-less
console) stays predictable.
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)             STATIC_IP=$2; shift 2 ;;
        --gw)             GATEWAY_IP=$2; shift 2 ;;
        --ctid)           CTID=$2; shift 2 ;;
        --hostname)       HOSTNAME=$2; shift 2 ;;
        --storage)        STORAGE=$2; shift 2 ;;
        --bridge)         BRIDGE=$2; shift 2 ;;
        --disk)           DISK_GB=$2; shift 2 ;;
        --memory)         MEMORY_MB=$2; shift 2 ;;
        --cores)          CORES=$2; shift 2 ;;
        --port)           GAME_PORT=$2; shift 2 ;;
        --playit-secret)  PLAYIT_SECRET=$2; shift 2 ;;
        --skip-playit)    SKIP_PLAYIT=1; shift ;;
        --no-start)       START_AFTER=0; shift ;;
        -h|--help)        usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m/!\\\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------- preflight

[[ $EUID -eq 0 ]] || die "run as root on the Proxmox host"
command -v pct   >/dev/null || die "pct not found — this is not a Proxmox host"
command -v pvesm >/dev/null || die "pvesm not found — this is not a Proxmox host"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SERVER_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
[[ -f "${SERVER_DIR}/gateway/bsgate.c" ]] \
    || die "expected gateway/bsgate.c next to this script; run it from the server/ directory"

[[ $GAME_PORT =~ ^[0-9]+$ ]] && (( GAME_PORT > 1024 && GAME_PORT < 65536 )) \
    || die "--port must be between 1025 and 65535"

if [[ -n $STATIC_IP ]]; then
    [[ $STATIC_IP =~ ^[0-9.]+/[0-9]+$ ]] || die "--ip must be CIDR, e.g. 192.168.1.50/24"
    [[ -n $GATEWAY_IP ]] || die "--gw is required when --ip is given"
    NETCONF="name=eth0,bridge=${BRIDGE},ip=${STATIC_IP},gw=${GATEWAY_IP},firewall=1"
else
    warn "no --ip given: using DHCP. The playit tunnel is unaffected by the"
    warn "container's LAN address changing, but 'pct enter'/'pct exec' still"
    warn "need to find the box, so a reservation is still worth setting."
    NETCONF="name=eth0,bridge=${BRIDGE},ip=dhcp,firewall=1"
fi

if [[ -z $CTID ]]; then
    CTID=$(pvesh get /cluster/nextid)
    say "using next free container id ${CTID}"
fi
[[ $CTID =~ ^[0-9]+$ ]] || die "container id must be numeric"
pct status "$CTID" &>/dev/null && die "container ${CTID} already exists — pick another --ctid"

# Guessing 'local-lvm' fails noisily on ZFS or directory-only nodes.
if [[ -z $STORAGE ]]; then
    STORAGE=$(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active" {print $1; exit}')
    [[ -n $STORAGE ]] || die "no active storage supports container rootfs; pass --storage"
    say "using storage ${STORAGE}"
fi

# ------------------------------------------------------------- template

say "checking for a Debian container template"
pveam update >/dev/null 2>&1 || warn "pveam update failed; using the cached template list"

TEMPLATE=$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null \
           | awk '/debian-1[23]-standard/ {print $1}' | sort | tail -1)

if [[ -z $TEMPLATE ]]; then
    AVAIL=$(pveam available --section system \
            | awk '/debian-1[23]-standard/ {print $2}' | sort | tail -1)
    [[ -n $AVAIL ]] || die "no debian-12/13-standard template available"
    say "downloading ${AVAIL}"
    pveam download "$TEMPLATE_STORAGE" "$AVAIL"
    TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${AVAIL}"
fi
say "template: ${TEMPLATE}"

# ------------------------------------------------------------- create CT

# Unprivileged, no nesting, no device passthrough of any kind. The container
# needs nothing beyond a network interface, so it is given nothing else.
say "creating unprivileged container ${CTID}"
pct create "$CTID" "$TEMPLATE" \
    --hostname     "$HOSTNAME" \
    --unprivileged 1 \
    --features     nesting=0 \
    --memory       "$MEMORY_MB" \
    --swap         "$SWAP_MB" \
    --cores        "$CORES" \
    --rootfs       "${STORAGE}:${DISK_GB}" \
    --net0         "$NETCONF" \
    --onboot       1 \
    --start        0 \
    --description  "Blocksmith secure transport gateway (bsgate)"

say "starting container"
pct start "$CTID"

# pct exec races the container's own boot; wait for systemd rather than
# sleeping a guessed number of seconds.
say "waiting for the container to finish booting"
for _ in $(seq 1 60); do
    pct exec "$CTID" -- test -d /run/systemd/system &>/dev/null && break
    sleep 1
done
pct exec "$CTID" -- test -d /run/systemd/system \
    || die "container ${CTID} did not boot into systemd"

# ------------------------------------------------------------- push source

say "copying the gateway source into the container"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# .deps and object files are artefacts of whatever machine you are on;
# excluding them means the container fetches libhydrogen itself at the pinned
# commit and builds from clean source. Same reasoning for game/ as for
# gateway/ — container-provision.sh builds bsgame from source too, so its
# host-built x86 .o files and binaries would otherwise ship in as stale
# artefacts the container never actually uses, just extra tar bytes that
# happen to be the wrong architecture.
tar -C "$SERVER_DIR" \
    --exclude='gateway/.deps' --exclude='gateway/*.o' \
    --exclude='gateway/bsgate' --exclude='gateway/bsgate_test' \
    --exclude='game/*.o' \
    --exclude='game/bsgame' --exclude='game/bsgame_test' \
    -czf "${STAGE}/bsgate-src.tar.gz" .

pct exec "$CTID" -- mkdir -p /opt/bsgate/src
pct push "$CTID" "${STAGE}/bsgate-src.tar.gz" /opt/bsgate/src.tar.gz
pct exec "$CTID" -- tar -xzf /opt/bsgate/src.tar.gz -C /opt/bsgate/src
pct exec "$CTID" -- rm -f /opt/bsgate/src.tar.gz

# ------------------------------------------------------------- provision

PROVISION_ARGS=(--port "$GAME_PORT")
[[ -n $PLAYIT_SECRET ]] && PROVISION_ARGS+=(--playit-secret "$PLAYIT_SECRET")
[[ $SKIP_PLAYIT -eq 1 ]] && PROVISION_ARGS+=(--skip-playit)

say "provisioning inside the container (this builds and tests bsgate)"
if [[ $SKIP_PLAYIT -eq 0 && -z $PLAYIT_SECRET ]]; then
    say "the playit claim step is interactive — it will print a URL below and"
    say "wait for you to approve it in a browser"
fi
pct exec "$CTID" -- bash /opt/bsgate/src/install/container-provision.sh "${PROVISION_ARGS[@]}"

CT_IP=$(pct exec "$CTID" -- bash -c \
        "ip -4 -o addr show dev eth0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || echo "unknown")

if [[ $START_AFTER -eq 0 ]]; then
    say "stopping container as requested (--no-start)"
    pct stop "$CTID"
fi

# ------------------------------------------------------------- report

if [[ $SKIP_PLAYIT -eq 1 ]]; then
    NEXT_STEPS=" --skip-playit was given: no tunnel agent was installed. The gateway is
 reachable from your LAN only. Re-run this script without --skip-playit (or
 run container-provision.sh again inside the container) when you are ready
 to make it reachable from outside."
else
    NEXT_STEPS=" 1. Create the tunnel yourself — this is the one step that cannot be
    scripted. Go to https://playit.gg/ (or the URL container-provision.sh
    printed during the claim step), open your agent, and add a tunnel:

        protocol   UDP
        type       proxy-protocol-v2   <-- NOT v1. v1 is silently dropped by
                                            this agent version: no error, no
                                            connection, nothing to grep for.
        local IP   127.0.0.1
        local port ${GAME_PORT}

 2. The dashboard shows the public address+port the tunnel assigns you
    (something like xyz.joinmc.link:12345). That is what your friends' 3DS
    clients connect to instead of your home IP — playit relays it in, your
    router never opens a port. You can also read it from the agent itself:

        pct exec ${CTID} -- systemctl status playit
        pct exec ${CTID} -- journalctl -u playit -n 50

 3. Get the credentials to bake into the 3DS client build:

        pct exec ${CTID} -- bsgate-keys identity

 4. Add each friend's public key (they generate it in the client):

        pct exec ${CTID} -- bsgate-keys add <their-64-hex-key> <label>

 There is no port forward, no DMZ, and no CGNAT concern here — the agent
 dials out through whatever NAT you have, the same as any outbound
 connection your LAN already makes every day."
fi

GREEN=$(printf '\033[1;32m'); RESET=$(printf '\033[0m')
cat <<EOF

${GREEN}=========================================================${RESET}
 Blocksmith gateway container ${CTID} (${HOSTNAME}) is up.
${GREEN}=========================================================${RESET}

 Container address:  ${CT_IP}   (LAN only — for administration, not for players)
 bsgate binds:       127.0.0.1:${GAME_PORT}/udp inside the container
 Enter it with:      pct enter ${CTID}
 bsgate status:      pct exec ${CTID} -- systemctl status bsgate
 bsgate logs:        pct exec ${CTID} -- journalctl -u bsgate -f
 playit status:      pct exec ${CTID} -- systemctl status playit
 playit logs:        pct exec ${CTID} -- journalctl -u playit -f

 NEXT STEPS

${NEXT_STEPS}
EOF
