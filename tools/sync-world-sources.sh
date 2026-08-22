#!/usr/bin/env bash
# tools/sync-world-sources.sh — re-syncs game/world/ from the client tree.
#
#   tools/sync-world-sources.sh
#
# game/world/{block.h,inventory.h,inventory.c,crafting.h,crafting.c,crc32.h,
# crc32.c} are vendored, byte-identical copies of the client's own
# <3ds.h>-free world sources (source/world/ in the Blocksmith checkout), not
# symlinks and not pulled in via an include path. That is deliberate: the
# DEPLOYED server is a standalone clone of deps/blocksmith-server alone (see
# tools/bs-update) with no client tree beside it, so the inventory/crafting
# logic bsgame runs at authoritative slot-arrangement and crafting has to
# physically live in this repo to ship at all.
#
# A vendored copy only stays trustworthy if it stays IDENTICAL to the
# original, so game/Makefile's `check-world-drift` target (part of `make` and
# `make test`, when a client tree sits next to this repo) fails the build the
# moment they diverge, naming this script as the fix — this is that fix. Run
# it, review the diff it produces with plain `git diff` before committing, and
# rebuild.
#
# This only works from inside a full Blocksmith checkout (this repo living at
# <blocksmith>/deps/blocksmith-server), the same tree game/Makefile's own
# WORLD probe expects — see that Makefile's header comment for why it is
# three directory levels, not two. Run from the standalone server-only repo,
# or from the installer's staging tar, there is nothing to sync from and this
# script says so rather than copying garbage over a working vendored copy.

set -euo pipefail

die() { echo "tools/sync-world-sources.sh: $*" >&2; exit 1; }

# Self-locating (see code-vault's pattern notes): resolves relative to this
# script's own path, not the caller's cwd, so `tools/sync-world-sources.sh`
# works the same whether run from the repo root or anywhere else.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Mirrors game/Makefile's WORLD := ../../../source, restated from tools/
# instead of game/ (one directory level shallower than the Makefile's own
# three, since this script sits at <repo>/tools/ rather than <repo>/game/).
CLIENT_WORLD="$REPO_ROOT/../../source/world"
VENDOR_WORLD="$REPO_ROOT/game/world"

FILES=(block.h inventory.h inventory.c crafting.h crafting.c crc32.h crc32.c registry.h registry.c)

[[ -d "$CLIENT_WORLD" ]] || die "no client tree at $CLIENT_WORLD — this only works from inside a full Blocksmith checkout (this repo at <blocksmith>/deps/blocksmith-server), the same layout game/Makefile's WORLD probe requires."

mkdir -p "$VENDOR_WORLD"

changed=0
for f in "${FILES[@]}"; do
    src="$CLIENT_WORLD/$f"
    dst="$VENDOR_WORLD/$f"
    [[ -f "$src" ]] || die "client tree is missing world/$f at $src"

    if cmp -s "$src" "$dst" 2>/dev/null; then
        echo "unchanged  $f"
    else
        cp -f "$src" "$dst"
        echo "synced     $f"
        changed=1
    fi
done

if [[ $changed -eq 1 ]]; then
    echo "game/world/ now matches $CLIENT_WORLD byte for byte. Review with 'git diff' and rebuild."
else
    echo "game/world/ was already in sync with $CLIENT_WORLD — nothing to do."
fi
