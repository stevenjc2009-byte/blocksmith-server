# bsgame — Blocksmith authoritative game-logic process
#
# `make`       build the daemon
# `make test`  build and run the host test suite
#
# No crypto and no network socket other than the local Unix one — see
# bsgame.c's header comment. This does not build or link anything from
# server/gateway; the two processes only agree on the byte layout in
# server/proto/bs_proto.h and the small BS_GAME_* enum bsgame.c duplicates
# from bsgate.c (see the comment at its definition for why).
#
# -I$(WORLD) lets validate.c pull BLOCK_COUNT and WORLD_HEIGHT straight from
# the client's own <3ds.h>-free world headers (source/world/block.h,
# source/world/world.h) instead of hand-duplicating those numbers; see
# validate.c's static asserts for what breaks if they ever drift.

CC     ?= cc
WORLD  := ../../source

# That client tree only exists when this repo sits inside the Blocksmith
# checkout. The published server-only repo, the installer's staging tar and the
# clone `update` makes all have no ../../source, and an unconditional include
# there is a fatal build error — which is exactly how a fresh Proxmox install
# and every future `update` turned out to be broken.  So probe, and tell
# validate.c which world it is being built in.
#
# Probing the two headers rather than the directory: a partially-moved tree
# should fall back to the server's own constants, not die on a missing include.
# The flag is defined either way (0 or 1) so -Wundef still catches a typo in the
# macro name instead of silently taking the fallback branch forever.
ifneq ($(and $(wildcard $(WORLD)/world/block.h),$(wildcard $(WORLD)/world/world.h)),)
  WORLD_CPPFLAGS := -I$(WORLD) -DBS_HAVE_CLIENT_WORLD_HEADERS=1
else
  WORLD_CPPFLAGS := -DBS_HAVE_CLIENT_WORLD_HEADERS=0
endif

# Same hardening as server/gateway/Makefile and for the same reason: this
# process parses bytes that reached it via an already-authenticated session,
# but "authenticated" is not "trusted" (see bsgame.c's header comment) —
# -Werror because a warning here is a review finding, not a style nit.
CFLAGS := -std=c11 -O2 -g \
          -Wall -Wextra -Werror \
          -Wformat=2 -Wconversion -Wsign-conversion -Wshadow \
          -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
          -Wvla -Wcast-qual -Wundef \
          -fstack-protector-strong -fstack-clash-protection \
          -D_FORTIFY_SOURCE=2 \
          -fPIE \
          -I.. $(WORLD_CPPFLAGS)

LDFLAGS := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed

OBJS := bsgame.o diffstore.o players.o validate.o

.PHONY: all test clean install-check

all: bsgame

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bsgame: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

bsgame_test: bsgame_test.o diffstore.o players.o validate.o
	$(CC) $^ -o $@ $(LDFLAGS)

test: all bsgame_test
	./bsgame_test

# Confirms the hardening actually landed in the binary rather than trusting
# that the flags were accepted.
install-check: bsgame
	@echo "== binary hardening =="
	@readelf -d bsgame | grep -qE 'BIND_NOW'      && echo "  RELRO/BIND_NOW ok" || (echo "  MISSING bind-now"; exit 1)
	@readelf -h bsgame | grep -qE 'DYN'           && echo "  PIE ok"            || (echo "  MISSING pie"; exit 1)
	@readelf -lW bsgame | grep -q 'GNU_STACK.*RW ' && echo "  NX stack ok"       || (echo "  stack may be executable"; exit 1)

clean:
	rm -f *.o bsgame bsgame_test
