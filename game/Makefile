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
# -I$(WORLD) lets validate.c pull WORLD_HEIGHT straight from the client's own
# <3ds.h>-free source/world/world.h instead of hand-duplicating that number; see
# validate.c's static asserts for what breaks if it ever drifts.
#
# It does NOT do that for BLOCK_COUNT. -I$(WORLD) is never consulted for
# "world/block.h" in either arm, so BLOCK_COUNT is compared against the VENDORED
# game/world/block.h and check-world-drift below closes the second hop to the
# client's original; WORLD_HEIGHT is the only one compared against the client
# tree directly.
#
# The MECHANISM this comment used to give for that was wrong, and the correction
# matters because the wrong one made -I. look droppable. It said a quoted include
# searches the including file's own directory first, so validate.c sitting in
# game/ reaches game/world/block.h with or without -I.. Re-measured with
# `gcc -E -H` on validate.c itself with the real CFLAGS, 2026-08-25: block.h is
# not reached from validate.c at all. It arrives at DEPTH 2, pulled in by
# world/registry.h, which validate.c includes unconditionally — and registry.h
# lives in game/world/, so its own-directory search for "world/block.h" looks for
# game/world/world/block.h, misses, and -I. is what catches it. The output is
# `.. ./world/block.h` in both arms with -I. present, and
# `.. ../../../source/world/block.h` — the CLIENT's copy — with -I. removed.
# So -I. is load-bearing for block.h as well as for the vendored .c files below.
# Dropping -I$(WORLD) instead leaves block.h at `.. ./world/block.h` and takes
# only world/world.h out ("world/world.h: No such file or directory").
#
# world/inventory.c, world/inventory.h, world/crafting.c, world/crafting.h,
# world/crc32.c, world/crc32.h and world/block.h are VENDORED into game/world/
# (byte-identical copies of the client's own <3ds.h>-free files). The
# deployed server is a standalone clone of this repo with no client tree next
# to it — tools/bs-update clones deps/blocksmith-server alone — so the
# inventory/crafting logic bsgame runs at authoritative slot-arrangement and
# crafting operations has to physically live here, compiled unconditionally,
# not gated behind a probe the way WORLD_HEIGHT is. -I. below is what lets those
# vendored .c files' own `#include "world/..."` lines resolve against this
# directory, without rewriting a single include: they live in game/world/, so
# their own-directory search for "world/inventory.h" looks for
# game/world/world/inventory.h and misses, and -I. is what catches it. Measured
# the same way — `gcc -E -H world/inventory.c` prints `. ./world/inventory.h`
# with -I., and `. ../../../source/world/inventory.h`, the CLIENT's copy, with
# -I. removed. The -I. is load-bearing for these .c files, and — per the
# correction above — for validate.c's block.h too. Do not drop it.

CC     ?= cc

# Three levels, not two. This Makefile is in <blocksmith>/deps/blocksmith-server/game/,
# so ../.. is deps/ and ../../source is deps/source — a directory that has never existed
# in any layout. The probe below therefore always took the fallback branch, even inside a
# full Blocksmith checkout, and the drift static-asserts in validate.c were compiled out
# everywhere instead of "everywhere that could cause drift". That is not hypothetical: it
# is how BLOCK_PLANKS shipped as client id 7 while the server still refused every block id
# >= 7, so the one thing this probe exists to catch went uncaught.
WORLD  := ../../../source

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
  BS_HAVE_CLIENT_WORLD_HEADERS := 1
else
  WORLD_CPPFLAGS := -DBS_HAVE_CLIENT_WORLD_HEADERS=0
  BS_HAVE_CLIENT_WORLD_HEADERS := 0
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
          -I. -I.. $(WORLD_CPPFLAGS)

LDFLAGS := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed

# block.h has no block.c (only the enum and struct shape are needed here —
# nothing in game/ ever calls blockInfo()), so there is no world/block.o to
# build; block.h is still tracked by VENDORED_WORLD_FILES below so the drift
# guard covers it even though it never becomes an object file.
# world/registry.c IS compiled (v1.6.0 Phase A): bsgame owns the canonical
# registry state — it loads <state-dir>/registry.bin at boot, fingerprints it
# into REGISTRY_INFO, and streams dynamic defs back on REGISTRY_FETCH.
WORLD_OBJS := world/inventory.o world/crafting.o world/crc32.o world/registry.o world/tick.o

OBJS := bsgame.o diffstore.o cheststore.o playerstate.o players.o validate.o $(WORLD_OBJS)

# bsgame_test.o is not in OBJS (it carries its own main()), but it includes the
# same headers, so it needs a dep file too or `make test` inherits the exact bug
# described below for the one translation unit the test suite actually runs.
DEPS := $(OBJS:.o=.d) bsgame_test.d

.PHONY: all test clean install-check check-world-drift

all: check-world-drift bsgame

# -MMD -MP, with the generated .d files read back by the -include at the bottom
# of this file. This is the idiom the client build already uses — devkitARM's
# base_rules compiles with `-MMD -MP -MF $(DEPSDIR)/$*.d` and the client Makefile
# ends with `-include $(DEPSDIR)/*.d` — so this is that same mechanism written out
# by hand, for a build that has no base_rules to inherit it from.
#
# Without it this rule listed NO header prerequisites at all, and the failure mode
# was not "an occasional stale object". Editing any header in game/ left every
# affected .o untouched while make printed "'bsgame' is up to date." and exited 0.
# Measured 2026-08-30 from a clean tree: `touch world/tick.h && make bsgame` ->
# "make: 'bsgame' is up to date.", rc=0, with bsgame.o, diffstore.o, playerstate.o,
# players.o, validate.o and world/tick.o all provably older than the header.
#
# That is worse than a slow build, because a skipped rebuild and a passing check
# are the SAME output. A verification pass that edits a header, rebuilds, and sees
# green has proven nothing about the code it just wrote — it re-ran the previous
# binary. Every "fixed, tests pass" claim resting on a header-only change in this
# directory was unfounded, and nothing in the log would say so.
#
# -MMD rather than -MD: system headers are not our drift risk and listing them
# makes every .d churn on a libc update. -MP emits a phony target for each header
# so that DELETING a header gives a clean recompile instead of make aborting with
# "No rule to make target 'world/tick.h'" against a dep file that outlived it.
#
# Deliberately NOT the blunt alternative (`$(OBJS): $(wildcard *.h world/*.h)`,
# the shape of the client's own `$(OFILES_SOURCES) : $(HFILES)` line). That would
# also turn the red arm below green, while rebuilding all ten objects for any
# header touched — which passes the same test for the wrong reason and hides
# which translation units actually depend on what. The .d files are exact.
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

bsgame: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

bsgame_test: bsgame_test.o diffstore.o cheststore.o playerstate.o players.o validate.o $(WORLD_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

test: check-world-drift all bsgame_test
	./bsgame_test

# ---------------------------------------------------------------- drift guard
#
# game/world/*.{c,h} are hand-copied from ../../../source/world/ (see the
# VENDORED note above and tools/sync-world-sources.sh, which performs the
# copy). A copy that silently drifts from its original is worse than no copy
# at all: bsgame would keep running the OLD merge/refuse rules for
# inventoryAdd, craftMake and friends while the client's UI, built against
# the NEW ones, shows the player something the server will not actually do.
#
# This checks the files themselves with `cmp -s`, not their constants with
# more _Static_assert lines. validate.c already had that treatment for
# BS_BLOCK_COUNT — a compile-time assert that BLOCK_COUNT matches — and it
# still let BLOCK_PLANKS ship as an accepted client id while this server
# refused it, because the assert was checking a NUMBER, and the number was
# never what drifted; the Makefile path feeding it the wrong header was (see
# validate.h's own account of that bug). A _Static_assert also cannot see
# LOGIC drift at all by construction: it has no way to ask "does
# inventoryAdd's merge-before-spill order still match", "does
# inventoryMoveUnits still refuse a mismatched destination item", or "does
# craftMake still roll back the ingredient on a full inventory" — those are
# not constants, they are control flow, and the only thing that reliably
# proves two implementations of them are identical is comparing the bytes
# that produce that control flow. Hence `cmp -s`, run whenever the client
# tree this could drift from is actually sitting next to this repo.
VENDORED_WORLD_FILES := block.h inventory.h inventory.c crafting.h crafting.c crc32.h crc32.c registry.h registry.c tick.h tick.c

ifeq ($(BS_HAVE_CLIENT_WORLD_HEADERS),1)
check-world-drift:
	@ok=1; \
	for f in $(VENDORED_WORLD_FILES); do \
		if ! cmp -s world/$$f $(WORLD)/world/$$f; then \
			echo "game/Makefile: game/world/$$f has drifted from $(WORLD)/world/$$f"; \
			echo "  the vendored copy in this repo no longer matches the client's original."; \
			echo "  re-sync it with: tools/sync-world-sources.sh"; \
			ok=0; \
		fi; \
	done; \
	if [ $$ok -eq 0 ]; then exit 1; fi
else
# No client tree beside this repo (the standalone server-only checkout, the
# installer's staging tar, or the clone tools/bs-update makes) — nothing to
# diff against, so there is nothing this guard can check. Not a failure: see
# validate.h's identical stance on BLOCK_COUNT/WORLD_HEIGHT for why "cannot
# detect drift" and "cannot cause drift" are the same fact from two directions
# in a build that has no client tree to have drifted from.
check-world-drift:
	@:
endif

# Confirms the hardening actually landed in the binary rather than trusting
# that the flags were accepted.
install-check: bsgame
	@echo "== binary hardening =="
	@readelf -d bsgame | grep -qE 'BIND_NOW'      && echo "  RELRO/BIND_NOW ok" || (echo "  MISSING bind-now"; exit 1)
	@readelf -h bsgame | grep -qE 'DYN'           && echo "  PIE ok"            || (echo "  MISSING pie"; exit 1)
	@readelf -lW bsgame | grep -q 'GNU_STACK.*RW ' && echo "  NX stack ok"       || (echo "  stack may be executable"; exit 1)

clean:
	rm -f *.o *.d world/*.o world/*.d bsgame bsgame_test

# Read back the header dependencies recorded by -MMD -MP on the last compile.
# Leading '-' because on a clean tree these do not exist yet and their absence is
# not an error: the first build has to compile everything anyway, and it is that
# build which writes them.
#
# This is the counterpart to the rule near the top of the file; the two are only
# useful together. Note the consequence for anyone testing this mechanism: a tree
# built BEFORE this line existed has no .d files, so the first `make` after the
# change still cannot see header deps for objects it considers up to date. Run
# `make clean` once when adopting this, or the fix looks like it did not work.
-include $(DEPS)
