# bsgate — Blocksmith secure transport gateway
#
# `make`       build the daemon
# `make test`  build and run the end-to-end handshake test
# `make deps`  fetch libhydrogen at the pinned commit
#
# libhydrogen is fetched rather than vendored, pinned to an exact commit so a
# rebuild cannot silently pick up a different crypto implementation. The same
# commit must be used for the 3DS client — a mismatch in the Noise transcript
# shows up as an unexplained handshake failure, not a compile error.

HYDRO_REPO   := https://github.com/jedisct1/libhydrogen.git
HYDRO_COMMIT := 617036a353cd4f6478ab6c3f98c36dd31e23ce8e
DEPS         := .deps
HYDRO        := $(DEPS)/libhydrogen

CC      ?= cc

# Hardening is not optional here: this is the only process on the box facing
# the internet, and it parses attacker-controlled bytes on its first
# instruction. -Werror because a warning in this file is a security review
# finding, not a style nit.
CFLAGS  := -std=c11 -O2 -g \
           -Wall -Wextra -Werror \
           -Wformat=2 -Wconversion -Wsign-conversion -Wshadow \
           -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
           -Wvla -Wcast-qual -Wundef \
           -fstack-protector-strong -fstack-clash-protection \
           -D_FORTIFY_SOURCE=2 \
           -fPIE \
           -I$(HYDRO) -I..

LDFLAGS := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed

# Split out from OBJS so DEPS below can name our own translation units without
# also naming libhydrogen's. hydrogen.o is compiled by its own rule with its own
# flags (see the third-party note below), generates no .d, and must not appear in
# an -include list that would then never be satisfied.
GATE_OBJS := bsgate.o allowlist.o invite.o proxyproto.o ratelimit.o replay.o

OBJS    := $(GATE_OBJS) $(HYDRO)/hydrogen.o

# bsgate_test.o carries its own main() and so is not in GATE_OBJS, but it includes
# the same headers; without its .d, `make test` keeps the bug described at the
# compile rule for the one translation unit the suite actually runs.
DEPS_MK := $(GATE_OBJS:.o=.d) bsgate_test.d

.PHONY: all deps test clean install-check

all: deps bsgate

deps: $(HYDRO)/hydrogen.h

# safe.directory is set per-command rather than globally: on a mounted
# filesystem (WSL, a bind mount, a shared volume) git refuses to operate on a
# tree whose owner differs from the caller, and that failure has nothing to do
# with whether the checkout is trustworthy. The commit is pinned above, which
# is what actually makes it trustworthy.
$(HYDRO)/hydrogen.h:
	@mkdir -p $(DEPS)
	git clone -q $(HYDRO_REPO) $(HYDRO)
	git -C $(HYDRO) -c safe.directory='*' checkout -q $(HYDRO_COMMIT)
	@test "$$(git -C $(HYDRO) -c safe.directory='*' rev-parse HEAD)" = "$(HYDRO_COMMIT)" \
	  || (echo "libhydrogen checkout is not at the pinned commit"; exit 1)
	@echo "libhydrogen pinned at $(HYDRO_COMMIT)"

# libhydrogen is third-party; do not fail its build on our warning set.
$(HYDRO)/hydrogen.o: $(HYDRO)/hydrogen.c
	$(CC) -std=c11 -O2 -g -fPIE -I$(HYDRO) -c $< -o $@

# -MMD -MP, with the generated .d files read back by the -include at the foot of
# this file. Same mechanism and same idiom as game/Makefile and as the client
# build (devkitARM's base_rules compiles with `-MMD -MP -MF $(DEPSDIR)/$*.d` and
# the client Makefile ends with `-include $(DEPSDIR)/*.d`); the two server
# Makefiles are deliberately kept the same shape.
#
# The $(HYDRO)/hydrogen.h prerequisite below is NOT a header dependency and is not
# made redundant by -MMD. It is an ordering guarantee: on a fresh checkout the
# libhydrogen clone has not happened yet, and this is what forces the
# $(HYDRO)/hydrogen.h clone rule above to run first. -MMD can only
# record headers that existed at the time of a successful compile, so it cannot
# bootstrap that. Keep the prerequisite.
#
# Before this, the rule named that ONE header and no others, so editing
# allowlist.h, invite.h, proxyproto.h, ratelimit.h or replay.h left the matching
# object stale while make printed "'bsgate' is up to date." and exited 0.
# Measured 2026-08-30 from a clean tree: `touch allowlist.h ratelimit.h replay.h
# && make bsgate` -> "make: 'bsgate' is up to date.", rc=0, with all six of
# bsgate.o allowlist.o invite.o proxyproto.o ratelimit.o replay.o left untouched
# and older than the headers.
#
# That matters more here than anywhere else in this repo. This is the only
# process facing the internet, and the objects that silently do not get rebuilt
# are the allowlist, the rate limiter and the replay guard. A security fix to one
# of those headers could be edited, rebuilt, tested green and shipped without ever
# having been compiled in, because a skipped rebuild and a passing check produce
# byte-identical output.
#
# -MMD rather than -MD: libhydrogen and libc are not our drift risk, and listing
# them churns every .d on a toolchain update. -MP emits a phony target per header
# so DELETING a header gives a clean recompile instead of make aborting with
# "No rule to make target 'allowlist.h'" against a dep file that outlived it.
#
# Deliberately NOT the blunt `$(GATE_OBJS): $(wildcard *.h)` form. That would also
# turn the red arm above green while rebuilding all six objects for any header
# touched - passing the test for the wrong reason and hiding which translation
# unit actually depends on what. The .d files are exact; see the commit message
# for the per-object rebuild sets measured against them.
%.o: %.c $(HYDRO)/hydrogen.h
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

bsgate: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

bsgate_test: bsgate_test.o allowlist.o invite.o proxyproto.o ratelimit.o replay.o $(HYDRO)/hydrogen.o
	$(CC) $^ -o $@ $(LDFLAGS)

test: all bsgate_test
	./bsgate_test

# Confirms the hardening actually landed in the binary rather than trusting
# that the flags were accepted.
install-check: bsgate
	@echo "== binary hardening =="
	@readelf -d bsgate | grep -qE 'BIND_NOW'      && echo "  RELRO/BIND_NOW ok" || (echo "  MISSING bind-now"; exit 1)
	@readelf -h bsgate | grep -qE 'DYN'           && echo "  PIE ok"            || (echo "  MISSING pie"; exit 1)
	@readelf -lW bsgate | grep -q 'GNU_STACK.*RW ' && echo "  NX stack ok"       || (echo "  stack may be executable"; exit 1)

clean:
	rm -f *.o *.d bsgate bsgate_test $(HYDRO)/hydrogen.o

# Read back the header dependencies recorded by -MMD -MP on the last compile.
# Leading '-' because on a clean tree these do not exist yet and their absence is
# not an error: the first build compiles everything regardless, and it is that
# build which writes them.
#
# Consequence worth knowing before testing this mechanism: a tree built BEFORE
# this line existed has no .d files, so the first `make` after the change still
# cannot see header deps for objects it already considers up to date. Run
# `make clean` once when adopting this, or the fix looks like it did not work.
#
# Note this does NOT remove .deps/libhydrogen - `clean` only deletes that clone's
# hydrogen.o, so a clean does not re-trigger a network fetch of the pinned commit.
-include $(DEPS_MK)
