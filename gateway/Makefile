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

OBJS    := bsgate.o allowlist.o invite.o proxyproto.o ratelimit.o replay.o $(HYDRO)/hydrogen.o

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

%.o: %.c $(HYDRO)/hydrogen.h
	$(CC) $(CFLAGS) -c $< -o $@

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
	rm -f *.o bsgate bsgate_test $(HYDRO)/hydrogen.o
