/* bsgate — Blocksmith secure transport gateway.
 *
 * Terminates the encrypted link from a 3DS and hands *plaintext* to the game
 * logic over a local Unix datagram socket. It does no game logic itself, and
 * that separation is the point: this process is the only one facing the
 * network, it is small enough to read end to end, and a bug in the game
 * server cannot reach a socket.
 *
 * Crypto terminates HERE, never in the relay. The playit tunnel forwards
 * opaque UDP and holds no key, so a compromised relay yields ciphertext and
 * traffic timing — nothing else.
 *
 * The listening socket is on loopback. The only thing that can reach it is the
 * playit agent running beside this process, which dials *out* to the relay;
 * nothing on the internet can address this container at all, and no port is
 * forwarded on the router. Because every player then arrives from the agent's
 * own socket, the agent is configured to prefix each datagram with a PROXY
 * protocol v2 header carrying the real client address — without which layers
 * 2 and 3 below would be measuring the relay instead of the player.
 *
 * Layers, outermost first:
 *   1. nftables            — no inbound path exists; egress denied to this uid
 *   2. stateless cookie    — no allocation for an unproven source address
 *   3. token buckets       — a proven address still cannot flood handshakes
 *   4. network PSK         — without the shipped build, no handshake starts
 *   5. Noise XX            — mutual auth, forward secrecy, per-session keys
 *   6. allowlist           — the peer's static key must be a known friend
 *   7. AEAD + replay window— every data packet authenticated and used once
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <hydrogen.h>

#include "../proto/bs_proto.h"
#include "allowlist.h"
#include "invite.h"
#include "proxyproto.h"
#include "ratelimit.h"
#include "replay.h"

/* The wire format literals in bs_proto.h are duplicated so the 3DS build stays
 * dependency-free. If libhydrogen ever changes one, fail the build here rather
 * than ship a gateway that silently disagrees with every client. */
_Static_assert(BS_KX_PUBLICKEYBYTES == hydro_kx_PUBLICKEYBYTES, "kx pk size drift");
_Static_assert(BS_KX_PACKET1BYTES   == hydro_kx_XX_PACKET1BYTES, "kx p1 size drift");
_Static_assert(BS_KX_PACKET2BYTES   == hydro_kx_XX_PACKET2BYTES, "kx p2 size drift");
_Static_assert(BS_KX_PACKET3BYTES   == hydro_kx_XX_PACKET3BYTES, "kx p3 size drift");
_Static_assert(BS_AEAD_HEADERBYTES  == hydro_secretbox_HEADERBYTES, "aead hdr drift");
_Static_assert(sizeof BS_CTX_S2C - 1 == hydro_secretbox_CONTEXTBYTES, "ctx len");
_Static_assert(sizeof BS_CTX_C2S - 1 == hydro_secretbox_CONTEXTBYTES, "ctx len");

#define BS_MAX_SESSIONS    16u   /* established players                       */
#define BS_MAX_PENDING     32u   /* half-open handshakes                      */
#define BS_HANDSHAKE_MS  5000u   /* a pending slot lives this long            */
#define BS_SESSION_IDLE_MS 30000u

/* How long a probation session gets to send its BS_PKT_ENROL. Short on
 * purpose: the console types the code BEFORE it connects, so by the time the
 * handshake finishes the code is already in hand and the packet goes out
 * immediately. This is a network timeout, not thinking time. */
#define BS_ENROL_WINDOW_MS 10000u
#define BS_COOKIE_ROTATE_MS 60000u
#define BS_LOG_SUMMARY_MS  10000u

#define BS_HASH_CTX  "bsgateCK"

/* ------------------------------------------------------------------ state */

/* Behind a relay a peer has two addresses, and conflating them is a security
 * bug in one direction and a delivery bug in the other:
 *
 *   reply — where a datagram actually came from, and the only address a
 *           sendto() can use. Behind playit this is the agent's per-client
 *           socket on loopback, not the player.
 *   real  — the player's own address, from the PROXY protocol header. This is
 *           the identity the cookie is bound to and the key the rate limiter
 *           counts, because it is the thing an attacker cannot fake without
 *           already being past the relay.
 *
 * Without a relay the two are the same address and everything below still
 * reads correctly.
 */
struct bs_peer {
    struct sockaddr_in reply;
    struct sockaddr_in real;
};

struct bs_session {
    bool     used;
    uint32_t sid;
    struct bs_peer peer;

    hydro_kx_session_keypair keys;
    struct bs_replay  replay;
    uint64_t          tx_msg_id;

    uint8_t  peer_pk[BS_KX_PUBLICKEYBYTES];
    char     label[BS_ALLOW_LABEL_MAX];
    uint64_t last_seen_ms;

    /* Enrolment probation. A session in this state has completed the Noise
     * handshake and holds real session keys, but its key is NOT on the
     * allowlist yet and it has NOT been announced to the game server. The only
     * packet it may send is BS_PKT_ENROL; everything else is dropped, and it
     * evaporates at enrol_deadline_ms whether or not anything arrives.
     *
     * Reusing a session slot rather than inventing a third kind of half-peer
     * is deliberate: the AEAD decrypt, the replay window and the address
     * rebinding are then the same code that guards everybody else, instead of
     * a parallel implementation nobody looks at twice. */
    bool     enrolling;
    uint64_t enrol_deadline_ms;
};

struct bs_pending {
    bool     used;
    uint32_t sid;
    struct bs_peer peer;
    hydro_kx_state kx;
    uint64_t deadline_ms;
};

struct bs_gate {
    int  udp_fd;
    int  unix_fd;
    char game_sock_path[108];

    /* PROXY protocol v2, for running behind the playit agent. Off by default:
     * a gateway that trusts an address header it was not told to expect is a
     * gateway an attacker can lie to. */
    bool     proxy_proto;
    uint32_t trusted_net;    /* network byte order, already masked */
    uint32_t trusted_mask;   /* network byte order                 */

    hydro_kx_keypair static_kp;
    uint8_t          psk[hydro_kx_PSKBYTES];
    bool             have_psk;

    struct bs_allowlist allow;
    char                allow_path[512];

    /* At most one invite is armed at a time — see invite.h for why that is a
     * property and not a limitation. Reloaded on SIGHUP alongside the
     * allowlist, so `bsgate-keys invite` takes effect without a restart. */
    struct bs_invite    invite;
    char                invite_path[512];
    uint64_t            enrol_total;

    /* Where write_status() drops its snapshot. Written only on SIGUSR1, so
     * this costs nothing while nobody is looking — see write_status(). */
    char                status_path[512];
    char                listen_desc[80];   /* --listen host, up to 63, plus ":65535" */
    char                trusted_desc[32];

    struct bs_ratelimit rl;

    struct bs_session session[BS_MAX_SESSIONS];
    struct bs_pending pending[BS_MAX_PENDING];

    uint8_t  cookie_key[2][hydro_hash_KEYBYTES];
    uint64_t cookie_rotated_ms;

    /* Drops are counted and summarised rather than logged individually; a
     * flood must not be able to write the journal full. */
    uint64_t drop_count;
    uint64_t drop_reported_ms;

    /* Lifetime totals, for the status snapshot. drop_count above is reset
     * every summary interval, so it cannot answer "how many since boot". */
    uint64_t started_ms;
    uint64_t drop_total;
    uint64_t join_total;
};

static volatile sig_atomic_t g_reload = 0;
static volatile sig_atomic_t g_quit   = 0;
static volatile sig_atomic_t g_status = 0;

static void on_sighup(int s)  { (void)s; g_reload = 1; }
static void on_sigterm(int s) { (void)s; g_quit = 1; }
static void on_sigusr1(int s) { (void)s; g_status = 1; }

/* ------------------------------------------------------------------- util */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* snprintf that treats truncation as an error rather than a shrug.
 *
 * sun_path is 108 bytes and a state directory can be far longer than that.
 * Silently truncating would bind or send to a *different* socket than the one
 * configured, which fails in a way that looks like a network problem. */
__attribute__((format(printf, 3, 4)))
static bool path_set(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

static void logf_(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* Renders an address for the log. Deliberately drops the low 16 bits of the
 * IPv4 address: the journal should be useful for spotting a flood without
 * becoming a log of exactly who played from where. */
static void addr_str(const struct sockaddr_in *a, char *out, size_t n)
{
    uint32_t h = ntohl(a->sin_addr.s_addr);
    snprintf(out, n, "%u.%u.x.x", (h >> 24) & 0xff, (h >> 16) & 0xff);
}

/* ---------------------------------------------------------------- cookies */

static void cookie_rotate(struct bs_gate *g, uint64_t t)
{
    memcpy(g->cookie_key[1], g->cookie_key[0], hydro_hash_KEYBYTES);
    hydro_random_buf(g->cookie_key[0], hydro_hash_KEYBYTES);
    g->cookie_rotated_ms = t;
}

/* cookie = MAC(secret, source_ip || source_port || client_nonce)
 *
 * Bound to the address so it cannot be handed to a different host, and to the
 * client's nonce so a passive observer replaying an old cookie learns nothing.
 * Entirely stateless: nothing is stored server-side between HELLO and KX1. */
static void cookie_make(const struct bs_gate *g, unsigned which,
                        const struct sockaddr_in *addr,
                        const uint8_t nonce[BS_NONCE_BYTES],
                        uint8_t out[BS_COOKIE_BYTES])
{
    uint8_t buf[4 + 2 + BS_NONCE_BYTES];
    memcpy(buf,     &addr->sin_addr.s_addr, 4);
    memcpy(buf + 4, &addr->sin_port,        2);
    memcpy(buf + 6, nonce, BS_NONCE_BYTES);

    hydro_hash_hash(out, BS_COOKIE_BYTES, buf, sizeof buf,
                    BS_HASH_CTX, g->cookie_key[which]);
}

/* ------------------------------------------------------------- slot lookup */

static struct bs_session *session_by_sid(struct bs_gate *g, uint32_t sid)
{
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        if (g->session[i].used && g->session[i].sid == sid) return &g->session[i];
    }
    return NULL;
}

static struct bs_session *session_alloc(struct bs_gate *g)
{
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        if (!g->session[i].used) return &g->session[i];
    }
    return NULL;
}

static struct bs_pending *pending_by_sid(struct bs_gate *g, uint32_t sid)
{
    for (unsigned i = 0; i < BS_MAX_PENDING; i++) {
        if (g->pending[i].used && g->pending[i].sid == sid) return &g->pending[i];
    }
    return NULL;
}

static struct bs_pending *pending_alloc(struct bs_gate *g)
{
    for (unsigned i = 0; i < BS_MAX_PENDING; i++) {
        if (!g->pending[i].used) return &g->pending[i];
    }
    return NULL;
}

/* Zeroing on release matters: these structs hold session keys and Noise
 * handshake state, and a freed slot is reused by the next player. */
static void session_free(struct bs_session *s)
{
    hydro_memzero(s, sizeof *s);
}

static void pending_free(struct bs_pending *p)
{
    hydro_memzero(p, sizeof *p);
}

static uint32_t fresh_sid(struct bs_gate *g)
{
    for (;;) {
        uint32_t sid;
        hydro_random_buf(&sid, sizeof sid);
        if (sid == 0) continue;
        if (session_by_sid(g, sid) == NULL && pending_by_sid(g, sid) == NULL) {
            return sid;
        }
    }
}

/* ------------------------------------------------------- game-side socket */

enum bs_game_msg {
    BS_GAME_JOIN  = 1,   /* gate -> game: sid, pubkey, label */
    BS_GAME_DATA  = 2,   /* both ways:    sid, payload       */
    BS_GAME_LEAVE = 3,   /* gate -> game: sid                */
    BS_GAME_KICK  = 4    /* game -> gate: sid                */
};

static void game_send(struct bs_gate *g, const uint8_t *buf, size_t len)
{
    if (g->game_sock_path[0] == '\0') return;

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", g->game_sock_path);

    ssize_t n = sendto(g->unix_fd, buf, len, MSG_DONTWAIT,
                       (struct sockaddr *)&un, sizeof un);
    if (n < 0 && errno != EAGAIN && errno != ENOENT && errno != ECONNREFUSED) {
        logf_("gate: game socket send failed: %s", strerror(errno));
    }
}

static void game_notify_join(struct bs_gate *g, const struct bs_session *s)
{
    uint8_t buf[1 + 4 + BS_KX_PUBLICKEYBYTES + BS_ALLOW_LABEL_MAX];
    buf[0] = BS_GAME_JOIN;
    bs_put_u32(buf + 1, s->sid);
    memcpy(buf + 5, s->peer_pk, BS_KX_PUBLICKEYBYTES);
    memset(buf + 5 + BS_KX_PUBLICKEYBYTES, 0, BS_ALLOW_LABEL_MAX);
    memcpy(buf + 5 + BS_KX_PUBLICKEYBYTES, s->label, strnlen(s->label, BS_ALLOW_LABEL_MAX - 1));
    game_send(g, buf, sizeof buf);
}

static void game_notify_leave(struct bs_gate *g, uint32_t sid)
{
    uint8_t buf[5];
    buf[0] = BS_GAME_LEAVE;
    bs_put_u32(buf + 1, sid);
    game_send(g, buf, sizeof buf);
}

/* ----------------------------------------------------------- send helpers */

static void udp_send(struct bs_gate *g, const struct sockaddr_in *to,
                     const uint8_t *buf, size_t len)
{
    ssize_t n = sendto(g->udp_fd, buf, len, MSG_DONTWAIT,
                       (const struct sockaddr *)to, sizeof *to);
    if (n < 0 && errno != EAGAIN) {
        char a[32]; addr_str(to, a, sizeof a);
        logf_("gate: sendto %s failed: %s", a, strerror(errno));
    }
}

static void send_encrypted(struct bs_gate *g, struct bs_session *s,
                           uint8_t type, const uint8_t *payload, size_t len)
{
    if (len > BS_MAX_PAYLOAD) return;

    uint8_t out[BS_MAX_PACKET];
    bs_put_hdr(out, type);
    bs_put_u32(out + BS_HDR_BYTES, s->sid);

    uint64_t msg_id = s->tx_msg_id++;
    bs_put_u64(out + BS_HDR_BYTES + BS_SID_BYTES, msg_id);

    uint8_t *ct = out + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES;
    if (hydro_secretbox_encrypt(ct, payload, len, msg_id,
                                BS_CTX_S2C, s->keys.tx) != 0) {
        logf_("gate: encrypt failed for sid %08x", s->sid);
        return;
    }

    udp_send(g, &s->peer.reply, out, BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES
                                     + BS_AEAD_HEADERBYTES + len);
}

/* Every rejection funnels through here. There is no error packet, ever: an
 * unauthenticated sender learns nothing, not even that something is
 * listening, which makes the port effectively unscannable. */
static void drop(struct bs_gate *g, const char *why)
{
    (void)why;
    g->drop_count++;
    g->drop_total++;
}

/* ------------------------------------------------------- packet handlers */

static void handle_hello(struct bs_gate *g, const struct bs_peer *peer,
                         const uint8_t *pkt, size_t len)
{
    if (len != BS_HELLO_BYTES) { drop(g, "hello size"); return; }

    const uint8_t *nonce = pkt + BS_HDR_BYTES;

    /* Bound to the player's real address, never the relay's: a cookie that
     * proved only "you came through playit" would prove nothing at all,
     * because everyone comes through playit. */
    uint8_t cookie[BS_COOKIE_BYTES];
    cookie_make(g, 0, &peer->real, nonce, cookie);

    uint8_t out[BS_COOKIE_PKT_BYTES];
    bs_put_hdr(out, BS_PKT_COOKIE);
    memcpy(out + BS_HDR_BYTES, cookie, BS_COOKIE_BYTES);
    bs_put_u32(out + BS_HDR_BYTES + BS_COOKIE_BYTES, 0);   /* reserved */

    /* Note: no rate limit here. The reply is smaller than the request and
     * costs one hash, so answering is cheaper than tracking who asked. */
    udp_send(g, &peer->reply, out, sizeof out);
}

static void handle_kx1(struct bs_gate *g, const struct bs_peer *peer,
                       const uint8_t *pkt, size_t len, uint64_t t)
{
    if (len != BS_KX1_BYTES) { drop(g, "kx1 size"); return; }

    const uint8_t *cookie = pkt + BS_HDR_BYTES;
    const uint8_t *p1     = cookie + BS_COOKIE_BYTES;

    /* The client echoes the nonce inside Noise packet1's ephemeral key, so we
     * cannot recover it — instead the cookie is recomputed over the first
     * BS_NONCE_BYTES of packet1, which is what the client hashed. Both epochs
     * are tried so a cookie issued just before a rotation still works. */
    bool cookie_ok = false;
    for (unsigned e = 0; e < 2 && !cookie_ok; e++) {
        uint8_t expect[BS_COOKIE_BYTES];
        cookie_make(g, e, &peer->real, p1, expect);
        if (hydro_equal(expect, cookie, BS_COOKIE_BYTES)) cookie_ok = true;
        hydro_memzero(expect, sizeof expect);
    }
    if (!cookie_ok) { drop(g, "bad cookie"); return; }

    /* Rate limiting comes *after* the cookie check, deliberately. The cookie
     * proves the sender really holds this source address; charging a token
     * before that would let a spoofed packet drain a legitimate player's
     * bucket and lock them out from an address they do not control. Two
     * hashes is a cheap price for that.
     *
     * Keyed on the real client address. Keyed on the relay's instead, every
     * player would share one bucket and any single flooder would lock out the
     * whole server. */
    if (!bs_rl_allow(&g->rl, peer->real.sin_addr.s_addr, t)) {
        drop(g, "rate limited");
        return;
    }

    struct bs_pending *p = pending_alloc(g);
    if (p == NULL) { drop(g, "pending table full"); return; }

    uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
    if (hydro_kx_xx_2(&p->kx, packet2, p1,
                      g->have_psk ? g->psk : NULL, &g->static_kp) != 0) {
        /* Wrong PSK, or a malformed packet1. Indistinguishable to the sender
         * from the port being closed. */
        hydro_memzero(p, sizeof *p);
        drop(g, "kx2 failed");
        return;
    }

    p->used        = true;
    p->sid         = fresh_sid(g);
    p->peer        = *peer;
    p->deadline_ms = t + BS_HANDSHAKE_MS;

    uint8_t out[BS_KX2_BYTES];
    bs_put_hdr(out, BS_PKT_KX2);
    bs_put_u32(out + BS_HDR_BYTES, p->sid);
    memcpy(out + BS_HDR_BYTES + BS_SID_BYTES, packet2, sizeof packet2);
    hydro_memzero(packet2, sizeof packet2);

    udp_send(g, &peer->reply, out, sizeof out);
}

static void handle_kx3(struct bs_gate *g, const struct bs_peer *peer,
                       const uint8_t *pkt, size_t len, uint64_t t)
{
    if (len != BS_KX3_BYTES) { drop(g, "kx3 size"); return; }

    uint32_t sid = bs_get_u32(pkt + BS_HDR_BYTES);
    struct bs_pending *p = pending_by_sid(g, sid);
    if (p == NULL) { drop(g, "no pending"); return; }

    /* The session id is public — it travelled in cleartext in KX2 — so it is
     * not proof of anything on its own. Requiring the same source address
     * stops an off-path attacker who guessed or observed a sid from finishing
     * someone else's handshake. Noise itself would reject them at xx_4, but
     * refusing here avoids burning the pending slot.
     *
     * The real address is what must match. The relay may legitimately move a
     * player to a different local socket between packets, so pinning the
     * reply address instead would drop honest handshakes. */
    if (p->peer.real.sin_addr.s_addr != peer->real.sin_addr.s_addr
        || p->peer.real.sin_port != peer->real.sin_port) {
        drop(g, "kx3 address mismatch");
        return;
    }

    hydro_kx_session_keypair kp;
    uint8_t peer_pk[hydro_kx_PUBLICKEYBYTES];

    if (hydro_kx_xx_4(&p->kx, &kp, peer_pk, pkt + BS_HDR_BYTES + BS_SID_BYTES,
                      g->have_psk ? g->psk : NULL) != 0) {
        pending_free(p);
        drop(g, "kx4 failed");
        return;
    }

    const struct bs_allow_entry *entry = bs_allowlist_find(&g->allow, peer_pk);
    bool enrolling = false;

    if (entry == NULL) {
        char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
        char a[32];
        hydro_bin2hex(hex, sizeof hex, peer_pk, sizeof peer_pk);
        addr_str(&peer->real, a, sizeof a);

        /* With no invite armed this is the end of the road, exactly as it has
         * always been. That is the important half of this branch: enrolment is
         * not a permanently reachable code path, it exists only for the
         * minutes after an operator deliberately armed a code. */
        if (!bs_invite_valid(&g->invite, (int64_t)time(NULL))) {
            /* Logged in full, unlike ordinary drops: a cryptographically valid
             * handshake from an unknown key is either a friend whose key was
             * never added, or someone who has your build and PSK. Both are
             * worth seeing, and the hex is exactly what you paste into the
             * allowlist. */
            logf_("gate: REJECTED unknown key %s from %s", hex, a);
            hydro_memzero(&kp, sizeof kp);
            pending_free(p);
            return;
        }

        /* One probation slot at a time, matching the one armed invite. Without
         * this cap, an armed invite would let anyone holding the PSK fill
         * every session slot with handshakes that never enrol. */
        for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
            if (g->session[i].used && g->session[i].enrolling) {
                logf_("gate: enrolment already in progress, refused %s", a);
                hydro_memzero(&kp, sizeof kp);
                pending_free(p);
                return;
            }
        }

        enrolling = true;
        logf_("gate: unknown key %s from %s may attempt enrolment as '%s'",
              hex, a, g->invite.label);
    }

    struct bs_session *s = session_alloc(g);
    if (s == NULL) {
        logf_("gate: server full, refused %s", enrolling ? "an enrolment" : entry->label);
        hydro_memzero(&kp, sizeof kp);
        pending_free(p);
        return;
    }

    /* One key, one session: a reconnect after a crash or a lid-close must
     * replace the stale session rather than sit alongside it consuming a slot
     * until the idle timer fires. */
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        if (g->session[i].used
            && hydro_equal(g->session[i].peer_pk, peer_pk, BS_KX_PUBLICKEYBYTES)) {
            game_notify_leave(g, g->session[i].sid);
            session_free(&g->session[i]);
        }
    }

    memset(s, 0, sizeof *s);
    s->used = true;
    s->sid  = p->sid;
    s->peer = *peer;
    s->keys = kp;
    s->tx_msg_id = 0;
    bs_replay_init(&s->replay);
    memcpy(s->peer_pk, peer_pk, sizeof peer_pk);
    snprintf(s->label, sizeof s->label,
             "%s", enrolling ? g->invite.label : entry->label);
    s->last_seen_ms = t;

    hydro_memzero(&kp, sizeof kp);
    pending_free(p);

    if (enrolling) {
        /* Not a player yet: no join counter, and crucially no
         * game_notify_join(), so bsgame never learns this sid exists unless
         * and until the code checks out. */
        s->enrolling         = true;
        s->enrol_deadline_ms = t + BS_ENROL_WINDOW_MS;
        return;
    }

    g->join_total++;

    char a[32]; addr_str(&peer->real, a, sizeof a);
    logf_("gate: %s joined (sid %08x) from %s", s->label, s->sid, a);
    game_notify_join(g, s);
}

/* Turns a probation session into a real one: writes the key into the
 * allowlist, reloads it, consumes the invite, and only then announces the
 * player. Ordering is the point — the allowlist entry must exist and be
 * readable before anything treats this peer as admitted, so that a crash
 * anywhere in here leaves either "not enrolled" or "enrolled and allowed",
 * never "playing but not on the list". */
static void enrol_succeed(struct bs_gate *g, struct bs_session *s, uint64_t t)
{
    char why[192];

    if (!bs_allowlist_append(g->allow_path, s->peer_pk, s->label, why, sizeof why)) {
        logf_("gate: enrolment of '%s' FAILED to write the allowlist: %s",
              s->label, why);
        session_free(s);
        return;
    }

    struct bs_allowlist fresh;
    if (!bs_allowlist_load(&fresh, g->allow_path, why, sizeof why)) {
        /* Should be unreachable: append validates the candidate before
         * installing it. Logged rather than ignored because if it ever does
         * happen, the running daemon and the file on disk now disagree. */
        logf_("gate: enrolment wrote the allowlist but it will not reload: %s", why);
        session_free(s);
        return;
    }
    g->allow = fresh;
    hydro_memzero(&fresh, sizeof fresh);

    g->invite.armed = false;
    if (!bs_invite_save(&g->invite, g->invite_path, why, sizeof why)) {
        /* The key is already on the allowlist, so refusing to admit them now
         * would be pointless. But a code that outlives its single use is a
         * standing door, so this is loud. */
        logf_("gate: WARNING could not clear the used invite at %s: %s — "
              "run `bsgate-keys invite --cancel`", g->invite_path, why);
    }

    s->enrolling = false;
    s->enrol_deadline_ms = 0;
    g->enrol_total++;
    g->join_total++;

    char a[32]; addr_str(&s->peer.real, a, sizeof a);
    char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
    hydro_bin2hex(hex, sizeof hex, s->peer_pk, sizeof s->peer_pk);
    logf_("gate: ENROLLED '%s' key %s from %s — invite consumed", s->label, hex, a);

    send_encrypted(g, s, BS_PKT_ENROL_OK, NULL, 0);
    logf_("gate: %s joined (sid %08x) from %s", s->label, s->sid, a);
    game_notify_join(g, s);
    (void)t;
}

static void handle_data(struct bs_gate *g, const struct bs_peer *peer,
                        const uint8_t *pkt, size_t len, uint64_t t)
{
    const size_t min = BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES + BS_AEAD_HEADERBYTES;
    if (len < min || len > BS_MAX_PACKET) { drop(g, "data size"); return; }

    uint32_t sid = bs_get_u32(pkt + BS_HDR_BYTES);
    struct bs_session *s = session_by_sid(g, sid);
    if (s == NULL) { drop(g, "no session"); return; }

    uint64_t msg_id = bs_get_u64(pkt + BS_HDR_BYTES + BS_SID_BYTES);
    const uint8_t *ct = pkt + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES;
    size_t ct_len = len - (BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES);

    uint8_t plain[BS_MAX_PAYLOAD];
    if (hydro_secretbox_decrypt(plain, ct, ct_len, msg_id,
                                BS_CTX_C2S, s->keys.rx) != 0) {
        drop(g, "auth failed");
        return;
    }
    size_t plain_len = ct_len - BS_AEAD_HEADERBYTES;

    /* Only now, with the tag verified, may the window be touched. Checking
     * replay before authentication would let a forged id lock out the peer. */
    if (!bs_replay_check(&s->replay, msg_id)) {
        hydro_memzero(plain, sizeof plain);
        drop(g, "replay");
        return;
    }

    /* Authenticated, so trusting the new addresses is safe. This is what
     * survives a 3DS moving between access points, a NAT rebinding after the
     * console sleeps, or the relay moving the player to a fresh local socket. */
    s->peer = *peer;
    s->last_seen_ms = t;

    /* A probation session is not a player. It may send exactly one kind of
     * packet, and every other kind — including a perfectly well-formed DATA —
     * ends it. Handled before the DISCONNECT and DATA branches below so that
     * neither can be reached by a peer who is not on the allowlist. */
    if (s->enrolling) {
        if (pkt[0] != BS_PKT_ENROL) {
            logf_("gate: enrolment attempt sent 0x%02x instead of a code — dropped",
                  pkt[0]);
            session_free(s);
            hydro_memzero(plain, sizeof plain);
            return;
        }

        char code[BS_INVITE_CODE_MAX + 1];
        size_t n = plain_len < BS_INVITE_CODE_MAX ? plain_len : BS_INVITE_CODE_MAX;
        memcpy(code, plain, n);
        code[n] = '\0';

        bool good = bs_invite_matches(&g->invite, code, (int64_t)time(NULL));
        hydro_memzero(code, sizeof code);
        hydro_memzero(plain, sizeof plain);

        if (good) {
            enrol_succeed(g, s, t);
            return;
        }

        /* Wrong code. Burn a strike and persist it, so that hammering cannot
         * be reset by restarting the daemon, and disarm once they are gone. */
        char a[32]; addr_str(&s->peer.real, a, sizeof a);
        if (g->invite.strikes_left > 0) g->invite.strikes_left--;
        if (g->invite.strikes_left == 0) {
            g->invite.armed = false;
            logf_("gate: wrong invite code from %s — invite for '%s' is now BURNT, "
                  "arm a new one with `bsgate-keys invite`", a, g->invite.label);
        } else {
            logf_("gate: wrong invite code from %s — %u attempt(s) left",
                  a, g->invite.strikes_left);
        }

        char why[192];
        if (!bs_invite_save(&g->invite, g->invite_path, why, sizeof why)) {
            logf_("gate: could not persist the invite strike count: %s", why);
        }

        session_free(s);
        return;
    }

    if (pkt[0] == BS_PKT_ENROL) {
        /* An allowlisted peer has no business enrolling; it is already in. */
        drop(g, "enrol from an established session");
        hydro_memzero(plain, sizeof plain);
        return;
    }

    if (pkt[0] == BS_PKT_DISCONNECT) {
        logf_("gate: %s left (sid %08x)", s->label, s->sid);
        game_notify_leave(g, s->sid);
        session_free(s);
        hydro_memzero(plain, sizeof plain);
        return;
    }

    if (plain_len > 0) {
        uint8_t msg[5 + BS_MAX_PAYLOAD];
        msg[0] = BS_GAME_DATA;
        bs_put_u32(msg + 1, s->sid);
        memcpy(msg + 5, plain, plain_len);
        game_send(g, msg, 5 + plain_len);
        hydro_memzero(msg, sizeof msg);
    } else {
        /* A zero-length DATA is the client's round-trip probe: it carries no
         * application payload, so there is nothing to hand the game server,
         * and the game server would have nothing to say about it anyway. The
         * gate answers it itself, in kind.
         *
         * This is not politeness. The client only starts a new keepalive once
         * the previous probe has been answered, so if nothing ever replies the
         * probe stays outstanding, the client stops sending, and after
         * BS_SESSION_IDLE_MS the gate drops a player who was sitting there
         * perfectly happily. Measured before this existed: a lone player was
         * evicted at 30 s with netPingMs() still reporting -1. */
        send_encrypted(g, s, BS_PKT_DATA, plain, 0);
    }

    hydro_memzero(plain, sizeof plain);
}

/* Is this datagram from an address permitted to assert a PROXY header?
 * Anything that can write to the socket can claim to be anyone, so the answer
 * has to come from configuration, never from the packet. */
static bool proxy_source_trusted(const struct bs_gate *g,
                                 const struct sockaddr_in *from)
{
    return (from->sin_addr.s_addr & g->trusted_mask) == g->trusted_net;
}

static void handle_udp(struct bs_gate *g)
{
    /* Room for the largest game packet plus a PROXY header with TLVs in
     * front of it. */
    uint8_t pkt[BS_MAX_PACKET + 256];
    struct sockaddr_in from;
    socklen_t flen = sizeof from;

    ssize_t n = recvfrom(g->udp_fd, pkt, sizeof pkt, MSG_DONTWAIT,
                         (struct sockaddr *)&from, &flen);
    if (n < 0) return;
    if (flen != sizeof from || from.sin_family != AF_INET) { drop(g, "family"); return; }

    struct bs_peer peer;
    peer.reply = from;
    peer.real  = from;

    const uint8_t *body = pkt;
    size_t body_len = (size_t)n;

    if (g->proxy_proto) {
        /* Order matters: check who is speaking before believing what they
         * say. Parsing first would still be safe, but refusing untrusted
         * sources outright keeps the parser off the reachable path entirely. */
        if (!proxy_source_trusted(g, &from)) {
            drop(g, "proxy header from untrusted source");
            return;
        }

        int off = bs_ppv2_parse(pkt, body_len, &peer.real);
        if (off < 0) {
            /* No silent fallback to the socket address. Accepting a datagram
             * that failed to prove who sent it is the whole vulnerability
             * this header exists to avoid. */
            drop(g, "bad proxy header");
            return;
        }

        body     = pkt + off;
        body_len -= (size_t)off;
    }

    if (body_len < BS_HDR_BYTES) { drop(g, "runt"); return; }

    if (body[1] != BS_PROTO_VERSION) { drop(g, "version"); return; }
    if (body[2] != 0 || body[3] != 0) { drop(g, "reserved"); return; }

    uint64_t t = now_ms();

    switch (body[0]) {
    case BS_PKT_HELLO: handle_hello(g, &peer, body, body_len);    break;
    case BS_PKT_KX1:   handle_kx1(g, &peer, body, body_len, t);   break;
    case BS_PKT_KX3:   handle_kx3(g, &peer, body, body_len, t);   break;
    case BS_PKT_DATA:
    case BS_PKT_DISCONNECT:
    case BS_PKT_ENROL:
                       handle_data(g, &peer, body, body_len, t);  break;
    default:           drop(g, "type");                           break;
    }
}

static void handle_game(struct bs_gate *g)
{
    uint8_t buf[5 + BS_MAX_PAYLOAD];
    ssize_t n = recv(g->unix_fd, buf, sizeof buf, MSG_DONTWAIT);
    if (n < 5) return;

    uint32_t sid = bs_get_u32(buf + 1);
    struct bs_session *s = session_by_sid(g, sid);
    if (s == NULL) return;      /* the player left while the game was replying */

    /* bsgame is never told about a probation sid, so it cannot legitimately
     * name one. Belt and braces: a bug there must not be able to push traffic
     * to a peer who is not on the allowlist. */
    if (s->enrolling) return;

    switch (buf[0]) {
    case BS_GAME_DATA:
        send_encrypted(g, s, BS_PKT_DATA, buf + 5, (size_t)n - 5);
        break;
    case BS_GAME_KICK:
        logf_("gate: %s kicked by game logic (sid %08x)", s->label, s->sid);
        send_encrypted(g, s, BS_PKT_DISCONNECT, NULL, 0);
        game_notify_leave(g, s->sid);
        session_free(s);
        break;
    default:
        break;
    }
}

/* ----------------------------------------------------------- status dump */

/* The journal masks peer addresses to a /16 (addr_str), because a friend's
 * home IP sitting in a log that gets pasted into a chat window is a leak
 * nobody asked for. The status snapshot is different: it is written only when
 * asked for, read only by root inside the container, and "who is connected,
 * from where" is the whole reason it exists. So it prints the address in
 * full — and nothing else does. */
static void addr_str_full(const struct sockaddr_in *a, char *out, size_t n)
{
    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip) == NULL) {
        snprintf(out, n, "?");
        return;
    }
    snprintf(out, n, "%s:%u", ip, (unsigned)ntohs(a->sin_port));
}

/* Writes a plain-text snapshot of what this process currently knows, for
 * tools/bsgate-status to read back. Triggered by SIGUSR1 only.
 *
 * Why a file and a signal, rather than a query socket: a socket is a second
 * thing listening, with a second parser, reachable by anything that can find
 * it — on a box whose entire design is "zero inbound, one parser". A signal
 * costs no attack surface at all (only root and the process's own uid may
 * send one) and the snapshot is a file the reader cannot talk back through.
 *
 * Written to a temp path and renamed, so a reader never sees a half-written
 * file, and mode 0640 so the group can read it but not the world. */
static void write_status(struct bs_gate *g, uint64_t t)
{
    char tmp[520];
    if (!path_set(tmp, sizeof tmp, "%s.tmp", g->status_path)) return;

    FILE *f = fopen(tmp, "w");
    if (f == NULL) {
        logf_("gate: status: %s: %s", tmp, strerror(errno));
        return;
    }
    fchmod(fileno(f), 0640);

    fprintf(f, "process bsgate\n");
    fprintf(f, "uptime_s %llu\n", (unsigned long long)((t - g->started_ms) / 1000u));
    fprintf(f, "listen %s\n", g->listen_desc);
    fprintf(f, "proxy_protocol %s\n", g->proxy_proto ? "v2" : "off");
    if (g->proxy_proto) fprintf(f, "trusted_proxy %s\n", g->trusted_desc);
    fprintf(f, "allowlist_peers %zu\n", g->allow.count);
    fprintf(f, "sessions_max %u\n", BS_MAX_SESSIONS);
    fprintf(f, "joins_total %llu\n", (unsigned long long)g->join_total);
    fprintf(f, "dropped_total %llu\n", (unsigned long long)g->drop_total);
    fprintf(f, "enrolments_total %llu\n", (unsigned long long)g->enrol_total);

    /* An armed invite is a temporarily open door and belongs in the same
     * report as the firewall state — the one thing an operator must not be
     * able to forget about. The code itself is not here and could not be
     * printed even if it were wanted: only its hash exists on this box. */
    if (bs_invite_valid(&g->invite, (int64_t)time(NULL))) {
        long long left = (long long)g->invite.expires_unix - (long long)time(NULL);
        fprintf(f, "invite_armed %s %lld %u\n",
                g->invite.label, left < 0 ? 0 : left, g->invite.strikes_left);
    } else {
        fprintf(f, "invite_armed none 0 0\n");
    }

    unsigned pending = 0;
    for (unsigned i = 0; i < BS_MAX_PENDING; i++) if (g->pending[i].used) pending++;
    fprintf(f, "handshakes_in_flight %u\n", pending);

    unsigned live = 0;
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) if (g->session[i].used) live++;
    fprintf(f, "sessions %u\n", live);

    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        const struct bs_session *s = &g->session[i];
        if (!s->used) continue;

        char real[64], reply[64];
        addr_str_full(&s->peer.real,  real,  sizeof real);
        addr_str_full(&s->peer.reply, reply, sizeof reply);

        /* idle_ms is how long since anything was heard FROM this player. It
         * is not a round-trip time and must never be presented as one: the
         * server never solicits a reply, so it has no RTT to report. See
         * tools/bsgate-status, which labels this column accordingly. */
        fprintf(f, "session %08x %s %s %s %llu%s\n",
                s->sid, s->label, real, reply,
                (unsigned long long)(t - s->last_seen_ms),
                s->enrolling ? " enrolling" : "");
    }

    fclose(f);
    if (rename(tmp, g->status_path) != 0) {
        logf_("gate: status: rename: %s", strerror(errno));
        unlink(tmp);
    }
}

static void tick(struct bs_gate *g, uint64_t t)
{
    for (unsigned i = 0; i < BS_MAX_PENDING; i++) {
        if (g->pending[i].used && t > g->pending[i].deadline_ms) {
            pending_free(&g->pending[i]);
        }
    }

    /* Probation sessions expire on their own, much shorter clock. Swept before
     * the idle sweep below so an enrolment slot can never sit occupied for the
     * full 30-second idle timeout and block the next attempt. */
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        struct bs_session *s = &g->session[i];
        if (s->used && s->enrolling && t > s->enrol_deadline_ms) {
            logf_("gate: enrolment attempt expired without a code");
            session_free(s);
        }
    }

    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        struct bs_session *s = &g->session[i];
        if (s->used && !s->enrolling && t - s->last_seen_ms > BS_SESSION_IDLE_MS) {
            logf_("gate: %s timed out (sid %08x)", s->label, s->sid);
            game_notify_leave(g, s->sid);
            session_free(s);
        }
    }

    if (t - g->cookie_rotated_ms > BS_COOKIE_ROTATE_MS) cookie_rotate(g, t);

    if (g->drop_count > 0 && t - g->drop_reported_ms > BS_LOG_SUMMARY_MS) {
        logf_("gate: dropped %llu unauthenticated packets in the last %us",
              (unsigned long long)g->drop_count, BS_LOG_SUMMARY_MS / 1000u);
        g->drop_count = 0;
        g->drop_reported_ms = t;
    }
}

/* ------------------------------------------------------------------ setup */

/* Loads a secret from `path`, or creates it with 0600 if absent. Refuses to
 * use a file that is group- or world-readable: a leaked static key means an
 * attacker can impersonate the server to every client. */
static bool load_or_create_secret(const char *path, uint8_t *buf, size_t len,
                                  bool create)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_mode & (S_IRWXG | S_IRWXO)) {
            logf_("gate: %s is group/world accessible (mode %o) — refusing",
                  path, st.st_mode & 07777);
            return false;
        }
        if ((size_t)st.st_size != len) {
            logf_("gate: %s is %lld bytes, expected %zu",
                  path, (long long)st.st_size, len);
            return false;
        }
        FILE *f = fopen(path, "rbe");
        if (f == NULL) { logf_("gate: cannot read %s", path); return false; }
        bool ok = fread(buf, 1, len, f) == len;
        fclose(f);
        if (!ok) logf_("gate: short read on %s", path);
        return ok;
    }

    if (!create) { logf_("gate: %s does not exist", path); return false; }

    hydro_random_buf(buf, len);

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { logf_("gate: cannot create %s: %s", path, strerror(errno)); return false; }
    bool ok = write(fd, buf, len) == (ssize_t)len;
    if (fsync(fd) != 0) ok = false;
    close(fd);
    if (!ok) logf_("gate: failed writing %s", path);
    return ok;
}

static bool udp_bind(struct bs_gate *g, const char *ip, uint16_t port)
{
    g->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (g->udp_fd < 0) { logf_("gate: socket: %s", strerror(errno)); return false; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        logf_("gate: bad listen address '%s'", ip);
        return false;
    }

    if (bind(g->udp_fd, (struct sockaddr *)&a, sizeof a) != 0) {
        logf_("gate: bind %s:%u: %s", ip, port, strerror(errno));
        return false;
    }
    logf_("gate: listening on %s:%u", ip, port);
    return true;
}

static bool unix_bind(struct bs_gate *g, const char *path)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;

    if (!path_set(un.sun_path, sizeof un.sun_path, "%s", path)) {
        logf_("gate: socket path too long (max %zu): %s", sizeof un.sun_path - 1, path);
        return false;
    }

    g->unix_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (g->unix_fd < 0) { logf_("gate: unix socket: %s", strerror(errno)); return false; }

    unlink(path);

    /* 0770 with a shared group, so the game process can reply but nothing
     * else on the box can inject packets as if they came from a player. */
    mode_t old = umask(0007);
    bool ok = bind(g->unix_fd, (struct sockaddr *)&un, sizeof un) == 0;
    umask(old);

    if (!ok) { logf_("gate: bind %s: %s", path, strerror(errno)); return false; }
    return true;
}

/* Parses "A.B.C.D/len" into a masked network and mask, both in network byte
 * order so a match is one AND against a raw s_addr. */
static bool parse_cidr(const char *s, uint32_t *net, uint32_t *mask)
{
    char buf[64];
    if (!path_set(buf, sizeof buf, "%s", s)) return false;

    char *slash = strchr(buf, '/');
    if (slash == NULL) return false;
    *slash = '\0';

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return false;

    char *end = NULL;
    long bits = strtol(slash + 1, &end, 10);
    if (end == NULL || *end != '\0' || bits < 0 || bits > 32) return false;

    /* A /0 shifts by 32, which is undefined for a 32-bit type, so it is
     * spelled out rather than computed. */
    uint32_t m = (bits == 0) ? 0u : htonl(0xFFFFFFFFu << (32 - (unsigned)bits));

    *mask = m;
    *net  = a.s_addr & m;
    return true;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: bsgate --listen IP:PORT --state-dir DIR [options]\n"
        "  --listen IP:PORT      bind address; 127.0.0.1 behind the playit agent\n"
        "  --state-dir DIR       holds server.seed, network.psk, allowlist\n"
        "  --gate-socket PATH    unix socket this process binds   (default DIR/gate.sock)\n"
        "  --game-socket PATH    unix socket the game logic binds (default DIR/game.sock)\n"
        "  --proxy-protocol      expect a PROXY protocol v2 header on every datagram\n"
        "                        and take the client address from it. Required when\n"
        "                        running behind the playit agent, and only safe when\n"
        "                        nothing untrusted can reach --listen.\n"
        "  --trusted-proxy CIDR  who may assert that header (default 127.0.0.0/8)\n"
        "  --print-identity      print the server public key and PSK, then exit\n"
        "  --arm-invite LABEL    generate a one-time enrolment code for LABEL,\n"
        "                        print it once, then exit. Replaces any existing\n"
        "                        invite. The code is stored hashed and cannot be\n"
        "                        printed again.\n"
        "  --cancel-invite       disarm the current invite, then exit\n"
        "  --show-invite         report the armed invite, then exit\n");
}

/* The three invite modes below are one-shot operations run by `bsgate-keys`,
 * not by the daemon. They are handled here rather than in the shell script for
 * one reason: the hash and the file format must have exactly one implementation.
 * A shell reimplementation of either would be a second thing to keep in step
 * with invite.c, and the failure mode of it drifting is an invite nobody can
 * redeem — or worse, one that validates against the wrong digest.
 *
 * Each returns the process exit code. Output is machine-readable `key value`
 * lines, matching --print-identity, because bsgate-keys parses it. */
static int mode_arm_invite(struct bs_invite *iv, const char *path,
                           const char *label)
{
    if (!bs_allowlist_label_ok(label)) {
        fprintf(stderr, "bsgate: invalid label '%s' — use 1-%u characters of "
                        "A-Z a-z 0-9 _ -\n", label, BS_ALLOW_LABEL_MAX - 1);
        return 1;
    }

    char code[BS_INVITE_CODE_MAX + 1];
    bs_invite_generate(code, sizeof code);

    memset(iv, 0, sizeof *iv);
    iv->armed        = true;
    iv->expires_unix = (int64_t)time(NULL) + BS_INVITE_TTL_SEC;
    iv->strikes_left = BS_INVITE_STRIKES;
    snprintf(iv->label, sizeof iv->label, "%s", label);
    bs_invite_hash_code(code, iv->code_hash);

    char why[256];
    if (!bs_invite_save(iv, path, why, sizeof why)) {
        fprintf(stderr, "bsgate: %s\n", why);
        hydro_memzero(code, sizeof code);
        return 1;
    }

    /* Printed with the separator for a human to read out; the daemon strips it
     * again on the way in, so the friend may type it with or without. */
    printf("invite_label   %s\n", label);
    printf("invite_code    %.5s-%.5s\n", code, code + 5);
    printf("invite_expires %lld\n", (long long)iv->expires_unix);
    printf("invite_ttl_s   %d\n", (int)BS_INVITE_TTL_SEC);
    hydro_memzero(code, sizeof code);
    return 0;
}

static int mode_cancel_invite(struct bs_invite *iv, const char *path)
{
    memset(iv, 0, sizeof *iv);
    iv->armed = false;

    char why[256];
    if (!bs_invite_save(iv, path, why, sizeof why)) {
        fprintf(stderr, "bsgate: %s\n", why);
        return 1;
    }
    printf("invite_armed none 0 0\n");
    return 0;
}

static int mode_show_invite(struct bs_invite *iv, const char *path)
{
    char why[256];
    if (!bs_invite_load(iv, path, why, sizeof why)) {
        fprintf(stderr, "bsgate: %s\n", why);
        return 1;
    }

    int64_t now = (int64_t)time(NULL);
    if (bs_invite_valid(iv, now)) {
        long long left = (long long)iv->expires_unix - (long long)now;
        printf("invite_armed %s %lld %u\n", iv->label, left, iv->strikes_left);
    } else {
        printf("invite_armed none 0 0\n");
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *listen_arg = NULL, *state_dir = NULL;
    const char *gate_sock = NULL, *game_sock = NULL;
    const char *trusted_cidr = "127.0.0.0/8";
    bool print_identity = false;
    bool proxy_proto = false;
    const char *arm_invite = NULL;
    bool cancel_invite = false, show_invite = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--listen") && i + 1 < argc)            listen_arg = argv[++i];
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc)    state_dir  = argv[++i];
        else if (!strcmp(argv[i], "--gate-socket") && i + 1 < argc)  gate_sock  = argv[++i];
        else if (!strcmp(argv[i], "--game-socket") && i + 1 < argc)  game_sock  = argv[++i];
        else if (!strcmp(argv[i], "--trusted-proxy") && i + 1 < argc) trusted_cidr = argv[++i];
        else if (!strcmp(argv[i], "--proxy-protocol"))               proxy_proto = true;
        else if (!strcmp(argv[i], "--print-identity"))               print_identity = true;
        else if (!strcmp(argv[i], "--arm-invite") && i + 1 < argc)   arm_invite = argv[++i];
        else if (!strcmp(argv[i], "--cancel-invite"))                cancel_invite = true;
        else if (!strcmp(argv[i], "--show-invite"))                  show_invite = true;
        else { usage(); return 2; }
    }

    /* Every one-shot mode needs only --state-dir; the daemon additionally needs
     * --listen. Grouped into one flag so adding a mode cannot accidentally
     * leave the daemon startable without an address. */
    bool oneshot = print_identity || arm_invite != NULL
                || cancel_invite || show_invite;

    if (state_dir == NULL || (listen_arg == NULL && !oneshot)) {
        usage();
        return 2;
    }

    if (hydro_init() != 0) { logf_("gate: hydro_init failed"); return 1; }

    static struct bs_gate g;
    memset(&g, 0, sizeof g);
    g.udp_fd = g.unix_fd = -1;

    g.proxy_proto = proxy_proto;
    if (!parse_cidr(trusted_cidr, &g.trusted_net, &g.trusted_mask)) {
        logf_("gate: --trusted-proxy must be CIDR, e.g. 127.0.0.0/8 (got '%s')",
              trusted_cidr);
        return 1;
    }

    /* Unix socket paths are bounded by sun_path, not by PATH_MAX, and every
     * one of these is refused rather than truncated. */
    char key_path[512], psk_path[512];
    char gate_path[sizeof g.game_sock_path];
    char game_path[sizeof g.game_sock_path];

    bool paths_ok =
        path_set(key_path, sizeof key_path, "%s/server.seed", state_dir)
     && path_set(psk_path, sizeof psk_path, "%s/network.psk", state_dir)
     && path_set(g.allow_path, sizeof g.allow_path, "%s/allowlist", state_dir)
     && (gate_sock ? path_set(gate_path, sizeof gate_path, "%s", gate_sock)
                   : path_set(gate_path, sizeof gate_path, "%s/gate.sock", state_dir))
     && (game_sock ? path_set(game_path, sizeof game_path, "%s", game_sock)
                   : path_set(game_path, sizeof game_path, "%s/game.sock", state_dir))
     && path_set(g.game_sock_path, sizeof g.game_sock_path, "%s", game_path)
     && path_set(g.status_path, sizeof g.status_path, "%s/status.txt", state_dir)
     && path_set(g.invite_path, sizeof g.invite_path, "%s/invite", state_dir);

    if (!paths_ok) {
        logf_("gate: --state-dir or a --*-socket path is too long "
              "(unix sockets cap at %zu bytes)", sizeof g.game_sock_path - 1);
        return 1;
    }

    /* Handled before the identity keys are touched, deliberately: arming an
     * invite must never be the thing that creates server.seed. If someone runs
     * this against the wrong --state-dir, the mistake should be an invite file
     * in an odd place, not a second server identity that later starts a daemon
     * every existing client refuses to talk to. */
    if (arm_invite != NULL || cancel_invite || show_invite) {
        if ((arm_invite != NULL) + (cancel_invite ? 1 : 0) + (show_invite ? 1 : 0) > 1) {
            fprintf(stderr, "bsgate: pick one of --arm-invite / --cancel-invite / "
                            "--show-invite\n");
            return 2;
        }
        int rc = arm_invite  ? mode_arm_invite(&g.invite, g.invite_path, arm_invite)
               : cancel_invite ? mode_cancel_invite(&g.invite, g.invite_path)
                               : mode_show_invite(&g.invite, g.invite_path);
        hydro_memzero(&g, sizeof g);
        return rc;
    }

    /* A 32-byte seed is stored, not the keypair: both halves are re-derived
     * every start, so the file can never hold a public key that disagrees
     * with its secret, and backing up the identity is backing up 32 bytes. */
    uint8_t seed[hydro_kx_SEEDBYTES];
    if (!load_or_create_secret(key_path, seed, sizeof seed, true)) return 1;
    hydro_kx_keygen_deterministic(&g.static_kp, seed);
    hydro_memzero(seed, sizeof seed);

    if (load_or_create_secret(psk_path, g.psk, sizeof g.psk, true)) {
        g.have_psk = true;
    } else {
        return 1;
    }

    if (print_identity) {
        char pk_hex[2 * hydro_kx_PUBLICKEYBYTES + 1];
        char psk_hex[2 * hydro_kx_PSKBYTES + 1];
        hydro_bin2hex(pk_hex, sizeof pk_hex, g.static_kp.pk, sizeof g.static_kp.pk);
        hydro_bin2hex(psk_hex, sizeof psk_hex, g.psk, sizeof g.psk);
        printf("server_public_key %s\n", pk_hex);
        printf("network_psk       %s\n", psk_hex);
        hydro_memzero(&g, sizeof g);
        return 0;
    }

    char err[256];
    if (!bs_allowlist_load(&g.allow, g.allow_path, err, sizeof err)) {
        /* Starting with an empty allowlist would look healthy and admit
         * nobody, which is a confusing failure. Refuse instead. */
        logf_("gate: %s", err);
        return 1;
    }
    logf_("gate: %zu peer(s) allowed", g.allow.count);

    /* A malformed invite file is fatal for the same reason a malformed
     * allowlist is: both decide who gets in, and starting anyway would mean
     * running with a security record the operator believes is in force and
     * isn't. A MISSING file is not malformed — that is the normal state and
     * bs_invite_load reports it as success with armed=false. */
    if (!bs_invite_load(&g.invite, g.invite_path, err, sizeof err)) {
        logf_("gate: %s", err);
        return 1;
    }
    if (bs_invite_valid(&g.invite, (int64_t)time(NULL))) {
        logf_("gate: invite armed for '%s', %lld second(s) left, %u attempt(s)",
              g.invite.label,
              (long long)g.invite.expires_unix - (long long)time(NULL),
              g.invite.strikes_left);
    }

    char ip[64];
    const char *colon = strrchr(listen_arg, ':');
    if (colon == NULL || (size_t)(colon - listen_arg) >= sizeof ip) {
        logf_("gate: --listen must be IP:PORT");
        return 1;
    }
    memcpy(ip, listen_arg, (size_t)(colon - listen_arg));
    ip[colon - listen_arg] = '\0';
    long port = strtol(colon + 1, NULL, 10);
    if (port < 1 || port > 65535) { logf_("gate: bad port"); return 1; }

    /* A /0 trusted range means "believe whatever address any sender claims",
     * which silently turns the cookie exchange into a no-op and lets one host
     * exhaust every rate-limit slot by inventing addresses. There is no
     * legitimate reason to configure it, so it is refused rather than warned
     * about. */
    if (g.proxy_proto && g.trusted_mask == 0) {
        logf_("gate: --trusted-proxy 0.0.0.0/0 with --proxy-protocol would let "
              "any sender forge a client address — refusing");
        return 1;
    }

    if (!udp_bind(&g, ip, (uint16_t)port)) return 1;
    if (!unix_bind(&g, gate_path)) return 1;

    if (g.proxy_proto) {
        logf_("gate: PROXY protocol v2 expected, trusting %s", trusted_cidr);
    }

    uint64_t t = now_ms();
    bs_rl_init(&g.rl, t);
    hydro_random_buf(g.cookie_key[0], sizeof g.cookie_key[0]);
    hydro_random_buf(g.cookie_key[1], sizeof g.cookie_key[1]);
    g.cookie_rotated_ms = t;
    g.drop_reported_ms  = t;
    g.started_ms        = t;

    /* Copied rather than kept as pointers into argv: the status snapshot is
     * written from the poll loop long after argument parsing, and argv is not
     * something to still be holding by then. */
    snprintf(g.listen_desc,  sizeof g.listen_desc,  "%s:%ld", ip, port);
    snprintf(g.trusted_desc, sizeof g.trusted_desc, "%s", trusted_cidr);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sighup;  sigaction(SIGHUP,  &sa, NULL);
    sa.sa_handler = on_sigterm; sigaction(SIGTERM, &sa, NULL);
                                sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = on_sigusr1; sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_IGN;    sigaction(SIGPIPE, &sa, NULL);

    logf_("gate: ready");

    while (!g_quit) {
        struct pollfd fds[2] = {
            { .fd = g.udp_fd,  .events = POLLIN },
            { .fd = g.unix_fd, .events = POLLIN },
        };

        int r = poll(fds, 2, 250);
        if (r < 0 && errno != EINTR) {
            logf_("gate: poll: %s", strerror(errno));
            break;
        }

        if (g_status) {
            g_status = 0;
            write_status(&g, now_ms());
        }

        if (g_reload) {
            g_reload = 0;
            struct bs_allowlist fresh;
            char e[256];
            if (bs_allowlist_load(&fresh, g.allow_path, e, sizeof e)) {
                g.allow = fresh;
                logf_("gate: allowlist reloaded, %zu peer(s)", g.allow.count);

                /* Revocation must take effect now, not at the next reconnect.
                 * Anyone no longer on the list is disconnected immediately. */
                for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
                    struct bs_session *s = &g.session[i];

                    /* A probation session is not on the allowlist BY
                     * DEFINITION — that is what it is for. Sweeping it here
                     * would report an enrolling stranger as a revoked player
                     * and tell the game logic somebody left who never
                     * arrived. It has its own 10-second deadline in tick(). */
                    if (s->used && !s->enrolling
                        && bs_allowlist_find(&g.allow, s->peer_pk) == NULL) {
                        logf_("gate: %s revoked, disconnecting (sid %08x)",
                              s->label, s->sid);
                        send_encrypted(&g, s, BS_PKT_DISCONNECT, NULL, 0);
                        game_notify_leave(&g, s->sid);
                        session_free(s);
                    }
                }
            } else {
                logf_("gate: allowlist reload REFUSED, keeping previous: %s", e);
            }
            hydro_memzero(&fresh, sizeof fresh);

            /* Reloaded on the same signal, because `bsgate-keys invite` arms
             * one by writing the file and then SIGHUPing us — the daemon owns
             * no other channel for it. Kept independent of the allowlist
             * result above: a broken allowlist must not silently strand an
             * invite the operator has already sent out. */
            struct bs_invite iv;
            if (bs_invite_load(&iv, g.invite_path, e, sizeof e)) {
                g.invite = iv;
                if (bs_invite_valid(&g.invite, (int64_t)time(NULL))) {
                    logf_("gate: invite armed for '%s', %lld second(s) left",
                          g.invite.label,
                          (long long)g.invite.expires_unix - (long long)time(NULL));
                } else {
                    logf_("gate: no invite armed");
                }
            } else {
                logf_("gate: invite reload REFUSED, keeping previous: %s", e);
            }
            hydro_memzero(&iv, sizeof iv);
        }

        if (r > 0) {
            if (fds[0].revents & POLLIN) handle_udp(&g);
            if (fds[1].revents & POLLIN) handle_game(&g);
        }

        tick(&g, now_ms());
    }

    logf_("gate: shutting down");
    for (unsigned i = 0; i < BS_MAX_SESSIONS; i++) {
        if (g.session[i].used) {
            send_encrypted(&g, &g.session[i], BS_PKT_DISCONNECT, NULL, 0);
        }
    }
    unlink(gate_path);
    close(g.udp_fd);
    close(g.unix_fd);
    hydro_memzero(&g, sizeof g);
    return 0;
}
