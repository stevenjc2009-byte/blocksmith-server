/* bs_proto.h — Blocksmith secure transport wire format.
 *
 * Shared verbatim between the 3DS client and the Linux gateway. Nothing in
 * here may depend on either platform: no libctru, no POSIX, no allocation.
 *
 * The link is libhydrogen Noise XX (mutual auth, forward secret) wrapped in a
 * stateless cookie exchange so the server allocates nothing for an unproven
 * source address.
 *
 *   client                                   server
 *     |------------- HELLO (64 B, padded) ----->|   no state allocated
 *     |<------------ COOKIE (40 B) -------------|   stateless MAC over addr
 *     |------------- KX1 + cookie ------------->|   cookie checked, then state
 *     |<------------ KX2 + session id ----------|
 *     |------------- KX3 ---------------------->|   client static key learned
 *     |                                          |   -> allowlist check here
 *     |<===========  DATA (AEAD both ways) ====>|
 *
 * Amplification: COOKIE (40 B) is smaller than HELLO (64 B), so an attacker
 * spoofing a victim's source address gets a net *reduction* in bytes. Every
 * later packet only flows to an address that proved it received the cookie.
 *
 * CLIENT ORDERING REQUIREMENT — the cookie is a MAC over
 * (source ip, source port, nonce), and the server has no memory of what it
 * issued, so it must be able to recompute that nonce from KX1 alone. It uses
 * the first BS_NONCE_BYTES of Noise packet1 (the client's ephemeral public
 * key). The client must therefore:
 *
 *   1. call hydro_kx_xx_1() FIRST, producing packet1
 *   2. send HELLO carrying packet1[0 .. BS_NONCE_BYTES-1] as the nonce
 *   3. send that same packet1 in KX1 alongside the returned cookie
 *
 * Generating a fresh ephemeral between HELLO and KX1 invalidates the cookie
 * and the handshake is silently dropped.
 */

#ifndef BS_PROTO_H
#define BS_PROTO_H

#include <stdint.h>
#include <string.h>

/* ---- sizes borrowed from libhydrogen -----------------------------------
 * Duplicated as literals so this header stays dependency-free for the 3DS
 * build. bsgate.c static-asserts every one of these against the real
 * libhydrogen constants, so a library bump that changes a size fails the
 * server build instead of silently desynchronising the wire format. */
#define BS_KX_PUBLICKEYBYTES   32
#define BS_KX_PACKET1BYTES     48
#define BS_KX_PACKET2BYTES     96
#define BS_KX_PACKET3BYTES     64
#define BS_AEAD_HEADERBYTES    36

/* ---- framing ----------------------------------------------------------- */

#define BS_PROTO_VERSION  1u

/* Bumped only for incompatible wire changes. The gateway refuses any other
 * value before touching crypto, so an old CIA gets a clean drop rather than a
 * confusing handshake failure. */

enum bs_pkt_type {
    BS_PKT_HELLO      = 0x01, /* C->S  probe, carries client nonce           */
    BS_PKT_COOKIE     = 0x02, /* S->C  stateless address proof               */
    BS_PKT_KX1        = 0x03, /* C->S  cookie + Noise XX message 1           */
    BS_PKT_KX2        = 0x04, /* S->C  session id + Noise XX message 2       */
    BS_PKT_KX3        = 0x05, /* C->S  session id + Noise XX message 3       */
    BS_PKT_DATA       = 0x06, /* both  AEAD payload                          */
    BS_PKT_DISCONNECT = 0x07  /* both  AEAD, empty payload                   */
};

#define BS_HDR_BYTES        4u   /* type, version, 2 reserved (must be zero) */
#define BS_NONCE_BYTES     32u
#define BS_COOKIE_BYTES    32u
#define BS_SID_BYTES        4u
#define BS_MSGID_BYTES      8u

/* HELLO is padded so the COOKIE reply can never be larger than the request. */
#define BS_HELLO_BYTES     (BS_HDR_BYTES + BS_NONCE_BYTES + 28u)          /* 64 */
#define BS_COOKIE_PKT_BYTES (BS_HDR_BYTES + BS_COOKIE_BYTES + 4u)         /* 40 */
#define BS_KX1_BYTES       (BS_HDR_BYTES + BS_COOKIE_BYTES + BS_KX_PACKET1BYTES) /* 84 */
#define BS_KX2_BYTES       (BS_HDR_BYTES + BS_SID_BYTES + BS_KX_PACKET2BYTES)    /* 104 */
#define BS_KX3_BYTES       (BS_HDR_BYTES + BS_SID_BYTES + BS_KX_PACKET3BYTES)    /* 72 */

#define BS_DATA_OVERHEAD   (BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES + BS_AEAD_HEADERBYTES)

/* Largest plaintext the gateway will carry. Chosen to keep every DATA packet
 * inside a 1280-byte IPv6-safe MTU after the WireGuard relay's own 60-byte
 * overhead, because a fragmented UDP datagram on 3DS Wi-Fi is a dropped one. */
#define BS_MAX_PAYLOAD     1024u
#define BS_MAX_PACKET      (BS_DATA_OVERHEAD + BS_MAX_PAYLOAD)

/* AEAD context strings. libhydrogen requires exactly 8 bytes, no terminator
 * semantics. Separate contexts per direction so a captured server->client
 * packet can never be replayed back at the server. */
#define BS_CTX_S2C  "bsgateS2"
#define BS_CTX_C2S  "bsgateC2"

/* Replay window, in packets, applied per session per direction. */
#define BS_REPLAY_WINDOW   1024u

/* ---- byte order --------------------------------------------------------
 * Everything multi-byte on the wire is little-endian, matching the ARM11 and
 * x86 native order, so neither end byte-swaps in the hot path. Written out
 * explicitly rather than memcpy'd so the format does not depend on either
 * compiler's struct padding. */

static inline void bs_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v      ); p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t bs_get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void bs_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
}

static inline uint16_t bs_get_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static inline void bs_put_u64(uint8_t *p, uint64_t v)
{
    bs_put_u32(p,     (uint32_t)(v & 0xffffffffu));
    bs_put_u32(p + 4, (uint32_t)(v >> 32));
}

static inline uint64_t bs_get_u64(const uint8_t *p)
{
    return (uint64_t)bs_get_u32(p) | ((uint64_t)bs_get_u32(p + 4) << 32);
}

static inline void bs_put_hdr(uint8_t *p, uint8_t type)
{
    p[0] = type; p[1] = (uint8_t)BS_PROTO_VERSION; p[2] = 0; p[3] = 0;
}

static inline void bs_put_i32(uint8_t *p, int32_t v)
{
    bs_put_u32(p, (uint32_t)v);
}

static inline int32_t bs_get_i32(const uint8_t *p)
{
    return (int32_t)bs_get_u32(p);
}

/* Both bsgame and the 3DS client are little-endian ARM11/x86 (see the byte
 * order note above), so a float is written as its raw IEEE-754 bytes rather
 * than converted through anything lossy. memcpy, not a union or a cast, so
 * this has no strict-aliasing undefined behaviour under -O2. */
_Static_assert(sizeof(float) == 4, "expects IEEE-754 binary32 float");

static inline void bs_put_f32(uint8_t *p, float v)
{
    uint32_t u;
    memcpy(&u, &v, sizeof u);
    bs_put_u32(p, u);
}

static inline float bs_get_f32(const uint8_t *p)
{
    uint32_t u = bs_get_u32(p);
    float v;
    memcpy(&v, &u, sizeof v);
    return v;
}

/* ---- game application protocol ------------------------------------------
 * Carried as the plaintext payload of BS_PKT_DATA (client<->gateway) and
 * BS_GAME_DATA (gateway<->bsgame). bsgate never looks inside these bytes —
 * only the 3DS client and bsgame (server/game/) do. Byte 0 of the payload is
 * the application message type; everything after it uses the same
 * little-endian, hand-written-not-memcpy'd convention as the header above,
 * for the same struct-padding reason.
 *
 * Added here rather than invented ad hoc in bsgame because this boundary —
 * gateway forwards opaque bytes, only the two endpoints agree on their
 * shape — is exactly what bs_proto.h exists to pin down.
 */

enum bs_app_msg {
    BS_APP_BLOCK_EDIT = 0x01, /* C->S: requested edit. S->C: an accepted one,
                                * same layout, broadcast or replayed from
                                * BS_APP_WORLD_SYNC.                          */
    BS_APP_POS_UPDATE = 0x02, /* C->S: the sender's own pose.
                                * S->C: another player's sid + pose.          */
    BS_APP_WORLD_SYNC = 0x03  /* S->C only: a batch of existing block diffs, */
};                             /* sent right after JOIN so a new player sees  */
                                /* the world as everyone else already edited it. */

#define BS_APP_HDR_BYTES 1u

/* x, y, z (world block coordinates, signed) + the new block id. Client->
 * server carries a request; server->client carries something already
 * accepted, so one parser handles both directions and BS_APP_WORLD_SYNC's
 * entries reuse the same per-entry shape below. */
#define BS_BLOCK_EDIT_BYTES (BS_APP_HDR_BYTES + 4u + 4u + 4u + 1u)   /* 14 */

/* POS_UPDATE, client->server: this player's own position (x, y, z, in
 * blocks) and facing (yaw, pitch), five float32. */
#define BS_POS_UPDATE_C_BYTES (BS_APP_HDR_BYTES + 4u * 5u)           /* 21 */

/* POS_UPDATE, server->client: whose pose this is, then the same five
 * float32 — a plain sid prefix in front of the client->server shape. */
#define BS_POS_UPDATE_S_BYTES (BS_APP_HDR_BYTES + 4u + 4u * 5u)      /* 25 */

/* WORLD_SYNC entry: x, y, z, block id — BS_BLOCK_EDIT_BYTES without the
 * per-message type byte, since one WORLD_SYNC packet carries many. */
#define BS_SYNC_ENTRY_BYTES 13u

/* Capped so the largest batch still fits inside BS_MAX_PAYLOAD (1024):
 * 1 (type) + 2 (count) + 64*13 = 835 bytes, comfortably clear. */
#define BS_SYNC_MAX_ENTRIES 64u

#define BS_WORLD_SYNC_BYTES(n) \
    (BS_APP_HDR_BYTES + 2u + (uint32_t)(n) * BS_SYNC_ENTRY_BYTES)

#endif /* BS_PROTO_H */
