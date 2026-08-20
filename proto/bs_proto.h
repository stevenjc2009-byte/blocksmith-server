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
    BS_PKT_DISCONNECT = 0x07, /* both  AEAD, empty payload                   */
    BS_PKT_ENROL      = 0x08, /* C->S  AEAD, one-time invite code as text    */
    BS_PKT_ENROL_OK   = 0x09  /* S->C  AEAD, empty; you are on the allowlist */
};

/* Enrolment exists so a human never has to move a 64-hex key between a 3DS and
 * the server. The operator runs `bsgate-keys invite <label>`, which arms a
 * single short-lived one-time code; the friend types that code into the console
 * once, and the console's own static key is written into the allowlist under
 * <label>. From then on they are an ordinary allowlisted peer and the code is
 * gone — it is a one-time door, not a password.
 *
 * The code rides inside an AEAD packet on a session whose Noise XX handshake
 * has ALREADY completed, so it is never on the wire in the clear and the peer
 * has already had to hold the network PSK to get this far. With no invite
 * armed, an unlisted key is dropped exactly as it always was: enrolment adds no
 * reachable code path at all unless the operator has just armed one. */
#define BS_INVITE_CODE_MAX  32u

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

/* Largest plaintext the gateway will carry. Sized so every DATA packet stays
 * inside a 1280-byte IPv6-safe MTU on both legs of the path, because a
 * fragmented UDP datagram on 3DS Wi-Fi is a dropped one:
 *
 *   BS_MAX_PACKET                        = 4 + 4 + 8 + 36 + 1024 = 1076
 *   3DS -> playit edge                   = 1076
 *   playit edge -> agent, + PROXY v2 v4  = 1076 + 28             = 1104
 *
 * (An earlier revision of this comment justified the number against a
 * WireGuard relay's 60-byte overhead. That relay was replaced by the playit
 * tunnel — see the README's topology section — and 28 bytes of PROXY protocol
 * v2 is the header that actually rides along now. The bound is looser than it
 * was, so 1024 remains correct; only the reasoning changed.) */
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
    BS_APP_WORLD_SYNC = 0x03, /* S->C only: a batch of existing block diffs,   */
                               /* sent right after JOIN so a new player sees    */
                               /* the world as everyone else already edited it. */
    BS_APP_WORLD_INFO = 0x04, /* S->C only: which world this is — the seed its
                                * terrain generates from. Sent once per session,
                                * as the FIRST packet after JOIN, before any
                                * WORLD_SYNC: the diffs in that sync are
                                * coordinates into this seed's terrain and mean
                                * nothing without it.
                                *
                                * This is what makes the server the owner of the
                                * world rather than a shared notepad. Until it
                                * existed the seed was a constant compiled into
                                * the client (BS_WORLD_SEED, source/main.c), so
                                * every server necessarily had the same terrain
                                * and "which world am I on" was not a question
                                * the protocol could even ask. */

    BS_APP_CHUNK_SUB   = 0x05, /* C->S: the client has loaded column (cx, cz)
                                * and wants the edits belonging to it. The
                                * server answers with one or more CHUNK_DIFFS
                                * for that column, the last flagged
                                * BS_CHUNK_DIFFS_LAST — and it answers even when
                                * the column has no edits at all, so the client
                                * can tell "none" from "still coming" and never
                                * meshes a half-synced column.               */
    BS_APP_CHUNK_DIFFS = 0x06, /* S->C: the edits for one column, in batches. */
    BS_APP_CHUNK_UNSUB = 0x07  /* C->S: the client has dropped column (cx, cz)
                                * and no longer wants edits broadcast for it. */
};

/* Why CHUNK_SUB exists at all, given WORLD_SYNC already replayed everything.
 *
 * WORLD_SYNC ships the entire diff set to every joining client, oldest first.
 * That forces the client's inbox to be as large as the server's whole store,
 * which is what capped the server at BS_DIFF_MAX (diffstore.h) — the 3DS cannot
 * hold millions of edits, so the server was not allowed to keep them either.
 * Scoping delivery to the column the player is actually standing near breaks
 * that coupling: the console holds edits for loaded columns only, and the
 * server's capacity stops being a client-memory question.
 *
 * WORLD_SYNC is kept, and still sent once at JOIN with a count of zero. It is
 * NOT dead weight — see send_world_sync() in game/bsgame.c for the admission
 * guarantee it carries, and note that a client from before this message set
 * exists still receives exactly what it always did.
 *
 * The wire sizes for these three live below, next to WORLD_SYNC's, because they
 * are built out of the same per-entry shape. */

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

/* The client's CHUNK_DIM (source/world/chunk.h:50), restated here because
 * column coordinates are now on the wire and the two ends MUST agree on how a
 * block coordinate maps to a column. It lives in the protocol header for the
 * same reason the message sizes do: it is part of what the endpoints promise
 * each other, not an internal choice either side may revise alone. */
#define BS_CHUNK_DIM 16

/* Block coordinate to column coordinate. An arithmetic right shift, not a
 * division: `/ 16` truncates toward zero, so -1 / 16 == 0 and blocks at x = -1
 * and x = +1 would land in the same column while x = -16 landed in another.
 * `>> 4` floors, which is what tiles correctly across the origin. This matches
 * source/net/blockdiff.c on the client exactly — if one side ever changes, edits
 * near the origin get filed under a column nobody subscribes to and quietly
 * stop arriving. */
static inline int32_t bs_col_of(int32_t block_coord) { return block_coord >> 4; }

/* CHUNK_SUB and CHUNK_UNSUB: the column coordinate, two int32. Columns, not
 * blocks — a column is BS_CHUNK_DIM wide in x and z and spans the full world
 * height, so one subscription covers every chunk stacked above that footprint. */
#define BS_CHUNK_SUB_BYTES   (BS_APP_HDR_BYTES + 4u + 4u)             /* 9 */
#define BS_CHUNK_UNSUB_BYTES BS_CHUNK_SUB_BYTES                       /* 9 */

/* Set on the final CHUNK_DIFFS packet for a column. A column with no edits
 * still gets one packet, with count 0 and this flag set — the client needs to
 * hear "that column is empty" as distinctly as it hears "here are its edits". */
#define BS_CHUNK_DIFFS_LAST  0x01u

/* CHUNK_DIFFS: cx, cz, flags, count, then `count` entries of the same shape
 * WORLD_SYNC uses. The column coordinate is repeated in every packet rather
 * than implied by the outstanding request, because UDP gives no ordering
 * guarantee between two columns subscribed in the same tick — without it a
 * client that asked for two columns at once cannot tell whose diffs arrived. */
#define BS_CHUNK_DIFFS_HDR_BYTES (BS_APP_HDR_BYTES + 4u + 4u + 1u + 2u)  /* 12 */
#define BS_CHUNK_DIFFS_BYTES(n) \
    (BS_CHUNK_DIFFS_HDR_BYTES + (uint32_t)(n) * BS_SYNC_ENTRY_BYTES)

/* Same reasoning as BS_SYNC_MAX_ENTRIES, one packet's worth: 12 + 64*13 = 844,
 * inside BS_MAX_PAYLOAD (1024) with the same margin WORLD_SYNC keeps. */
#define BS_CHUNK_DIFFS_MAX_ENTRIES BS_SYNC_MAX_ENTRIES

/* WORLD_INFO: the world's terrain seed, one uint32. Deliberately just the seed
 * and not a struct with room to grow — a client that meets a longer WORLD_INFO
 * from a newer server must be able to reject it on length alone rather than
 * silently half-parse it, so widening this later means a new message type, not
 * a bigger one. */
#define BS_WORLD_INFO_BYTES (BS_APP_HDR_BYTES + 4u)                   /* 5 */

#endif /* BS_PROTO_H */
