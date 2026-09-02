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
    BS_APP_CHUNK_UNSUB = 0x07, /* C->S: the client has dropped column (cx, cz)
                                * and no longer wants edits broadcast for it. */

    BS_APP_INV_STATE  = 0x08, /* S->C only: the whole of this player's
                               * inventory, authoritative. Sent unprompted once
                               * at JOIN and again after anything that could
                               * have changed it. See the note below on why the
                               * server speaks first.                         */
    BS_APP_INV_ACTION = 0x09, /* C->S: one requested inventory or crafting
                               * operation. Never sent until an INV_STATE has
                               * arrived — that is the capability probe.      */

    BS_APP_PLAYER_STATE  = 0x0A, /* S->C only: the whole of this player's saved
                                  * state beyond the inventory — pose, armour,
                                  * XP and meters. Sent unprompted once, right
                                  * after JOIN's INV_STATE, for the same reason
                                  * INV_STATE is volunteered (see its comment
                                  * and the sizes section below).               */
    BS_APP_PLAYER_REPORT = 0x0B, /* C->S: the client's report of its own armour,
                                  * XP and meters. Never sent until a
                                  * PLAYER_STATE has arrived — same capability
                                  * probe pattern as INV_ACTION. A server that
                                  * never speaks PLAYER_STATE therefore never
                                  * hears PLAYER_REPORT, which is what makes
                                  * this pair deployment-order-safe like the
                                  * inventory one above.                        */

    /* v1.6.0 Phase A: the master block registry over the wire.
     *
     * REGISTRY_INFO is volunteered by the server right after WORLD_INFO at
     * join, before INV_STATE — the join order (world_info -> registry_info ->
     * inv_state -> player_state) is load-bearing: registry definitions must be
     * applied before any server column can generate or mesh, and the client's
     * FETCH is only ever sent after an INFO has been seen, which keeps the
     * capability-probe discipline (an old server sends no INFO, so a new
     * client never sends FETCH at it and is never kicked).
     *
     * INFO carries the registry layout revision, the defined-row count and a
     * CRC-16/CCITT-FALSE over the canonical table stream. A client whose
     * compiled-in table hashes identically is done — the common case costs
     * zero extra traffic. On mismatch it asks for the dynamic rows only:
     * core rows are compiled into every binary of the same protocol era. */
    BS_APP_REGISTRY_INFO  = 0x0C, /* S->C only: {rev u8, count u8, crc16 u16 LE}. */
    BS_APP_REGISTRY_FETCH = 0x0D, /* C->S: {first_index u8}. Only sent after an
                                   * INFO has arrived; asks for dynamic defs
                                   * from first_index up, in DEFS batches.       */
    BS_APP_REGISTRY_DEFS  = 0x0E, /* S->C only: {first u8, n u8, last u8,
                                   * n x 28B records}. last is 1 on the final
                                   * batch of a fetch. The 28-byte record is
                                   * {id, name[16], tex[6], flags, luminance,
                                   * hardness, variant_of, fluid_class} — all
                                   * single bytes, so no endianness inside it.   */

    /* v1.8.3 Phase 4. WHICH GENERATOR shaped the world that WORLD_INFO's seed
     * feeds, as opposed to which world it is. Terrain is never transmitted —
     * every client generates the landscape for itself out of the seed — so two
     * clients running different generators over the same seed are standing in
     * two different worlds: one player's floor is another player's sky, and
     * every block edit lands in the wrong hillside. Until this message existed
     * the client had no way to ask and covered for it by always generating its
     * oldest generator (see the client's world/genversion.h,
     * genVersionForSession, whose comment names this message as its own exit).
     *
     * S->C ONLY, and that is load-bearing rather than incidental. A new C->S
     * type would meet handle_app_payload()'s `default: send_kick()` on every
     * server older than this one, which is why a client-to-server message can
     * only ever be introduced by shipping the server first — v1.2.7 learned
     * that the hard way. A new S->C type costs an old client nothing: its own
     * dispatch ends in a silent `default: break;`. The whole decision this
     * message feeds — enter the world, or refuse it — is the client's, and this
     * side only announces, exactly as it does for BS_APP_REGISTRY_INFO. Do NOT
     * add an acknowledgement or a capability report; that would turn a
     * ship-order preference into kick-or-be-kicked.
     *
     * Phase 4 declares 1 (the client's GEN_VERSION_LEGACY) and nothing else.
     * Declaring 2 (DENSITY) is a SEPARATE and larger change and must not be
     * done by editing world_gen.txt: the density generator places water, and
     * the client keeps water LEVEL in a local sparse side map that is on no
     * wire, in no region file and in no chunk encoding. Two clients that agree
     * on "2" would generate the same lakes and then simulate their own flow
     * out of them, with nothing reconciling the two and — because they agree —
     * no refusal to fire. Water has to go on the wire first. */
    BS_APP_WORLD_GEN      = 0x0F  /* S->C only: {gen_version u16 LE}.            */
};

/* Why INV_STATE is sent unprompted, and why the client must never open with
 * INV_ACTION.
 *
 * The two ends do not treat an unknown message type the same way, and they
 * cannot. bsgame kicks it (handle_app_payload's default case, game/bsgame.c):
 * a byte it does not understand arriving from an authenticated-but-untrusted
 * client is exactly the case that boundary exists to refuse. The client
 * ignores it (net/networld.c's `default: break;`): a server is trusted, and a
 * console that dropped its session every time a newer server mentioned a
 * feature it had not heard of would be unusable the moment the two versions
 * drifted.
 *
 * That asymmetry has a consequence worth stating once, in the header both ends
 * read: a new CLIENT->SERVER message can only ever be introduced by shipping
 * the server first. v1.2.7 learned that the hard way — it sends CHUNK_SUB on
 * its first loaded column, so it is kicked outright by any server older than
 * v1.3.0, and the release had to be sequenced by hand.
 *
 * This message pair is built so that never happens again. The server volunteers
 * INV_STATE; a client that has not received one keeps its inventory locally,
 * exactly as it did before this feature existed, and never sends INV_ACTION.
 * So an old server (which sends no INV_STATE) leaves a new client working, and
 * an old client simply ignores an INV_STATE it was not expecting. Both
 * directions are safe and the deployment order stops mattering. The cost is one
 * unsolicited 50-byte packet per join to clients that will discard it, which is
 * cheaper than another hand-sequenced release. */

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

/* log2(BS_CHUNK_DIM), for the shift below. Named rather than left as a bare `4`
 * in bs_col_of(): the two are one constant written two ways, and nothing tied
 * them together — widening BS_CHUNK_DIM to 32 and leaving the shift at 4 would
 * halve every column coordinate with no diagnostic at all, the same silent
 * class of bug the registry record size had. game/validate.c asserts
 * (1u << BS_CHUNK_DIM_SHIFT) == BS_CHUNK_DIM so the pair cannot drift apart. */
#define BS_CHUNK_DIM_SHIFT 4

/* Block coordinate to column coordinate. An arithmetic right shift, not a
 * division: `/ 16` truncates toward zero, so -1 / 16 == 0 and blocks at x = -1
 * and x = +1 would land in the same column while x = -16 landed in another.
 * `>> 4` floors, which is what tiles correctly across the origin. This matches
 * source/net/blockdiff.c on the client exactly — if one side ever changes, edits
 * near the origin get filed under a column nobody subscribes to and quietly
 * stop arriving. */
static inline int32_t bs_col_of(int32_t block_coord)
{
    return block_coord >> BS_CHUNK_DIM_SHIFT;
}

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

/* WORLD_GEN: the generator version, one uint16 little-endian, and nothing else.
 *
 * uint16 rather than uint32 because 16 bits is the width the number already has
 * where it is durable: the client writes its world's generator into a 12-byte
 * genver.bin sidecar as two bytes (its world/genversion.c). A 32-bit wire field
 * would let a server declare a version no world file could ever hold, giving one
 * number two widths and a range only half of which can be stored.
 *
 * No reserved bytes and no room to grow, for exactly the reason stated on
 * BS_WORLD_INFO_BYTES above and enforced the same way — the client rejects on
 * strict length equality, and a strict-equality reader cannot tell "reserved,
 * ignore" from "a field I have never heard of". Widening this later means a new
 * message type (0x10), not a bigger one. */
#define BS_WORLD_GEN_BYTES (BS_APP_HDR_BYTES + 2u)                    /* 3 */

/* ---- inventory ----------------------------------------------------------
 *
 * The client's own inventory shape (source/world/inventory.h), restated here
 * for the same reason BS_CHUNK_DIM is: the moment a slot index travels on the
 * wire, how many slots there are stops being either end's private choice.
 * validate.h static-asserts these against the real headers wherever the client
 * tree is present, the way it does for BS_BLOCK_COUNT — and that guard is only
 * worth anything because the path bug that silently disabled it was fixed
 * first (see game/Makefile's WORLD). */
#define BS_INV_SLOT_COUNT   24u   /* mirrors INV_SLOT_COUNT   */
#define BS_INV_HOTBAR_SLOTS  8u   /* mirrors INV_HOTBAR_SLOTS */
#define BS_INV_STACK_MAX    99u   /* mirrors INV_STACK_MAX    */
#define BS_RECIPE_COUNT      4u   /* mirrors RECIPE_COUNT (world/crafting.h) */

/* The operations a client may ask for. The first five are deliberately the
 * same primitives world/inventory.h and world/crafting.h already expose, one
 * to one, rather than a higher-level "the player dragged from here to there":
 * the server has to run the exact merge/refuse rules the client's UI was
 * written against, and the only way to be sure of that is to call the same
 * functions with the same arguments. Anything the UI composes out of these
 * stays composed on the UI side, where it already is. These five are also
 * where this feature's server verification actually lives: MOVE/SWAP/SPLIT
 * can only rearrange units the inventory already holds (no duplication),
 * SELECT only changes which slot is in hand, and CRAFT can only succeed if
 * craftMake() finds the real ingredient count already present — a client
 * cannot conjure planks it never spent wood for.
 *
 * BS_INV_OP_PICKUP and BS_INV_OP_CONSUME, appended below, are a different
 * kind of op: the client's *report* of what a block break or place just did
 * to its own held items, taken on trust because the server has nothing to
 * check it against — see their own comment for why that is permanent, not a
 * gap. Read BS_INV_STATE_BYTES's own comment with that in mind: it is an
 * authoritative record of what this server's inventory logic has done with
 * what it was told, not proof that what it was told was true.
 *
 * Appended-only, like the block ids. An op byte the server does not recognise
 * is refused (and answered with an unchanged INV_STATE), not kicked — unlike an
 * unknown message *type*, an unknown op inside a known message is a bad
 * argument, and the answer to a bad argument is "no, and here is the truth". */
enum bs_inv_op {
    BS_INV_OP_MOVE    = 0x00, /* a = src slot, b = dst slot, c = units       */
    BS_INV_OP_SWAP    = 0x01, /* a = slot, b = slot, c unused                */
    BS_INV_OP_SPLIT   = 0x02, /* a = slot, b = dst slot (must be empty)      */
    BS_INV_OP_SELECT  = 0x03, /* a = hotbar slot to put in hand              */
    BS_INV_OP_CRAFT   = 0x04, /* a = recipe index, < BS_RECIPE_COUNT         */

    /* Appended, not inserted, for the same reason block ids are append-only
     * (world/block.h) — an op byte is on the wire and in front of clients
     * already running v1.x the day this ships.
     *
     * PICKUP and CONSUME are reported by the client, not verified by the
     * server, and that is a deliberate, permanent property of this feature —
     * not a gap awaiting a later patch. bsgame has no terrain generator (see
     * bsgame.c's header comment: "terrain is deterministic... this process
     * only ever ships the *diffs* players have made") and never will; a
     * server-side check of "did you actually just mine wood at (x,y,z)" would
     * require regenerating this world's terrain to know what stood there
     * before the first diff, which is exactly the machinery that was never
     * built and is not going to be. So the server cannot confirm a pickup or
     * a consume against anything it owns, full stop — see the longer version
     * of this reasoning at the BS_INV_OP_PICKUP/BS_INV_OP_CONSUME case in
     * bsgame.c's handle_inv_action(), which is where it actually matters. */
    BS_INV_OP_PICKUP  = 0x05, /* a = item id (inventoryCanHold(a), the block
                                * registry -- game/validate.h), b = count
                                * (1..BS_INV_STACK_MAX), c unused. The client
                                * reports what a block break just put in its
                                * hand. v1.9.1: the guard used to be
                                * `< BS_BLOCK_COUNT`; see validate.h.          */
    BS_INV_OP_CONSUME = 0x06, /* a = item id (inventoryCanHold(a), the block
                                * registry -- game/validate.h), b = count
                                * (1..BS_INV_STACK_MAX), c unused. The client
                                * reports what a placement just took out of
                                * it. v1.9.1: same guard as PICKUP above.      */
    BS_INV_OP_COUNT
};

/* INV_ACTION: the op, then three generic uint8 parameters. Three bytes rather
 * than a per-op layout because every parameter any of these five operations
 * takes is a slot index (0..23), a hotbar index (0..7), a unit count
 * (0..99) or a recipe index (0..3) — all of which fit a byte with room to
 * spare, and none of which is a coordinate. A fixed size means the parser
 * rejects on length before it looks at the op, the same one-line admission
 * check every other message here gets. Unused parameters MUST be sent as 0 so
 * that a future op cannot find garbage in them. */
#define BS_INV_ACTION_BYTES (BS_APP_HDR_BYTES + 1u + 3u)              /* 5 */

/* INV_STATE: the selected hotbar slot, then every slot as (item, count).
 *
 * The whole inventory every time, not a delta. 50 bytes is smaller than the
 * bookkeeping a reliable delta would need on an unordered, unacknowledged
 * transport: a dropped delta leaves the console showing an inventory that no
 * longer exists and nothing to notice it by, whereas a dropped snapshot is
 * corrected by the next one. The same argument WORLD_INFO's comment makes
 * about growing this later applies — a longer INV_STATE from a newer server
 * must be rejectable on length alone, so widening it means a new message type.
 *
 * count is 0 if and only if item is 0 (BLOCK_AIR / ITEM_NONE); the client is
 * entitled to treat any other pairing as a malformed packet and drop it. */
#define BS_INV_STATE_BYTES \
    (BS_APP_HDR_BYTES + 1u + BS_INV_SLOT_COUNT * 2u)                  /* 50 */

/* ---- player state -------------------------------------------------------
 *
 * PLAYER_STATE/PLAYER_REPORT carry everything worth persisting about a
 * player beyond the inventory: where they stood (pose), what they were
 * wearing (armour) and their meters (XP level/progress, health, hunger).
 *
 * The same deployment-order argument bs_proto.h makes for INV_STATE/
 * INV_ACTION applies here unchanged, and for the same reason: bsgame kicks
 * an unknown C->S message type while the client merely ignores an unknown
 * S->C one, so a new client->server message must be gated on first seeing
 * its server->client counterpart. The server volunteers PLAYER_STATE at
 * JOIN — always, even for a brand-new player with nothing saved (a
 * well-formed all-zero packet with no valid-state flags, so "fresh spawn"
 * is distinguishable from a lost packet); a client that has not received
 * one never sends PLAYER_REPORT; an old client ignores PLAYER_STATE
 * entirely. Old server/new client and new server/old client are both safe,
 * exactly as for the inventory pair.
 *
 * The server does NOT answer a PLAYER_REPORT — it is fire-and-forget, like
 * every other C->S message on this unordered transport, and self-corrects
 * at the next join's PLAYER_STATE snapshot rather than needing an ack.
 * A peer that never sends reports is tolerated without ceremony: the
 * server just keeps whatever it last had on disk.
 *
 * Widening either message later means a NEW type, not a bigger one — same
 * rule as WORLD_INFO above: a client that meets a longer state message
 * from a newer peer must be able to reject it on length alone rather than
 * silently half-parse it.
 */

/* Flags carried in PLAYER_STATE's second byte. Zero means "nothing saved
 * for this player yet" — the fresh-spawn marker. */
#define BS_PLAYER_STATE_FLAG_POSE 0x01u   /* pose fields are meaningful     */
#define BS_PLAYER_STATE_FLAG_EXT  0x02u   /* armour/meters are meaningful   */

/* Armour slot order everywhere below: head, chest, legs, feet. Each slot is
 * an { item id, count } pair, items drawn from the same id space as the
 * inventory's (a block id — see bs_proto.h's inventory section). */
#define BS_ARMOR_SLOTS 4u

/* PLAYER_STATE: flags, then pose (5 x f32), then the armour+meters block.
 *
 *   u8  type (0x0A)
 *   u8  flags                          BS_PLAYER_STATE_FLAG_*
 *   f32 x, y, z, yaw, pitch            (20 bytes)
 *   u8  armor[4][2]                    head/chest/legs/feet, {item, count}
 *   u32 xp_level
 *   f32 xp_progress                    0..1 through the current level
 *   f32 health                         0..20
 *   f32 hunger                         0..20
 */
#define BS_PLAYER_STATE_BYTES \
    (BS_APP_HDR_BYTES + 1u + 4u * 5u + BS_ARMOR_SLOTS * 2u \
     + 4u + 4u + 4u + 4u)                                             /* 46 */

/* PLAYER_REPORT: the client's own armour+meters, the exact same block
 * PLAYER_STATE carries after its pose — same field order, same encodings,
 * so one decoder serves both messages.
 *
 *   u8  type (0x0B)
 *   u8  armor[4][2]
 *   u32 xp_level
 *   f32 xp_progress
 *   f32 health
 *   f32 hunger
 *   u8  reserved[5]                    MUST be sent as zero; ignored on receipt
 *
 * The five reserved tail bytes keep this message a fixed 30 bytes as
 * specified, the same way BS_BLOCK_EDIT's disk record reserves trailing
 * zero bytes (game/diffstore.c): room to grow without ever redefining what
 * an existing peer may send, since any future use of them would still have
 * to arrive as a new message type under the widening rule above. A report
 * whose length is not exactly BS_PLAYER_REPORT_BYTES is malformed and is
 * treated like any other known-type wrong-length payload.
 */
#define BS_PLAYER_METERS_BYTES (BS_ARMOR_SLOTS * 2u + 4u + 4u + 4u + 4u)  /* 24 */
#define BS_PLAYER_REPORT_BYTES \
    (BS_APP_HDR_BYTES + BS_PLAYER_METERS_BYTES + 5u)                  /* 30 */

/* REGISTRY_INFO: the whole registry's fingerprint in 5 bytes.
 *
 *   u8  type (0x0C)
 *   u8  rev                              REGISTRY_REV, layout generation
 *   u8  count                            defined rows, air included (<=254)
 *   u16 crc16                            LE; CCITT-FALSE over the canonical
 *                                        table stream (see world/registry.c)
 */
#define BS_APP_REGISTRY_INFO_BYTES (BS_APP_HDR_BYTES + 1u + 1u + 2u)      /* 5 */

/* REGISTRY_FETCH: "send me your dynamic defs from here up".
 *
 *   u8  type (0x0D)
 *   u8  first_index                      always REG_ID_DYN_LO today
 */
#define BS_APP_REGISTRY_FETCH_BYTES (BS_APP_HDR_BYTES + 1u)               /* 2 */

/* One block on the wire: the id byte plus the packed BlockDef behind it.
 *
 * Mirrors REGISTRY_WIRE_RECORD_BYTES (world/registry.h), restated here for the
 * same reason BS_INV_SLOT_COUNT is: the record travels on the wire, so its size
 * stops being either end's private choice. game/validate.c static-asserts the
 * two against each other — unconditionally, because registry.h is VENDORED into
 * game/world/ and is therefore present in the standalone daemon build too.
 *
 * It exists at all because this used to be a bare `28u` written out twice
 * below, and the two sites are not interchangeable: BS_APP_REGISTRY_DEFS_MAX_N
 * sizes the batch, while bsgame.c's handle_registry_fetch() sizes its stack
 * buffer and strides its packing with REGISTRY_WIRE_RECORD_BYTES and then
 * DECLARES the packet's length with BS_APP_REGISTRY_DEFS_BYTES(). Add one field
 * to BlockDef and the record goes 28 -> 29, and the literal does not move:
 * measured on the real headers, 36 records then pack 1048 bytes into a buffer
 * whose declared wire length is 1012 — 36 bytes of registry short on every
 * batch — while MAX_N stays 36 when only 35 fit and 1048 overruns
 * BS_MAX_PAYLOAD (1024). The compile was clean and silent: gcc rc=0, no
 * warning. Mismatched framing, not merely a wrong count.
 */
#define BS_REGISTRY_WIRE_RECORD_BYTES 28u  /* mirrors REGISTRY_WIRE_RECORD_BYTES */

/* REGISTRY_DEFS: one batch of consecutive dynamic defs.
 *
 *   u8  type (0x0E)
 *   u8  first                            id of the first record
 *   u8  n                                record count, 1..BS_APP_REGISTRY_DEFS_MAX_N
 *   u8  last                             1 on the final batch of a fetch
 *   ..  records                         n x BS_REGISTRY_WIRE_RECORD_BYTES,
 *                                        id-ascending
 *
 * The batch capacity is what fits one BS_MAX_PAYLOAD packet:
 * (1024 - 4) / 28 = 36 records.
 */
#define BS_APP_REGISTRY_DEFS_MAX_N \
    ((BS_MAX_PAYLOAD - BS_APP_HDR_BYTES - 3u) / BS_REGISTRY_WIRE_RECORD_BYTES)  /* 36 */
#define BS_APP_REGISTRY_DEFS_BYTES(n) \
    (BS_APP_HDR_BYTES + 3u + (uint32_t)(n) * BS_REGISTRY_WIRE_RECORD_BYTES)

#endif /* BS_PROTO_H */
