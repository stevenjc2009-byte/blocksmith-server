/* bs_gamelink.h — the bsgate <-> bsgame local IPC framing.
 *
 * NOT part of bs_proto.h's wire contract, and deliberately a separate file from
 * it. bs_proto.h is shared verbatim with the 3DS client and is PINNED by the
 * client's Makefile (PROTO_COMMIT, enforced by its check-proto-drift target),
 * which compares proto/bs_proto.h and nothing else. Nothing in this file is
 * covered by that pin and nothing in it ever travels over the network: this is
 * one datagram kind byte on the local AF_UNIX socket between two processes on
 * the same box.
 *
 * It lives in a header anyway, because it is still a CONTRACT BETWEEN TWO
 * BINARIES, and a contract written down once cannot drift. It previously was
 * not written down once. The same four enumerators were hand-copied into
 *
 *   game/bsgame.c        game/bsgame_test.c
 *   gateway/bsgate.c     gateway/bsgate_test.c
 *
 * with nothing whatsoever holding them equal — the only wire-ish enum in either
 * tree duplicated that way. The cost was already visible before any value had
 * drifted: bsgame.c's own cross-reference comment pointed at
 * "server/gateway/bsgate.c:293-298" while the definition it names had moved to
 * bsgate.c:334-339, so the single pointer between the copies was already stale.
 * The argument for duplicating was that this is "not part of the wire protocol
 * proper" — true, and beside the point. A value drifting here would not have
 * been a compile error in any of the four: it would have been the gate sending
 * one kind byte for what the game reads as another, at runtime, in production,
 * with no diagnostic anywhere.
 *
 * Both game/ and gateway/ reach this by relative path exactly as they already
 * reach bs_proto.h, so no Makefile change is needed for either binary.
 *
 * STILL DUPLICATED, OUTSIDE THIS REPO: the Blocksmith client tree carries two
 * further copies of these same four values —
 *
 *   source/net/interop_test.c                    (enum bs_game_msg)
 *   source/net/hosttest/bsnet_transport_hosttest.c   (anonymous enum)
 *
 * Both are host-side harnesses that speak this exact IPC framing to a real
 * bsgate/bsgame pair, so they are bound by this contract as tightly as the four
 * above are. They are not changed here because they belong to the other repo;
 * they should include this header the same way once someone owns that edit.
 * Until they do, six copies became three, not one.
 */

#ifndef BS_GAMELINK_H
#define BS_GAMELINK_H

/* Gate<->game framing: the first byte of every datagram on the game socket.
 * Every kind is followed by a 4-byte session id; see BS_GAME_ENVELOPE_BYTES in
 * bsgame.c for the envelope size that implies. */
enum bs_game_msg {
    BS_GAME_JOIN  = 1,   /* gate -> game: sid(4) + pubkey(32) + label(32) */
    BS_GAME_DATA  = 2,   /* both ways:    sid(4) + payload                */
    BS_GAME_LEAVE = 3,   /* gate -> game: sid(4)                          */
    BS_GAME_KICK  = 4    /* game -> gate: sid(4)                          */
};

#endif /* BS_GAMELINK_H */
