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
 * STILL DUPLICATED, OUTSIDE THIS REPO: the Blocksmith client tree carries ONE
 * further copy of these same four values —
 *
 *   source/net/hosttest/bsnet_transport_hosttest.c   (anonymous enum)
 *
 * It is a host-side harness that speaks this exact IPC framing to a real
 * bsgate/bsgame pair, so it is bound by this contract as tightly as the four
 * above are. It is not changed here because it belongs to the other repo, and
 * source/net/hosttest/ is off limits there without its owner's say-so. It should
 * include this header the same way once someone owns that edit.
 *
 * The client's other copy — source/net/interop_test.c's own enum bs_game_msg,
 * which was the second entry in this list — is gone. That file now includes this
 * header, spelled "proto/bs_gamelink.h" and reached by the same
 * -I deps/blocksmith-server already in tools/run_host_tests.sh's interop_test
 * stanza, so it needed no build change either. Proved load-bearing by moving
 * this header aside, at which point that stanza fails with `fatal error:
 * proto/bs_gamelink.h: No such file or directory`; restored, the suite runs
 * green at its pinned `PASS: 66 checks, 0 failed` — 56 when this paragraph was
 * written on 2026-08-25; v1.8.3 Phase 4 added scenario 9 (BS_APP_WORLD_GEN
 * across the real process boundary), ten checks. This sentence is a second copy
 * of INTEROP_TEST_EXPECTED_CHECKS that nothing enforces, so it has to be moved
 * by hand every time that pin moves.
 *
 * So six copies are now two, not three, and the one that remains is a scope
 * boundary rather than an oversight.
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
