# Changelog

All notable changes to the Blocksmith server. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/). Earlier releases were tracked only as annotated
git tags; this file starts recording forward from v1.9.10.

## [1.9.10] - 2026-09-07

Pairs with client v1.9.0. The chest block itself and its registry row shipped in v1.9.9; this
release carries the wire side — the three opcodes a v1.9.0 client actually needs to sync a
chest's contents, the capability bitfield that announces them, and the server-side store the
opcodes read and write.

### Added

- **Three new opcodes.** `BS_APP_SERVER_CAPS` (`0x11`, S→C, sent once at the end of the join
  burst by `send_server_caps()`, `game/bsgame.c:999-1005`), `BS_APP_CHEST_STATE` (`0x12`, S→C,
  one whole chest's contents, broadcast to every connected player on a transfer by
  `broadcast_chest_state()` (`game/bsgame.c:1868-1873`) and sent to a single joiner by
  `send_chest_state()` (`game/bsgame.c:1879-1885`), and `BS_APP_CHEST_ACTION` (`0x13`, C→S, one
  requested deposit or withdraw, decoded by `chestActionDecode()` and dispatched by
  `handle_chest_action()`, `game/bsgame.c:2149-2186`).

- **`send_chunk_column_chests()` — chest contents follow a column subscription, not just a
  live transfer.** Forward-declared at `game/bsgame.c:1685`, called from `handle_chunk_sub()`
  at `game/bsgame.c:1719` right after `send_chunk_diffs()`, defined at `game/bsgame.c:1929-1940`.
  Before this, `broadcast_chest_state()` had exactly one caller — a live deposit or withdraw —
  so a player who joined *after* a chest was filled saw it as empty, could withdraw nothing
  from it, and could still break it: their client paid itself out from its own empty local
  record while the server's `cheststoreRemove()` deleted the real contents underneath it. The
  fix is scoped to the column rather than a join-time burst of the whole store, for reasons the
  function's header comment spells out: a full dump is `BS_CHEST_MAX` (4096) records at
  `BS_CHEST_STATE_BYTES` each — roughly 118 KB — which re-creates exactly the join-burst storm
  V127-A's chunk-subscription model removed, and it would be largely wasted anyway, since the
  client's own block-state table is a fixed `BLOCKSTATE_SLOTS`-entry array that drops any
  surplus on arrival. `CHUNK_SUB` is what loading a column already emits, so a player cannot
  render, open, or break a chest in a column whose contents have not already arrived.

- **A capability bitfield, not a protocol bump.** `send_server_caps()` announces
  `BS_CAP_CHESTS` (bit 0); `BS_PROTO_VERSION` does not move. The reasoning is written directly
  above the function: a client must not send `CHEST_ACTION` unless it saw this bit, because an
  unrecognised client-to-server opcode still ends in `send_kick()` on any server, old or new —
  the bit exists so a v1.9.0 client can tell the two cases apart before it ever risks that kick
  (`game/bsgame.c:993-998`). Any caps bits a client might echo back are not a message type this
  side dispatches at all, so there is nothing for a hostile client to abuse there.

- **A chest store, `BsChestStore`.** A flat array of `BS_CHEST_MAX = 4096` records keyed by
  `(x, y, z)`, linear-scanned — at this size the scan costs microseconds, so there is no index
  (`game/cheststore.h:40,55`). Opened once at startup, after `registryFreeze()`, because
  loading a record sanitises its slots through `inventoryCanHold()`, which needs the registry
  already settled to answer. A damaged file refuses the server from starting rather than
  silently coming up with fewer chests than it should — the same posture `diffstoreOpen()`
  already takes on the diff store, because a chest that silently comes up empty is an item
  loss nobody would ever see happen (`game/bsgame.c:2677-2689`).

- **`chests.bin`, debounced.** The store itself decides whether anything is dirty and whether
  `BS_CHEST_FLUSH_MS` (1000 ms) has passed since the last write, so `tick()`'s call is a
  couple of comparisons on most ticks (`game/bsgame.c:2360-2369`). The write is whole-file,
  `playerstate.c`'s own shape: new bytes go to `<path>.tmp`, get fsync'd, get renamed over the
  real path, and the directory is fsync'd — a crash at any point during that leaves either the
  previous file or the new one, never a half-written one (`game/cheststore.h:144-148`). A
  failed write is logged and the store is left dirty for the next due attempt rather than
  taking the server down; the contents are correct in memory either way.

- **Orphan drop on block edit.** A chest's record is keyed by position alone, so if the block
  at that position stops being `BLOCK_CHEST`, its record is deleted in the same edit that
  changed the block — otherwise the next chest placed on that cell would come up full of the
  previous one's contents, free items for whoever breaks and re-places a chest. A chest
  replaced by another chest keeps its record, because the block did not actually change
  (`handle_block_edit()`, `game/bsgame.c:1577-1620`).

### Fixed

- **Chest transfers were not a move — a deposit or withdraw touched only the chest, never the
  bag.** `chest_action_apply()` used to take a `const BsPlayer *p` and never write to it
  (`game/bsgame.c:2006`); it now takes a mutable `BsPlayer *p` and moves units on both sides of
  the transfer, in both directions, with the bag committed first and rolled back if the chest
  side then refuses — the bag's rollback can never itself fail (units just removed always fit
  back; units just added can always be removed again), while rolling a chest back would mean
  re-deriving a slot a concurrent packet may already have moved (`game/bsgame.c:1993-1997`).
  DEPOSIT now checks the bag actually holds `act->count` of the item before touching anything
  (`game/bsgame.c:2033-2041`), and debits the bag by the room-clamped `units` the chest is
  actually going to take, never the raw requested `act->count`
  (`game/bsgame.c:2051-2054`) — MEASURED: debiting the request instead of the clamp destroyed 6
  units on a deposit into a slot already standing at 95. WITHDRAW credits the bag *first*,
  reads back how many units `inventoryAdd()` actually `accepted`, and takes only that many from
  the chest, rolling the bag credit back if the chest then can't produce them
  (`game/bsgame.c:2113-2138`) — MEASURED pre-fix: a withdraw into a full bag destroyed 50 units,
  because the chest side had already been decremented before the bag's refusal was known.

- **Breaking a chest destroyed its contents — the headline bug.** MEASURED on a real bound
  `AF_UNIX SOCK_DGRAM` receiver against the real `bsgame.c`: breaking a filled chest emitted
  **0 `CHEST_STATE`, 0 `INV_STATE`, 1 `BLOCK_EDIT`**, and 94 units left the authoritative store
  with nothing on the wire to account for them — worse than plain annihilation, because
  `handle_inv_action()` answers *every* `INV_ACTION` with an unconditional `send_inv_state()`
  outside its `if (changed)` guard, so even a client that paid itself out of its own stale local
  record had that payout silently reverted by its own next hotbar tap. `handle_block_edit()`
  now computes the whole payout on a **scratch copy** of the breaker's bag *above* the
  `diffstoreApply()` world commit, and refuses the whole break — nothing destroyed, block and
  chest record both intact — if any unit will not fit; only once the payout is guaranteed to fit
  does the commit proceed, with the scratch bag written back and `cheststoreRemove()` called in
  the same step (`game/bsgame.c:1467-1657`, payout computed at `1533-1568`, orphan drop and
  commit at `1577-1620`). The long comment at the top of that block states the ordering trap
  and the rejected alternative: `diffstoreApply()` has already committed the block by the time
  the old orphan-drop code ran, so checking room *after* the commit would leave a choice between
  a refusal that reverts the world (which `diffstoreApply()` cannot do — it has no undo) or one
  that leaves the block changed with the chest record still standing, diverging from the wire.
  Checking room *before* the commit, on a scratch copy that is only written back once the commit
  has actually succeeded, was taken instead because a scratch bag that is never committed needs
  no rollback path at all — there is no second way for the function to leave half a transfer
  behind.

- **A crash could leave the bag and `chests.bin` disagreeing on disk for up to a second.**
  `chests.bin` is written by a debounced whole-file rewrite — `cheststoreFlush()`, at most once
  every `BS_CHEST_FLUSH_MS` (1000 ms) — while a broken chest's payout reaches
  `players/<label>/inventory.dat` immediately. Measured with a real `SIGKILL` inside that
  window: `inventory.dat` held **25 units** while `chests.bin` still held the removed chest's
  record with **5 units** of the same item. This never produced in-game duplication — the stale
  record does not come back as a live withdrawable chest on restart — but the two stores
  disagreed, and anything reading `chests.bin` directly (a backup, an external tool) would see
  it. `handle_block_edit()` now forces a flush in the same step as the removal and the bag
  commit. After the fix, the same `SIGKILL` gives "chest record absent — the removal DID reach
  disk before the kill", with the bag still holding its 25.

  The debounce itself is deliberately unchanged. Ordinary deposits and withdrawals go through
  `handle_chest_action()`, never this path, and keep coalescing exactly as before — they are
  frequent, and absorbing them is what the debounce is for. A chest break is rare and already
  rate limited by `playerEditAllow()`, so one forced whole-file rewrite there costs little.

  **The residual window is a loss window, and that is the deliberate choice.** No transaction
  spans `chests.bin` and `inventory.dat`, so a crash in the gap between the two writes must
  lose one way or the other. As ordered, the record is already gone and the bag not yet saved,
  so the units are lost on restart; reversed, the bag would be saved with the record still
  standing and the units would exist in both places — duplication. Loss is the one to take:
  duplication is exploitable by anyone who can make the process die at will, and it inflates a
  shared world permanently. The ordering is commented in place so it is not "tidied" later.

  **Not guarded by the in-process suite, and this was checked rather than assumed.** A
  regression check that read `chests.bin` straight after a break was written, red-armed, and
  found to stay **green** with the fix reverted: `bsgame_test.c` runs one shared daemon for the
  whole suite, so `tick()`'s own debounced flush already carries a stale `last_flush_ms` by the
  time the chest scenarios run and flushes on the next tick regardless. It was removed rather
  than kept for show — a check that cannot go red proves nothing. Only a real `SIGKILL` and
  restart catches this, which is what the out-of-repo harness does.

### Design

- **A refused `CHEST_ACTION` is dropped, never a kick.** Every failure path inside
  `chest_action_apply()` — a position out of range, no chest at that position, a count outside
  `1..BS_INV_STACK_MAX`, a bad chest slot, an item the inventory can't hold, no room left in
  the slot, an empty withdraw slot, an unrecognised op — logs one line naming the reason and
  returns `false`; the caller sends nothing back to the player at all
  (`game/bsgame.c:2006-2147`). This is a deliberate departure from `handle_app_payload()`'s
  usual answer to a malformed or out-of-contract message, which is `send_kick()`. A
  `CHEST_ACTION` sent in good faith can legitimately lose a race against another player
  emptying the same chest a moment earlier — kicking the loser of an ordinary race over shared
  state would be the wrong failure mode for something this routine.

### Compatibility

- **Clients from before chests are unaffected.** Such a client never sends `CHEST_ACTION`, so
  `handle_chest_action()` is never reached on its behalf, and it has no reason to look for
  `SERVER_CAPS` since that opcode did not exist when it was built. The registry lockstep that
  actually gates who can join at all is unchanged from v1.9.9 — this release adds no new
  registry row and no new join-time gate of its own.

### Testing

- Full host suite: `PASS 594 checks, 0 failed`. The chest group alone ran 247 checks against its
  own pin (`BSGAME_TEST_CHEST_CHECKS`, `game/bsgame_test.c:5661`), raised from 214 to 233 by two
  scenarios added for the break-payout fix (`test_chest_break_pays_the_breaker` and
  `test_chest_break_into_a_full_bag_is_refused`), and from 233 to 247 by a third added for the
  forced-flush fix (`test_chest_break_forces_a_chest_store_flush`, `game/bsgame_test.c:5500`),
  which reads `game/bsgame.c`'s own source text and proves the `cheststoreFlush(..., force=true)`
  call sits inside the `if (has_record)` block rather than merely somewhere in the function; the
  pin itself was already raised once this release, 184 → 214, for the transfer-conservation fix.

- **Known limitation.** A chest slot holding an item id that `inventoryCanHold()` refuses can
  never be broken and never be withdrawn from — the refusal fires on any leftover, and this
  release's break-payout fix and `chest_action_apply()`'s deposit path both refuse the whole
  action rather than destroy or strand a partial amount. Unreachable today:
  `cheststoreOpen()` sanitises every stored slot through `inventoryCanHold()` at load
  (`game/cheststore.c:186-209`), and deposits are gated on the same check
  (`game/bsgame.c:2028`), so no chest can come to hold such an item in the first place. It
  becomes reachable only if a future registry edit un-defines, or changes the meaning of, an
  item id already sitting in a live chest — no escape hatch was added for that case; it is a
  design decision, not an oversight.

- **Not playtested on hardware.** Everything above was verified against the host build and the
  host test suite (`bsgame_test`, Linux x86-64) plus a real `AF_UNIX SOCK_DGRAM` receiver on the
  same host. Nothing in this release has run against a real 3DS.
