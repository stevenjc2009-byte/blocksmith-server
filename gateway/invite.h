/* invite.h — the single armed, one-time enrolment code.
 *
 * The allowlist (allowlist.h) is the authorisation model, and it is a list of
 * 32-byte static public keys. That is correct and is not changing. The problem
 * it creates is purely human: getting a key off a 3DS and onto a server means
 * moving 64 hex characters between two devices that share no clipboard.
 *
 * An invite inverts the direction. The operator arms one code, in the form
 * `XXXXX-XXXXX`, and sends it to the friend by any means they like. The friend
 * types it into the console once. The console's key is then written into the
 * allowlist by the daemon and the invite is destroyed. Nobody reads a key.
 *
 * Deliberate properties, in the order they matter:
 *
 *  - At most ONE invite exists at a time. Not a pool, not per-friend: arming a
 *    new one replaces any existing one. A single armed code is a thing an
 *    operator can hold in their head, and it bounds the blast radius to one.
 *  - It is stored HASHED, never in plaintext. `bsgate-keys invite` prints the
 *    code once and then cannot show it again, because nothing on the box can
 *    recover it. Losing it means arming a new one, which costs nothing.
 *  - It expires on a wall clock, not a monotonic one, so a reboot cannot
 *    silently extend the window.
 *  - Wrong guesses are counted and the invite disarms itself after
 *    BS_INVITE_STRIKES of them. An expired or burnt invite leaves the gateway
 *    behaving exactly as it does with no invite at all.
 *
 * What this does NOT do: it never authorises anyone by itself. A correct code
 * causes a key to be ADDED to the allowlist; from that moment the ordinary
 * allowlist check is what admits the peer, on that connection and every one
 * after it. There is no path here that admits a session without an allowlist
 * entry existing.
 */

#ifndef BS_INVITE_H
#define BS_INVITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "allowlist.h"
#include "hydrogen.h"

/* Wrong codes tolerated before the invite disarms itself. Three is chosen
 * against a human typo, not against a search: the code is ~49 bits, so an
 * attacker with unlimited guesses inside the window still gets nowhere, and
 * the strike counter is there so that a *burnt* invite cannot be left armed
 * indefinitely by someone hammering it. */
#define BS_INVITE_STRIKES  3u

/* How long `bsgate-keys invite` arms one for, in seconds. Long enough to send
 * a message and have someone go and fetch their console; short enough that a
 * forgotten invite is not a standing door. */
#define BS_INVITE_TTL_SEC  (15 * 60)

/* Characters a code is drawn from: 30 symbols, chosen to survive being read
 * aloud, retyped, and entered on a 3DS software keyboard. No 0/O, no 1/I/L,
 * no U (which turns into V in some handwriting and is the classic Crockford
 * exclusion). 10 symbols of this alphabet is 10 * log2(30) = 49.1 bits. */
#define BS_INVITE_ALPHABET "23456789ABCDEFGHJKMNPQRSTVWXYZ"
#define BS_INVITE_CODE_LEN 10u

struct bs_invite {
    bool     armed;
    char     label[BS_ALLOW_LABEL_MAX];
    uint8_t  code_hash[hydro_hash_BYTES];
    int64_t  expires_unix;
    unsigned strikes_left;
};

/* Normalises a typed code and hashes it. Normalising means: uppercase, and
 * every character outside the alphabet discarded. That is what makes
 * "tom" pasting `9k4b2-hmq7x`, `9K4B2 HMQ7X` and `9K4B2HMQ7X` all work — the
 * separator is presentation, and a 3DS keyboard makes people fight for it. */
void bs_invite_hash_code(const char *raw, uint8_t out[hydro_hash_BYTES]);

/* Fills `out` with a fresh random code, NUL-terminated, WITHOUT the separator
 * (BS_INVITE_CODE_LEN characters). `cap` must be > BS_INVITE_CODE_LEN. */
void bs_invite_generate(char *out, size_t cap);

/* Reads `path`. A missing file is not an error: `out->armed` becomes false and
 * the function returns true, because "no invite armed" is the normal state and
 * must never be reported as a fault. A malformed file IS an error and leaves
 * `out` untouched, on the same reasoning as bs_allowlist_load: a half-parsed
 * security record is worse than a stale one. */
bool bs_invite_load(struct bs_invite *out, const char *path,
                    char *errbuf, size_t errbuf_len);

/* Writes `in` to `path` via a temp file and rename, 0600. If `in->armed` is
 * false the file is removed instead — that is how "consumed" and "cancelled"
 * are both expressed, so there is exactly one way to end up disarmed. */
bool bs_invite_save(const struct bs_invite *in, const char *path,
                    char *errbuf, size_t errbuf_len);

/* True if armed and not past its expiry. `now_unix` is passed in rather than
 * read here so the tests can drive the clock. */
bool bs_invite_valid(const struct bs_invite *iv, int64_t now_unix);

/* Constant-time comparison of a typed code against the armed hash. Returns
 * false for an unarmed or expired invite without looking at `raw` at all. */
bool bs_invite_matches(const struct bs_invite *iv, const char *raw,
                       int64_t now_unix);

#endif /* BS_INVITE_H */
