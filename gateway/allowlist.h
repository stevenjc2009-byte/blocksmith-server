/* allowlist.h — the set of client static public keys permitted to join.
 *
 * There is no account system and no password. A friend is a 32-byte Noise
 * static public key that appears in this file; revoking them is deleting the
 * line and sending SIGHUP. That is the whole authorisation model, and it is
 * deliberately small enough to audit in one sitting.
 */

#ifndef BS_ALLOWLIST_H
#define BS_ALLOWLIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../proto/bs_proto.h"

#define BS_ALLOW_MAX_PEERS  64u
#define BS_ALLOW_LABEL_MAX  32u

struct bs_allow_entry {
    uint8_t pk[BS_KX_PUBLICKEYBYTES];
    char    label[BS_ALLOW_LABEL_MAX];
};

struct bs_allowlist {
    struct bs_allow_entry entry[BS_ALLOW_MAX_PEERS];
    size_t                count;
};

/* Parses `path` into `out`, replacing its previous contents only on success.
 * Format: one entry per line, `<64 hex chars> <label>`; blank lines and lines
 * beginning with '#' are ignored. Returns false and leaves `out` untouched if
 * the file cannot be read or any line is malformed — a half-applied allowlist
 * is worse than a stale one, because it silently locks people out or, worse,
 * lets a deleted key survive a reload.
 *
 * On failure `errbuf` (if non-NULL) receives a human-readable reason. */
bool bs_allowlist_load(struct bs_allowlist *out, const char *path,
                       char *errbuf, size_t errbuf_len);

/* Returns the matching entry, or NULL. Scans every entry without early exit so
 * the lookup takes the same time whether the key is present, absent, or first
 * in the file. */
const struct bs_allow_entry *bs_allowlist_find(const struct bs_allowlist *al,
                                               const uint8_t pk[BS_KX_PUBLICKEYBYTES]);

#endif /* BS_ALLOWLIST_H */
