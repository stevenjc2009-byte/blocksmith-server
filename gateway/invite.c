/* fchmod/fileno are POSIX, not C11, and -std=c11 hides them. Same declaration
 * bsgate.c makes, for the same reason. */
#define _GNU_SOURCE

#include "invite.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

/* Hash context for the stored code digest. libhydrogen wants exactly 8 bytes.
 * Distinct from every other context in the build so a digest from here can
 * never be confused with, or substituted for, a cookie MAC. */
#define BS_INVITE_HASH_CTX "bsinvite"

static char upper_ascii(char c)
{
    return (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
}

void bs_invite_hash_code(const char *raw, uint8_t out[hydro_hash_BYTES])
{
    /* Normalise first: uppercase, and drop anything not in the alphabet. The
     * separator in XXXXX-XXXXX is presentation only, and a 3DS software
     * keyboard makes people fight for a hyphen, so it must not be load
     * bearing. Characters outside the alphabet are dropped rather than
     * rejected here so that normalisation cannot fail — a wrong code has
     * exactly one outcome (a mismatch), never a different one. */
    char norm[BS_INVITE_CODE_MAX + 1];
    size_t n = 0;

    for (size_t i = 0; raw != NULL && raw[i] != '\0' && n < sizeof norm - 1; i++) {
        char c = upper_ascii(raw[i]);
        if (strchr(BS_INVITE_ALPHABET, c) != NULL && c != '\0') norm[n++] = c;
    }
    norm[n] = '\0';

    hydro_hash_hash(out, hydro_hash_BYTES, norm, n, BS_INVITE_HASH_CTX, NULL);
    hydro_memzero(norm, sizeof norm);
}

void bs_invite_generate(char *out, size_t cap)
{
    const size_t alpha = sizeof(BS_INVITE_ALPHABET) - 1;

    if (cap == 0) return;
    size_t want = BS_INVITE_CODE_LEN;
    if (want > cap - 1) want = cap - 1;

    for (size_t i = 0; i < want; i++) {
        /* hydro_random_uniform is rejection-sampled upstream, so the alphabet
         * stays uniform even though 30 does not divide 2^32. Doing this with
         * `% 30` would bias the first two symbols, which is exactly the kind
         * of quiet entropy loss that never shows up in a test. */
        out[i] = BS_INVITE_ALPHABET[hydro_random_uniform((uint32_t)alpha)];
    }
    out[want] = '\0';
}

bool bs_invite_load(struct bs_invite *out, const char *path,
                    char *errbuf, size_t errbuf_len)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        /* No file is the normal state, not a fault: most of this server's life
         * is spent with no invite armed. Reporting it as an error would make
         * the daemon's startup log cry wolf on every boot. */
        memset(out, 0, sizeof *out);
        out->armed = false;
        return true;
    }

    struct bs_invite tmp;
    memset(&tmp, 0, sizeof tmp);

    char line[256];
    bool have_label = false, have_hash = false, have_exp = false, have_str = false;
    bool ok = true;

    while (ok && fgets(line, sizeof line, f) != NULL) {
        char key[32], val[192];
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, "%31s %191s", key, val) != 2) continue;

        if (strcmp(key, "label") == 0) {
            snprintf(tmp.label, sizeof tmp.label, "%s", val);
            have_label = tmp.label[0] != '\0';
        } else if (strcmp(key, "code_hash") == 0) {
            if (hydro_hex2bin(tmp.code_hash, sizeof tmp.code_hash,
                              val, strlen(val), NULL, NULL)
                != (int)sizeof tmp.code_hash) {
                if (errbuf) snprintf(errbuf, errbuf_len, "%s: bad code_hash", path);
                ok = false;
            } else {
                have_hash = true;
            }
        } else if (strcmp(key, "expires") == 0) {
            tmp.expires_unix = strtoll(val, NULL, 10);
            have_exp = true;
        } else if (strcmp(key, "strikes") == 0) {
            long s = strtol(val, NULL, 10);
            if (s < 0) s = 0;
            if (s > (long)BS_INVITE_STRIKES) s = (long)BS_INVITE_STRIKES;
            tmp.strikes_left = (unsigned)s;
            have_str = true;
        }
    }

    fclose(f);

    if (ok && !(have_label && have_hash && have_exp && have_str)) {
        if (errbuf) snprintf(errbuf, errbuf_len, "%s: incomplete invite record", path);
        ok = false;
    }

    if (ok) {
        tmp.armed = true;
        *out = tmp;
    }
    hydro_memzero(&tmp, sizeof tmp);
    return ok;
}

bool bs_invite_save(const struct bs_invite *in, const char *path,
                    char *errbuf, size_t errbuf_len)
{
    if (!in->armed) {
        /* Disarmed is represented by the file's absence, so "consumed",
         * "cancelled" and "burnt out" all converge on one state rather than
         * three flavours of armed-but-not-really. */
        if (unlink(path) != 0 && errno != ENOENT) {
            if (errbuf) snprintf(errbuf, errbuf_len, "cannot remove %s", path);
            return false;
        }
        return true;
    }

    char tmp_path[600];
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path) >= (int)sizeof tmp_path) {
        if (errbuf) snprintf(errbuf, errbuf_len, "invite path too long");
        return false;
    }

    /* 0600 from creation, not chmod'ed afterwards: even a hash of a live code
     * has no business being world-readable for the width of a syscall. */
    FILE *f = fopen(tmp_path, "wxe");
    if (f == NULL) {
        (void)unlink(tmp_path);
        f = fopen(tmp_path, "we");
    }
    if (f == NULL) {
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot write %s", tmp_path);
        return false;
    }
    if (fchmod(fileno(f), 0600) != 0) {
        fclose(f);
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot chmod %s", tmp_path);
        return false;
    }

    char hex[2 * hydro_hash_BYTES + 1];
    hydro_bin2hex(hex, sizeof hex, in->code_hash, sizeof in->code_hash);

    fprintf(f, "# bsgate invite — armed by `bsgate-keys invite`, one use only.\n");
    fprintf(f, "# The code itself is NOT here and cannot be recovered; only a\n");
    fprintf(f, "# hash of it is stored. Lost it? Arm a new one, it costs nothing.\n");
    fprintf(f, "label     %s\n", in->label);
    fprintf(f, "code_hash %s\n", hex);
    fprintf(f, "expires   %lld\n", (long long)in->expires_unix);
    fprintf(f, "strikes   %u\n", in->strikes_left);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot flush %s", tmp_path);
        return false;
    }
    fclose(f);

    if (rename(tmp_path, path) != 0) {
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot rename %s -> %s", tmp_path, path);
        return false;
    }
    return true;
}

bool bs_invite_valid(const struct bs_invite *iv, int64_t now_unix)
{
    return iv->armed && iv->strikes_left > 0 && now_unix < iv->expires_unix;
}

bool bs_invite_matches(const struct bs_invite *iv, const char *raw,
                       int64_t now_unix)
{
    if (!bs_invite_valid(iv, now_unix)) return false;

    uint8_t got[hydro_hash_BYTES];
    bs_invite_hash_code(raw, got);

    bool eq = hydro_equal(got, iv->code_hash, sizeof got);
    hydro_memzero(got, sizeof got);
    return eq;
}
