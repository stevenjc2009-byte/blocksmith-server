/* fchmod/fileno are POSIX, not C11, and -std=c11 hides them. Same declaration
 * bsgate.c makes, for the same reason. */
#define _GNU_SOURCE

#include "allowlist.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include <hydrogen.h>

static bool parse_line(const char *line, struct bs_allow_entry *e)
{
    /* Skip leading whitespace. */
    while (*line == ' ' || *line == '\t') line++;

    char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
    size_t n = 0;
    while (n < sizeof hex - 1 && line[n] != '\0'
           && line[n] != ' ' && line[n] != '\t') {
        hex[n] = line[n];
        n++;
    }
    if (n != 2 * BS_KX_PUBLICKEYBYTES) return false;
    hex[n] = '\0';

    if (hydro_hex2bin(e->pk, sizeof e->pk, hex, n, NULL, NULL)
        != (int)sizeof e->pk) {
        return false;
    }

    line += n;
    while (*line == ' ' || *line == '\t') line++;

    size_t l = 0;
    while (l < BS_ALLOW_LABEL_MAX - 1 && line[l] != '\0'
           && line[l] != '\n' && line[l] != '\r') {
        /* Labels reach the log; keep them to printable ASCII so a crafted
         * allowlist cannot inject terminal escapes into journalctl output. */
        e->label[l] = (line[l] >= 0x20 && line[l] < 0x7f) ? line[l] : '?';
        l++;
    }
    e->label[l] = '\0';
    if (l == 0) return false;   /* an unlabelled key is unrevocable in practice */

    return true;
}

bool bs_allowlist_load(struct bs_allowlist *out, const char *path,
                       char *errbuf, size_t errbuf_len)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot open %s", path);
        return false;
    }

    /* Build into a scratch copy so a malformed line late in the file cannot
     * leave the live allowlist partially replaced. */
    struct bs_allowlist tmp;
    memset(&tmp, 0, sizeof tmp);

    char line[256];
    unsigned lineno = 0;
    bool ok = true;

    while (fgets(line, sizeof line, f) != NULL) {
        lineno++;

        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#') continue;

        if (tmp.count >= BS_ALLOW_MAX_PEERS) {
            if (errbuf) snprintf(errbuf, errbuf_len,
                                 "%s: more than %u peers", path, BS_ALLOW_MAX_PEERS);
            ok = false;
            break;
        }
        if (!parse_line(line, &tmp.entry[tmp.count])) {
            if (errbuf) snprintf(errbuf, errbuf_len,
                                 "%s:%u: malformed entry", path, lineno);
            ok = false;
            break;
        }

        /* Reject duplicates: two lines with one key means revoking one of them
         * looks like it worked while the peer still gets in. */
        for (size_t i = 0; i < tmp.count; i++) {
            if (hydro_equal(tmp.entry[i].pk, tmp.entry[tmp.count].pk,
                            BS_KX_PUBLICKEYBYTES)) {
                if (errbuf) snprintf(errbuf, errbuf_len,
                                     "%s:%u: duplicate key", path, lineno);
                ok = false;
                break;
            }
        }
        if (!ok) break;

        tmp.count++;
    }

    fclose(f);

    if (ok) *out = tmp;
    hydro_memzero(&tmp, sizeof tmp);
    return ok;
}

const struct bs_allow_entry *bs_allowlist_find(const struct bs_allowlist *al,
                                               const uint8_t pk[BS_KX_PUBLICKEYBYTES])
{
    const struct bs_allow_entry *hit = NULL;

    for (size_t i = 0; i < al->count; i++) {
        if (hydro_equal(al->entry[i].pk, pk, BS_KX_PUBLICKEYBYTES)) {
            hit = &al->entry[i];      /* no break: keep the scan constant-time */
        }
    }
    return hit;
}

/* Labels are written into the authorisation file and later read back out into
 * the journal, so the set is kept deliberately narrow. Same rule the
 * `bsgate-keys add` shell validator enforces, restated here because this path
 * does not go through that script. */
bool bs_allowlist_label_ok(const char *label)
{
    size_t n = 0;
    for (; label[n] != '\0'; n++) {
        char c = label[n];
        bool good = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                 || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!good) return false;
    }
    return n >= 1 && n < BS_ALLOW_LABEL_MAX;
}

bool bs_allowlist_append(const char *path,
                         const uint8_t pk[BS_KX_PUBLICKEYBYTES],
                         const char *label, char *errbuf, size_t errbuf_len)
{
    if (!bs_allowlist_label_ok(label)) {
        if (errbuf) snprintf(errbuf, errbuf_len, "invalid label");
        return false;
    }

    /* Read-modify-write against the file, not against the daemon's in-memory
     * copy: the operator may have edited the file by hand since the last
     * reload, and silently discarding that is how an enrolment would appear to
     * revoke somebody. */
    struct bs_allowlist current;
    char why[160];
    if (!bs_allowlist_load(&current, path, why, sizeof why)) {
        if (errbuf) snprintf(errbuf, errbuf_len, "%s", why);
        return false;
    }
    if (bs_allowlist_find(&current, pk) != NULL) {
        if (errbuf) snprintf(errbuf, errbuf_len, "key is already on the allowlist");
        hydro_memzero(&current, sizeof current);
        return false;
    }
    /* Labels are how `bsgate-keys revoke` names a peer, so two entries sharing
     * one label means revoking it removes both — or, read the other way, an
     * operator who thinks they revoked a friend has actually revoked two
     * people and been told it worked. `bsgate-keys add` refuses this for the
     * same reason; the check is repeated here because an invite can be armed
     * for a label that only becomes a duplicate afterwards. */
    for (size_t i = 0; i < current.count; i++) {
        if (strcmp(current.entry[i].label, label) == 0) {
            if (errbuf) snprintf(errbuf, errbuf_len,
                                 "label '%s' is already on the allowlist", label);
            hydro_memzero(&current, sizeof current);
            return false;
        }
    }
    if (current.count >= BS_ALLOW_MAX_PEERS) {
        if (errbuf) snprintf(errbuf, errbuf_len, "allowlist is full (%u peers)",
                             BS_ALLOW_MAX_PEERS);
        hydro_memzero(&current, sizeof current);
        return false;
    }
    hydro_memzero(&current, sizeof current);

    char tmp_path[600];
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path) >= (int)sizeof tmp_path) {
        if (errbuf) snprintf(errbuf, errbuf_len, "allowlist path too long");
        return false;
    }

    FILE *in = fopen(path, "re");
    if (in == NULL) {
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot read %s", path);
        return false;
    }
    FILE *out = fopen(tmp_path, "we");
    if (out == NULL) {
        fclose(in);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot write %s", tmp_path);
        return false;
    }
    if (fchmod(fileno(out), 0600) != 0) {
        fclose(in); fclose(out); (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot chmod %s", tmp_path);
        return false;
    }

    int last = '\n';
    int c;
    bool io_ok = true;
    while ((c = fgetc(in)) != EOF) {
        if (fputc(c, out) == EOF) { io_ok = false; break; }
        last = c;
    }
    fclose(in);

    /* A file whose last line has no newline would otherwise absorb the new key
     * into it, producing one unparseable line and a daemon that refuses to
     * reload. */
    if (io_ok && last != '\n') io_ok = fputc('\n', out) != EOF;

    char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
    hydro_bin2hex(hex, sizeof hex, pk, BS_KX_PUBLICKEYBYTES);
    if (io_ok) io_ok = fprintf(out, "%s %s\n", hex, label) > 0;
    if (io_ok) io_ok = fflush(out) == 0 && fsync(fileno(out)) == 0;
    fclose(out);

    if (!io_ok) {
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "write to %s failed", tmp_path);
        return false;
    }

    /* Validate before installing, exactly as `bsgate-keys` does: an allowlist
     * the daemon cannot parse is a lockout for everyone, not just the peer
     * being added. */
    struct bs_allowlist check;
    if (!bs_allowlist_load(&check, tmp_path, why, sizeof why)) {
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "refusing to install: %s", why);
        hydro_memzero(&check, sizeof check);
        return false;
    }
    hydro_memzero(&check, sizeof check);

    if (rename(tmp_path, path) != 0) {
        (void)unlink(tmp_path);
        if (errbuf) snprintf(errbuf, errbuf_len, "cannot rename %s -> %s", tmp_path, path);
        return false;
    }
    return true;
}
