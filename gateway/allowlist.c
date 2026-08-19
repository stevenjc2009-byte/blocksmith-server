#include "allowlist.h"

#include <stdio.h>
#include <string.h>

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
