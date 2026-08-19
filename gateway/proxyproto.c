#include "proxyproto.h"

#include <string.h>

/* The v2 signature. Chosen by HAProxy to be un-mistakable for any real
 * protocol payload, which is what makes it safe to sniff for. */
static const uint8_t BS_PPV2_SIG[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* Byte 12: high nibble is the version, low nibble the command. */
#define PPV2_VERSION      0x2u
#define PPV2_CMD_LOCAL    0x0u
#define PPV2_CMD_PROXY    0x1u

/* Byte 13: high nibble address family, low nibble transport. */
#define PPV2_AF_INET_STREAM 0x11u
#define PPV2_AF_INET_DGRAM  0x12u

/* Offsets inside the AF_INET address block, which starts at BS_PPV2_HDR_BYTES. */
#define PPV2_OFF_SRC_ADDR   0u
#define PPV2_OFF_SRC_PORT   8u

int bs_ppv2_parse(const uint8_t *pkt, size_t len, struct sockaddr_in *client)
{
    if (pkt == NULL || client == NULL) return -1;
    if (len < BS_PPV2_HDR_BYTES)       return -1;

    if (memcmp(pkt, BS_PPV2_SIG, sizeof BS_PPV2_SIG) != 0) return -1;

    const uint8_t ver_cmd = pkt[12];
    if ((uint8_t)(ver_cmd >> 4) != PPV2_VERSION) return -1;

    /* LOCAL means "this is the proxy's own traffic, ignore the addresses" and
     * carries no usable client address. Health checks arrive this way. There
     * is nothing to authenticate against, so it is refused rather than
     * silently attributed to the relay. */
    if ((uint8_t)(ver_cmd & 0x0Fu) != PPV2_CMD_PROXY) return -1;

    /* IPv4 only. The 3DS has no IPv6 stack, so a v6 client is either a
     * misconfiguration or someone who is not a 3DS; either way it cannot be a
     * player, and widening the parser to carry an address the rest of the
     * gateway cannot represent would be all cost and no benefit. */
    const uint8_t fam = pkt[13];
    if (fam != PPV2_AF_INET_STREAM && fam != PPV2_AF_INET_DGRAM) return -1;

    /* Big-endian, per the spec — the one field on the wire here that is not
     * little-endian, because this format is not ours. */
    const size_t addr_len = ((size_t)pkt[14] << 8) | (size_t)pkt[15];

    /* Must hold at least the IPv4 block. It may be longer: TLVs are appended
     * inside this length, and skipping past them is exactly what the returned
     * offset does. */
    if (addr_len < BS_PPV2_INET_BYTES)   return -1;
    if (addr_len > len - BS_PPV2_HDR_BYTES) return -1;

    const uint8_t *a = pkt + BS_PPV2_HDR_BYTES;

    memset(client, 0, sizeof *client);
    client->sin_family = AF_INET;
    /* Both already in network byte order on the wire, so they copy straight
     * into the sockaddr without a swap. */
    memcpy(&client->sin_addr.s_addr, a + PPV2_OFF_SRC_ADDR, 4);
    memcpy(&client->sin_port,        a + PPV2_OFF_SRC_PORT, 2);

    return (int)(BS_PPV2_HDR_BYTES + addr_len);
}
