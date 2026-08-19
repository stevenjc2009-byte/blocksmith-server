/* proxyproto.h — HAProxy PROXY protocol v2 header parsing.
 *
 * The playit relay forwards every player's traffic from its own local socket,
 * so without this the gateway would see one source address for everybody:
 * per-player rate limiting would collapse into a single shared bucket, and the
 * stateless cookie would bind to the relay rather than to the client, which is
 * to say it would prove nothing.
 *
 * With Proxy Protocol v2 enabled on the tunnel, the relay prefixes each
 * datagram with the real client address, and both of those layers work again.
 *
 * Trust boundary: this header is *unauthenticated*. Anything that can send to
 * the listening socket can claim any source address. It is only safe because
 * the gateway binds to loopback and refuses to honour a header from outside a
 * configured trusted CIDR — see --proxy-protocol / --trusted-proxy in bsgate.
 * The parser itself therefore assumes nothing and validates everything.
 *
 * Note v1 (the text form) is deliberately not supported: playit ignores v1 on
 * UDP tunnels, so accepting it here would only add parser surface for a format
 * that can never legitimately arrive.
 */

#ifndef BS_PROXYPROTO_H
#define BS_PROXYPROTO_H

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

/* Fixed part of a v2 header: 12-byte signature, version/command, family/
 * protocol, and a 16-bit length. */
#define BS_PPV2_HDR_BYTES   16u

/* AF_INET address block: src addr, dst addr, src port, dst port. */
#define BS_PPV2_INET_BYTES  12u

/* Parses a PROXY protocol v2 header at the front of `pkt`.
 *
 * On success, writes the real client address to *client and returns the byte
 * offset at which the wrapped payload begins.
 *
 * Returns -1 for anything that is not a well-formed v2 PROXY header carrying
 * an IPv4 address — a bad signature, v1, the LOCAL command, IPv6, a truncated
 * or over-long length. The caller must drop the datagram; there is no partial
 * success and no fallback to the socket's own source address, because falling
 * back is exactly how a spoofed header would get itself trusted.
 */
int bs_ppv2_parse(const uint8_t *pkt, size_t len, struct sockaddr_in *client);

#endif /* BS_PROXYPROTO_H */
