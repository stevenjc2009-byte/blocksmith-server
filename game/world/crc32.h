// CRC-32 (the IEEE 802.3 polynomial, reflected — the same one zip and PNG use).
//
// Step 8.1 needs it for one job: telling a payload that finished writing apart from one
// that was half-way through when the console lost power. A checksum is the only thing that
// can answer that, because a torn write leaves a *plausible* prefix behind — the length is
// right, the bytes decode, and the world quietly comes back wrong.
//
// Reflected rather than the straight form because that is what every other tool on the
// machine produces, so a save file's checksum can be verified from Python without
// reimplementing anything.
#pragma once

#include <stddef.h>
#include <stdint.h>

// Seed a fresh run with CRC32_INIT, feed it any number of blocks in order, and finish with
// crc32Final. Splitting it this way lets a region write checksum a header and a payload that
// are not next to each other in memory.
#define CRC32_INIT  0xFFFFFFFFu

uint32_t crc32Update(uint32_t crc, const void* data, size_t len);

static inline uint32_t crc32Final(uint32_t crc) { return crc ^ 0xFFFFFFFFu; }

// The whole thing in one call, for the common case.
static inline uint32_t crc32(const void* data, size_t len)
{
	return crc32Final(crc32Update(CRC32_INIT, data, len));
}
