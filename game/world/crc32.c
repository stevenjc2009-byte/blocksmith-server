#include "world/crc32.h"

// Nibble-at-a-time, so the table is 16 entries (64 bytes) instead of 256 (1 KB).
//
// The 3DS has 32 KB of L1 data cache shared with everything else the frame is doing, and
// this runs during a save, right next to the mesher's 4 KB scratch and the region file's
// 3 KB directory. A 1 KB table would evict a quarter of what the frame is using to save
// roughly one shift per byte on a checksum that is not on any per-frame path.
static const uint32_t kCrcNib[16] = {
	0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
	0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
	0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
	0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu,
};

uint32_t crc32Update(uint32_t crc, const void* data, size_t len)
{
	const uint8_t* p = (const uint8_t*)data;

	for (size_t i = 0; i < len; i++) {
		crc ^= p[i];
		crc = (crc >> 4) ^ kCrcNib[crc & 0x0F];
		crc = (crc >> 4) ^ kCrcNib[crc & 0x0F];
	}
	return crc;
}
