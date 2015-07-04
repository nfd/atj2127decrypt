#include <inttypes.h>

/* From SDK */
typedef struct {
	uint8_t   name[11]; /* 8.3 format */
	uint8_t   type; // A, B, H, F, S, U, or I  -- no idea what this is for yet
	uint32_t  address;
	uint32_t  offset; // file offset in bytes (encrypted central directory) or 512-byte sectors (FWIMAGE)
	uint32_t  length; // length in bytes, rounded up to 512 bytes 
	uint32_t  sub_type;
	uint32_t  checksum;
} AFI_DIR_t;

struct fwimage_header {
	uint8_t signature[4]; /* 0x55 0xAA 0xf0 0x0f*/
	uint8_t version_string[12];
	uint8_t unknown[4];
};

