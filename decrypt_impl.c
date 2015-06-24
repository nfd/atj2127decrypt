#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "decrypt_impl.h"

uint8_t __bss[5440];

unsigned char firmware_directory_key[] = { // aka _key_2950 aka data_3000
	0x16, 0x2b, 0x01, 0xe4, 0x0e, 0x3d, 0xc1, 0xdf, 0x0f, 0x35, 0x8f, 0xf5, 0xe2, 0x48, 0xa0, 0x2e,
	0x1c, 0x6a, 0x57, 0xea, 0x6d, 0x9a, 0xe2, 0x03, 0xec, 0xe8, 0x84, 0x9c, 0x87, 0xca, 0xba, 0xcf,
	0xdb, 0x5c, 0x6f, 0xf2, 0x32, 0x72, 0xe9, 0x50, 0x42, 0x06, 0x1b, 0xe9, 0x9d, 0x8f, 0xa4, 0xff,
	0x66, 0x64, 0x59, 0xb7, 0xd0, 0x15, 0x3c, 0x42, 0x27, 0x25, 0x52, 0x47, 0x83, 0x09, 0x7c, 0x55,
	0x1d, 0xc1, 0x12, 0xfa, 0x7c, 0xaa, 0xf8, 0x60, 0xc6, 0x65, 0x3a, 0xf3, 0x13, 0x44, 0xa7, 0x5e,
	0xc7, 0x22, 0x7e, 0x91, 0xdf, 0x98, 0xf2, 0x8a, 0x08, 0x2c, 0x32, 0x77, 0x6a, 0x72, 0xff, 0x3d,
	0xa6, 0x13, 0x0c, 0xbe, 0x3e, 0x4b, 0xe9, 0x76, 0x35, 0x85, 0x93, 0x91, 0x9b, 0x25, 0x14, 0x10,
	0x08, 0x49, 0x39, 0xa9, 0x9a, 0x9c, 0x06, 0x1c, 0x4b, 0xf9, 0xae, 0x12, 0x94, 0xfa, 0x08, 0x55,
	0xaa, 0x05, 0x58, 0x10, 0x29, 0x80, 0x76, 0xe4, 0xac, 0x4b, 0x67, 0xdc, 0xdf, 0x87, 0x19, 0x6d,
	0x42, 0x66, 0x7c, 0x8c, 0xf7, 0x8d, 0x01, 0x29, 0x35, 0xba, 0xc7, 0x60, 0x4d, 0xe1, 0xb7, 0xd3,
	0xe7, 0xe3, 0xb0, 0x67, 0x3e, 0x38, 0x40, 0x67, 0x76, 0xd8, 0xa7, 0xd3, 0xd4, 0x72, 0xa4, 0x70,
	0xb6, 0x31, 0x51, 0xa0, 0x40, 0x4f, 0xaf, 0xab, 0x52, 0x8c, 0xf7, 0xf8, 0x74, 0x98, 0xaf, 0xbe,
	0x6e, 0x23, 0xd7, 0x47, 0xa1, 0x5d, 0x1b, 0x4e, 0xa2, 0x97, 0xd9, 0xc2, 0x26, 0x79, 0xb9, 0xf8,
	0xae, 0x5e, 0x04, 0x6d, 0xd5, 0xd0, 0xa7, 0x98, 0x6a, 0xce, 0xaa, 0x5f, 0xe4, 0xf9, 0xb8, 0xd2,
	0xbe, 0x1e, 0xcc, 0x55, 0xcb, 0x70, 0x0f, 0x6f, 0x81, 0x28, 0xcb, 0xf8, 0x8c, 0x5d, 0x7e, 0x55,
	0xd3, 0x27, 0xc9, 0xa9, 0x85, 0xa6, 0xc0, 0xf5, 0x79, 0xed, 0xc0, 0x7b, 0x1c, 0x36, 0xc3, 0xbd,
	0xa5, 0x8e, 0xa8, 0x77, 0x60, 0xe0, 0x39, 0xcd, 0x9a, 0x65, 0x60, 0x8b, 0x33, 0xfc, 0x2b, 0x49,
	0xa8, 0xca, 0x67, 0xba, 0x44, 0xaf, 0xf9, 0x29, 0x5d, 0x71, 0x30, 0x85, 0xe0, 0xe5, 0x16, 0xe0,
	0x25, 0x44, 0xc2, 0xab, 0x42, 0xf3, 0x48, 0x26, 0x01, 0x3f, 0x09, 0x59, 0xf5, 0x7f, 0xde, 0xce,
	0x49, 0x23, 0x38, 0xc6, 0x55, 0xd1, 0x47, 0xc6, 0x5b, 0xee, 0x9b, 0x6a, 0x9d, 0x0d, 0x72, 0x3c,
	0x36, 0x39, 0xf9, 0xdd, 0xf1, 0xd3, 0x84, 0x70, 0xe9, 0x05, 0x12, 0x10, 0x62, 0xcb, 0x6e, 0xbc,
	0x3f, 0xcb, 0x34, 0x73, 0xf6, 0x6f, 0xc4, 0x17, 0x0d, 0xe8, 0xeb, 0x25, 0x5c, 0xdf, 0xa0, 0x86,
	0x8c, 0xc3, 0xb9, 0x4a, 0xbb, 0x7e, 0x38, 0xc1, 0x17, 0x08, 0xd0, 0x93, 0x0f, 0x3e, 0xcf, 0x27,
	0x71, 0xa0, 0x72, 0xe7, 0xee, 0x7b, 0x41, 0x33, 0x4d, 0xfb, 0xaf, 0x5c, 0x55, 0xf7, 0xdc, 0xd9,
	0xf2, 0x14, 0x7d, 0xea, 0xe3, 0x08, 0xd6, 0xd3, 0xa0, 0xfa, 0x52, 0x17, 0x1b, 0x10, 0xce, 0x70,
	0xb6, 0xb9, 0xcf, 0xb4, 0x25, 0x9b, 0x42, 0x53, 0x67, 0x2b, 0x57, 0x7c, 0xff, 0x72, 0xa1, 0x83,
	0xcd, 0x08, 0xd3, 0x11, 0xae, 0x30, 0x9c, 0x0a, 0x01, 0x25, 0x73, 0x45, 0x7a, 0xfe, 0x78, 0xe9,
	0xf6, 0x3f, 0x5d, 0x0a, 0x35, 0x9f, 0x45, 0x48, 0x04, 0x48, 0xfe, 0x81, 0xc2, 0xc4, 0x82, 0x41,
	0xde, 0xa2, 0xb1, 0x67, 0x6a, 0x3b, 0x5b, 0x0c, 0x06, 0xb4, 0x6e, 0xe6, 0x0e, 0x15, 0xef, 0x12,
	0x3c, 0x7c, 0xd7, 0x49, 0xf3, 0x9c, 0x5b, 0x06, 0xf1, 0x2b, 0x45, 0xec, 0x99, 0x45, 0xaf, 0x10,
	0x17, 0x60, 0x66, 0x49, 0x85, 0x75, 0x02, 0x3d, 0xae, 0xe4, 0x15, 0xa8, 0xd7, 0xdf, 0xb7, 0x95,
	0xa3, 0x2d, 0xb3, 0x55, 0x19, 0x46, 0x3d, 0x62, 0x88, 0x08, 0x66, 0xf9, 0x4a, 0xb3, 0xa3, 0x3e,
	0x85, 0x79, 0x20, 0xaf, 0xed, 0xa7, 0x41, 0xa2, 0x8f, 0xa8, 0x84, 0x93, 0x46, 0x88, 0xb0, 0x1e,
	0x88, 0x58, 0x0b, 0x16, 0xc6, 0x28, 0x4b, 0x01, 0x7d, 0x8d, 0x54, 0x61, 0x1d, 0x57, 0x94, 0xfb,
	0x84, 0x6b, 0xea, 0xa4, 0x86, 0x98, 0x1b, 0x5e, 0xdb, 0x53, 0xcd, 0xf6, 0x0b, 0x44, 0xf0, 0xa9,
	0xb0, 0xcd, 0x1f, 0xda, 0x5e, 0xd0, 0xea, 0xb1, 0xe1, 0x70, 0xdf, 0x16, 0x44, 0xc2, 0xd0, 0x97,
	0xf9, 0xca, 0x88, 0x93, 0xf6, 0x4c, 0x12, 0xa3, 0x91, 0x2f, 0x16, 0x9f, 0x7b, 0xef, 0x2a, 0x7c,
	0x47, 0xf1, 0xbf, 0x16, 0xd6, 0x7b, 0xfc, 0x49, 0x91, 0xd9, 0xee, 0x84, 0xa8, 0xed, 0x84, 0xfb,
	0x2d, 0x84, 0x2d, 0x0c, 0x4e, 0xad, 0xee, 0x26, 0x81, 0xb2, 0x61, 0x27, 0x14, 0x3a, 0x9a, 0x32,
	0x2f, 0xf6, 0xac, 0xa7, 0xc6, 0xaa, 0x57, 0x37, 0x02, 0x23, 0x94, 0x26, 0xd3, 0xe5, 0x12, 0x84,
	0xdc, 0x53, 0x43, 0x76, 0x91, 0x79, 0xf6, 0x83, 0xef, 0x4a, 0x4c, 0xd8, 0x31, 0x76, 0x7d, 0xb4,
	0xe3, 0xb2, 0x78, 0x5c, 0x9d, 0xf4, 0xf7, 0x71, 0xf9, 0xd7, 0xdb, 0x64, 0xad, 0x8b, 0x36, 0x62,
	0x2c, 0xd5, 0x38, 0x32, 0x9e, 0x7b, 0xb3, 0xca, 0x83, 0xb3, 0x98, 0x78, 0x46, 0x9b, 0xf6, 0x69,
	0xa0, 0x57, 0xdb, 0x82, 0x8a, 0x3b, 0xaa, 0x69, 0x01, 0x1a, 0xf4, 0x1d, 0x80, 0x8f, 0xa8, 0x19,
	0x78, 0xe2, 0x56, 0x79, 0x78, 0x38, 0xb4, 0x09, 0x5c, 0x8d, 0x14, 0xf1, 0x35, 0x7a, 0x23, 0xa1,
	0xe1, 0x83, 0xaa, 0xf9, 0xbe, 0x5b, 0x81, 0x3a, 0xdc, 0x83, 0x47, 0xf9, 0xd1, 0xe4, 0x24, 0x84,
	0xfd, 0x51, 0xb8, 0x8a, 0xf5, 0xe3, 0x70, 0xee, 0xb4, 0xa6, 0x55, 0x57, 0xb5, 0xe3, 0xb9, 0x2e,
	0xfa, 0x26, 0x48, 0x01, 0xcd, 0x4a, 0x79, 0x70, 0x61, 0x76, 0xd6, 0xe9, 0xcd, 0x40, 0x63, 0x64,
	0x1f, 0xdd, 0xe4, 0x6e, 0x39, 0xb3, 0x3e, 0x3d, 0x28, 0xe4, 0xf6, 0x0b, 0x6c, 0x7a, 0xa9, 0x0d,
	0xcd, 0xd4, 0x5e, 0x33, 0xf7, 0x03, 0xde, 0x74, 0x51, 0xd3, 0xe0, 0x69, 0x58, 0x48, 0x5f, 0x80,
	0x8f, 0x73, 0x61, 0x16, 0xe7, 0x1c, 0x17, 0x34, 0x14, 0x7a, 0x93, 0xba, 0x3a, 0xbc, 0x21, 0x61,
	0xa9, 0x54, 0xe7, 0x89, 0x76, 0xf7, 0xb5, 0x86, 0x18, 0x76, 0x30, 0x26, 0x43, 0x50, 0xe8, 0x91,
	0x6b, 0xa8, 0xd9, 0x9a, 0x8f, 0xe1, 0x79, 0x9d, 0x9f, 0x13, 0xf7, 0x16, 0xf7, 0xe1, 0xeb, 0xd7,
	0xd5, 0x5e, 0xa7, 0x45, 0x4a, 0x7e, 0x6e, 0x3b, 0x62, 0xaa, 0x85, 0xa2, 0xfb, 0xa1, 0x2f, 0x47,
	0x9d, 0xcf, 0xf0, 0xcc, 0x91, 0xb9, 0x3c, 0xb4, 0x79, 0xe5, 0x68, 0x22, 0xaa, 0x1d, 0x2e, 0x5c,
	0x86, 0x3b, 0x2a, 0x28, 0x3e, 0x88, 0xd1, 0xc2, 0xc9, 0x32, 0x3b, 0x97, 0xa7, 0xd7, 0x48, 0xc4,
	0x65, 0xdd, 0x1b, 0xa2, 0xba, 0x20, 0xd4, 0x21, 0x38, 0x40, 0x0c, 0x18, 0x40, 0x77, 0x2e, 0x55,
	0xb5, 0x78, 0x65, 0xc9, 0x2e, 0x2d, 0x5a, 0x43, 0x41, 0xd5, 0x9e, 0x71, 0x68, 0x76, 0x07, 0x66,
	0xfc, 0x1c, 0x26, 0xdf, 0x18, 0xa7, 0xe4, 0x5a, 0x53, 0x9b, 0x50, 0x47, 0x76, 0xc5, 0xe1, 0xff,
	0x4b, 0x10, 0x29, 0x1f, 0x5c, 0x57, 0x58, 0xc1, 0xc3, 0xb1, 0xf7, 0xdd, 0x24, 0xd1, 0xaf, 0x13,
	0xb1, 0x13, 0xfb, 0x2a, 0x06, 0xcf, 0xc5, 0x47, 0x58, 0xa0, 0xbd, 0x0c, 0xf2, 0xbb, 0x3d, 0xcb,
	0x01, 0x91, 0xa3, 0xc9, 0x4e, 0xb6, 0x76, 0x35, 0x22, 0xec, 0x84, 0x7c, 0xe1, 0x0b, 0xb9, 0xc4,
	0xae, 0x1b, 0xf6, 0x84, 0xbf, 0x76, 0x40, 0x65, 0x6c, 0x1f, 0x2a, 0xbe, 0x01, 0x95, 0xbd, 0xaa,
	0x09, 0xf2, 0x86, 0x46, 0xb1, 0x52, 0x6b, 0x24, 0x47, 0x8f, 0x4b, 0x4d, 0x98, 0x95, 0x56, 0x42,
};

// aka _key_282c (or __rodata_282c)
uint32_t atj2127_key[] = {
	0x42146ea2, 0x892c8e85, 0x9f9f6d27, 0x545fedc3,
	0x09e5c0ca, 0x2dfa7e61, 0x4e5322e6, 0xb19185b9
};


// aka _data_3400 or __data + 400, g_crypt_key6
uint8_t data_3400[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
};

// data + 420
uint8_t data_3420[] = {
	0xa3, 0xe6, 0xfa, 0x56, 0x10, 0xc1, 0xe0, 0x56,
	0x9b, 0xeb, 0x8a, 0xf1, 0x9b, 0xcd, 0xa8, 0x27,
	0xc4, 0x67, 0x5a, 0x55, 0x0f, 0xf7, 0xb7, 0x19,
	0xe8, 0xec, 0x7d, 0x53, 0xdb, 0x01, 0x00, 0x00 /* 3440 */
};

uint8_t data_3440[] = {
	0x26, 0x61, 0xad, 0xef, 0x6e, 0x9d, 0x4c, 0x0a,
	0xf5, 0x6b, 0xc2, 0x19, 0xa4, 0x63, 0x95, 0x14,
	0xf4, 0x2f, 0xf2, 0x29, 0xf1, 0x1a, 0x73, 0x7e,
	0x3a, 0x85, 0xba, 0x32, 0x72, 0x01, 0x00, 0x00  /* 3460 */
};

// aka _data_3460 or __data + 460
uint8_t data_3460[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00 /* 3484 */
};


// aka _data_3484 or __data + 484
uint8_t data_3484[] = {
	0x20, 0xf9, 0xd7, 0x56, 0x30, 0x24, 0x55, 0xa9,
	0x7a, 0xd7, 0x25, 0xe5, 0xed, 0xf8, 0xb4, 0x36,
	0x41, 0xc5, 0x51, 0xaf
};

uint8_t firmware_signature_3498[] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x75   /* "3DUfw... */ /* 34a8 */
};

uint8_t signature_34b0[] = {
	0x3f, 0xad, 0xf8, 0xb0, 0x2e, 0xaf, 0x67, 0x49,
	0xb9, 0x85, 0x5f, 0x63, 0x4e, 0x5e, 0x8e, 0x2e
};

uint8_t signature_34ac[] = {
	0x08, 0x08, 0x00, 0x00
};

uint8_t signature_34a8[] = {
	0x08, 0x00, 0x00, 0x00
};

void func_1b1c_c(uint32_t a0, uint8_t *a1, int length, uint32_t a3);

/* 
 * In: buf: central directory block, encrypted 
*/
uint32_t func_808_c(uint8_t *buf, uint8_t *scratch1, uint8_t *scratch2, uint8_t *decrypted_ok)
{
	int idx;

	*decrypted_ok = 0;
	// Decrypt the firmware central directory block.
	if(func_b1c_c(buf + 4) != 0) {
		return 11;
	}
	*decrypted_ok = 1;

	// These are some pretty crazy memcpy / set operations. They frequently overlap.
	memcpy(scratch2, buf, 296);

	idx = 906;
	memcpy(scratch1, &buf[idx], 5);

	idx += 5;
	memset(&scratch1[8], 0, 32);

	memset(&scratch1[12], 0, 32);

	memcpy(&scratch1[8], &buf[idx], 30);

	idx += 30;
	memcpy(&scratch1[12], &buf[idx], 30);

	idx += 30;
	memcpy(&scratch1[16], &buf[idx], 16);

	idx += 33;
	memcpy(&scratch1[49], &buf[idx], 21);

	if(scratch2[286] != 1 || scratch2[287] != 0) {
		return 24;
	} else {
		return 0;
	}
}

void func_97c_c(uint8_t *encstart, int length, uint8_t *scratch)
{
	int num_chunks = (length / KEY_LENGTH);
	int remainder  = length - (num_chunks * KEY_LENGTH);
	int chunk, i;

	memset(scratch, 0, KEY_LENGTH);

	if(num_chunks > 0) {
		for(chunk = 0; chunk < num_chunks; chunk++) {
			for(i = 0; i < KEY_LENGTH; i++) {
				scratch[i] ^= encstart[i + (chunk * KEY_LENGTH)];
			}
		}
	}

	for(i = 0; i < remainder; i++) {
		scratch[i] ^= encstart[(num_chunks * KEY_LENGTH) + i];
	}

	for(i = 0; i < KEY_LENGTH; i++) {
		scratch[i] = ~scratch[i];
	}
}

int func_abc_c(uint8_t *encstart, uint8_t *kworking, int length)
{
	uint8_t scratch[KEY_LENGTH];

	func_97c_c(encstart, length, scratch);
	return (int8_t)(memcmp(scratch, kworking, KEY_LENGTH));
}

int func_b1c_c(uint8_t *enc)
{
	int i, chunk;
	uint8_t scratch[32];

	// Select a decryption key between 0 and 31
	uint8_t key_idx = enc[998] & 0x1f;

	// Load the 32-byte key
	uint8_t *key = &firmware_directory_key[key_idx * 32];

	// Calculate the first 20 bytes of a key...  # b4c
	for (i = 0; i < 20; i++) {
		uint8_t xored = enc[1000 + i] ^ key[i];

		enc[1000 + i] = xored;
		scratch[i] = xored;
	}

	// And then copy the first 16 bytes of that calculated key into the rest of the key.  # b80
	for (i = 20; i < 32; i++) {
		scratch[i] = scratch[i - 20];
	}

	// Use the calculated key to descramble the rest of the block.  #bac
	for (chunk = 0; chunk < 31; chunk++) {
		for (i = 0; i < 32; i++) {
			enc[(chunk * 32) + i] ^= (scratch[i] ^ firmware_directory_key[(chunk * 32) + i]);
		}
	}
	
	return func_abc_c(enc - 1, enc + 1000, 1001);
}

void func_c14_c(uint8_t *key, uint32_t key_length, uint8_t *out)
{
	uint32_t a1, t1, v0, v1;
	int index;

	for(index = 0; index < 256; index ++) {
		out[index] = index;
	}

	out[256] = 0;
	out[257] = 0;
	v1 = 0;
	t1 = 0;

	for(index = 0; index < 256; index ++) {
		v0 = v1 + 1;     // c54 addiu v0,v1,1
		
		a1 = out[index];
		t1 = (key[v1] + a1 + t1) & 0xff;
		out[index] = out[t1];

		out[t1] = a1;
		v1 = (v0 % key_length) & 0xff;
	}
}

void func_cac_c(uint8_t *arg1, uint32_t count, uint8_t *arg3)
{
	uint32_t t6;
	uint8_t byte1, byte2;

	byte1 = arg3[256];
	byte2 = arg3[257];

	for(int idx = 0; idx < count; idx++) {
		uint8_t temp;
		byte1++; // will wrap at 256

		temp = arg3[byte1];
		byte2 += temp;
		
		arg3[byte1] = arg3[byte2];
		arg3[byte2] = temp;

		t6 = (arg3[byte1] + temp) & 0xff;
		arg1[idx] ^= arg3[t6];
	}

	arg3[257] = byte2;
	arg3[256] = byte1;
}

void func_d2c_c(uint8_t *key, int key_length, uint32_t a2, uint32_t count, uint8_t *out)
{
	func_c14_c(key, key_length, out);     // d4c jal func_c14
	func_cac_c((uint8_t *)a2, count, out);
}

void func_d78_c(uint8_t *key, int key_length, uint32_t a2, uint32_t count, uint8_t *out)
{
	return func_d2c_c(key, key_length, a2, count, out);
}

void func_d80_c(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint8_t *out)
{
	uint8_t scratch[32];

	func_1b1c_c(a0, scratch, 32, a1);
	func_d2c_c(scratch, 32, a2, a3, out);
}

/* a1 is a flag: zero or one */
int32_t func_dd8_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, a3, t0, v0, v1, zero;
	zero = 0;

	v0 = 1;     // dd8 li v0,1
	a3 = zero;     // ddc move a3,zero
	if(a1 == v0) {
		a1 = 7 << 0x2;     // e14 li v1,7
		a2 = 7;     // e1c li a2,7
	} else {
		a1 = 15 << 0x2;     // de0 li v1,15
		a2 = 15;     // de8 li a2,15
	};     // de4 beq a1,v0,3604

	v0 = a1 + a0;     // df0 addu v0,a1,a0
	v1 = *((uint32_t *)(v0 + 0));     // df4 lw v1,0(v0)

	__df8:
	v0 = v0 + -4;     // dfc addiu v0,v0,-4
	if(v1 != 0) {
		goto __e20;
	}

	a2 = a2 + -1;     // e00 addiu a2,a2,-1
	if(a2 >= 0) {
		v1 = *((uint32_t *)(v0 + 0));     // e08 lw v1,0(v0)
		goto __df8;
	} else {
		return a3;
	}

	__e20:
	a0 = v1;     // e20 move a0,v1
	a3 = a2 << 0x5;     // e24 sll a3,a2,0x5
	v1 = 31;     // e28 li v1,31
	a1 = 1;     // e30 li a1,1
	goto __e3c;     // e2c b 3644

	__e34:
	if(v1 < 0) {
		return a3;
	}

	__e3c:
	t0 = a1 << v1;     // e3c sllv t0,a1,v1
	a2 = a0 & t0;     // e40 and a2,a0,t0
	if(a2 == 0) {
		v1 = v1 + -1;     // e48 addiu v1,v1,-1
		goto __e34;
	} ;     // e44 beqzl a2,3636

	a3 = a3 + v1;     // e4c addu a3,a3,v1
	v0 = a3;     // e54 move v0,a3
	return v0;     // e50 jr ra
}

uint32_t func_e58_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, a3, t0, t1, v0, v1, zero;
	zero = 0;

	//__e58:
	a1 = a1 + 28;     // e58 addiu a1,a1,28
	a0 = a0 + 28;     // e5c addiu a0,a0,28
	t0 = zero;     // e60 move t0,zero
	a3 = 7;     // e64 li a3,7
	v1 = *((uint32_t *)(a0 + 0));     // e68 lw v1,0(a0)

	__e6c:
	t1 = *((uint32_t *)(a1 + 0));     // e6c lw t1,0(a1)
	a3 = a3 + -1;     // e70 addiu a3,a3,-1
	v0 = t1 < v1;     // e74 sltu v0,t1,v1
	a2 = v1 < t1;     // e78 sltu a2,v1,t1
	a0 = a0 + -4;     // e7c addiu a0,a0,-4
	if(v0 != 0) {
		a1 = a1 + -4;     // e84 addiu a1,a1,-4
		goto __ea0;
	} else {
		a1 = a1 + -4;     // e84 addiu a1,a1,-4
	};     // e80 bnez v0,3744

	//__e88:
	if(a2 != 0) {
		t0 = -1;     // e8c li t0,-1
		goto __eac;
	} ;     // e88 bnezl a2,3756

	//__e90:
	if(a3 >= 0) {
		v1 = *((uint32_t *)(a0 + 0));     // e94 lw v1,0(a0)
		goto __e6c;
	} ;     // e90 bgezl a3,3692

	//__e98:
	v0 = t0;     // e9c move v0,t0
	return v0;     // e98 jr ra

	__ea0:
	t0 = 1;     // ea0 li t0,1
	v0 = t0;     // ea8 move v0,t0
	return v0;     // ea4 jr ra

	__eac:
	v0 = t0;     // eb0 move v0,t0
	return v0;     
}

// this is func_eb4_c
void copy_32_bytes(uint32_t *dst, uint32_t *src)
{
	uint32_t count = 8;

	while(count--) {
		*dst++ = *src++;
	}
}

// this is func_ed8_c
void clear_memory(uint32_t *dst, int words)
{
	while(words--) {
		*dst++ = 0;
	}
}

// this is func_ef8_c
void xor_64_bytes(uint32_t *dst, uint32_t *src1, uint32_t *src2)
{
	int count = 16;

	while(count--) {
		*dst++ = *src1++ ^ *src2++;
	}
}

void func_f28_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, a3, t0, t1, t2, v0, v1, zero;
	zero = 0;

	//__f28:
	t1 = a0;     // f28 move t1,a0
	t0 = a1;     // f2c move t0,a1
	a3 = zero;     // f30 move a3,zero

	__f34:
	t2 = a3 << 0x2;     // f34 sll t2,a3,0x2
	a2 = t2 + t0;     // f38 addu a2,t2,t0
	v0 = t2 + t1;     // f3c addu v0,t2,t1
	a1 = *((uint32_t *)(v0 + 0));     // f40 lw a1,0(v0)
	v1 = *((uint32_t *)(a2 + 0));     // f44 lw v1,0(a2)
	a3 = a3 + 1;     // f48 addiu a3,a3,1
	a0 = (a3 < 8);     // f4c slti a0,a3,8
	*((uint32_t *)(v0 + 0)) = v1;     // f50 sw v1,0(v0)
	if(a0 != 0) {
		*((uint32_t *)(a2 + 0)) = a1;     // f58 sw a1,0(a2)
		goto __f34;
	} else {
		*((uint32_t *)(a2 + 0)) = a1;     // f58 sw a1,0(a2)
	};     // f54 bnez a0,3892

}

void func_f64_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, a3, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, v0, v1, zero;
	zero = 0;

	t2 = (a1 < 0);     // f64 slti t2,a1,0
	t0 = a1 + 31;     // f68 addiu t0,a1,31
	if(t2 == 0) {
		t0 = a1;
	};     // f6c movz t0,a1,t2
	t1 = t0 >> 0x5;     // f70 sra t1,t0,0x5
	t2 = t1;     // f74 move t2,t1
	a3 = t1 << 0x5;     // f78 sll a3,t1,0x5
	t1 = a1 - a3;     // f7c subu t1,a1,a3
	a2 = 1;     // f80 li a2,1
	a1 = t2 << 0x2;     // f84 sll a1,t2,0x2
	v0 = a2 << t1;     // f88 sllv v0,a2,t1
	v1 = a1 + a0;     // f8c addu v1,a1,a0
	t3 = v0 + -1;     // f90 addiu t3,v0,-1
	v1 = v1 + 28;     // f94 addiu v1,v1,28
	a2 = 7;     // f98 li a2,7
	a1 = a0 + 28;     // f9c addiu a1,a0,28

	__fa0:
	t4 = *((uint32_t *)(a1 + 0));     // fa0 lw t4,0(a1)
	a2 = a2 + -1;     // fa4 addiu a2,a2,-1
	*((uint32_t *)(v1 + 0)) = t4;     // fa8 sw t4,0(v1)
	a1 = a1 + -4;     // fac addiu a1,a1,-4
	if((a2 & (1 << 31)) == 0) {
		v1 = v1 + -4;     // fb4 addiu v1,v1,-4
		goto __fa0;
	} else {
		v1 = v1 + -4;     // fb4 addiu v1,v1,-4
	};     // fb0 bgez a2,4000

	if(((t2 & (1 << 31)) != 0) || t2 == 0) {
		t5 = 32;     // fbc li t5,32
		goto __fdc;
	} else {
		t5 = 32;     // fbc li t5,32
	};     // fb8 blez t2,4060

	v1 = a0;     // fc0 move v1,a0
	v0 = t2;     // fc4 move v0,t2

	__fc8:
	v0 = v0 + -1;     // fc8 addiu v0,v0,-1
	*((uint32_t *)(v1 + 0)) = zero;     // fcc sw zero,0(v1)
	if(v0 != 0) {
		v1 = v1 + 4;     // fd4 addiu v1,v1,4
		goto __fc8;
	} else {
		v1 = v1 + 4;     // fd4 addiu v1,v1,4
	};     // fd0 bnez v0,4040

	t5 = 32;     // fd8 li t5,32

	__fdc:
	t4 = t2 + 8;     // fdc addiu t4,t2,8
	t0 = t5 - t1;     // fe0 subu t0,t5,t1
	if(((t4 & (1 << 31)) != 0) || t4 == 0) {
		a3 = zero;     // fe8 move a3,zero
		goto __1028;
	} else {
		a3 = zero;     // fe8 move a3,zero
	};     // fe4 blez t4,4136

	a2 = t4;     // fec move a2,t4
	a1 = a0;     // ff0 move a1,a0

	__ff4:
	t8 = *((uint32_t *)(a1 + 0));     // ff4 lw t8,0(a1)
	a2 = a2 + -1;     // ff8 addiu a2,a2,-1
	t9 = t8 << t1;     // ffc sllv t9,t8,t1
	t7 = t9 | a3;     // 1000 or t7,t9,a3
	t6 = t8 >> t0;     // 1004 srlv t6,t8,t0
	*((uint32_t *)(a1 + 0)) = t7;     // 1008 sw t7,0(a1)
	a3 = t6 & t3;     // 100c and a3,t6,t3
	if(a2 != 0) {
		a1 = a1 + 4;     // 1014 addiu a1,a1,4
		goto __ff4;
	} else {
		a1 = a1 + 4;     // 1014 addiu a1,a1,4
	};     // 1010 bnez a2,4084

	if(a3 == 0) {
		v1 = t4 << 0x2;     // 101c sll v1,t4,0x2
		goto __1028;
	} else {
		v1 = t4 << 0x2;     // 101c sll v1,t4,0x2
	};     // 1018 beqz a3,4136

	t3 = v1 + a0;     // 1020 addu t3,v1,a0
	*((uint32_t *)(t3 + 0)) = a3;     // 1024 sw a3,0(t3)

	__1028:
	return;
}

void func_1030_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, s0, s1, s2, s3, s4, s5, v0;

	s1 = (uint32_t)__bss + 0x320;     // 103c la s1,__bss + 0x320
	s4 = a0;     // 1048 move s4,a0
	s0 = a1;     // 104c move s0,a1
	a0 = s1;     // 1050 move a0,s1
	a1 = 16;     // 1054 li a1,16
	clear_memory((void *)a0, a1);
	a0 = s4;     // 106c move a0,s4
	a1 = 8;     // 1074 li a1,8
	clear_memory((void *)a0, a1);
	a2 = (0xbfc3) << 16;     // 1078 lui a2,0xbfc3
	s5 = (uint32_t)__bss + 0x10a0;     // 107c la s5,__bss + 0x10a0
	a0 = 1;     // 1080 li a0,1
	*((uint32_t *)(s4 + 0)) = a0;     // 1084 sw a0,0(s4)
	a1 = 8;     // 1088 li a1,8
	a0 = s5;     // 1090 move a0,s5
	clear_memory((void *)a0, a1);
	s2 = (uint32_t)__bss + 0x20;     // 1098 la s2,__bss + 0x20
	a1 = s0;     // 109c move a1,s0
	a0 = s2;     // 10a4 move a0,s2
	copy_32_bytes((void *)a0, (void *)a1);
	v0 = (0xbfc3) << 16;     // 10a8 lui v0,0xbfc3
	s3 = (uint32_t)__bss + 0x8a0;     // 10ac la s3,__bss + 0x8a0
	a1 = (0xbfc3) << 16;     // 10b0 lui a1,0xbfc3
	a1 = (uint32_t)data_3400;     // 10b4 la a1,__data + 0x400
	a0 = s3;     // 10bc move a0,s3
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = s2;     // 10c4 move a0,s2
	goto __1138;     // 10c0 b 4408

	__10c8:
	a0 = s3;     // 10c8 move a0,s3
	a1 = 1;     // 10d0 li a1,1
	s0 = s0 - func_dd8_c(a0, a1);     // 10d4 subu s0,s0,v0
	a0 = s2;     // 10d8 move a0,s2
	if(((s0 & (1 << 31)) != 0)) {
		a1 = s3;     // 10e0 move a1,s3
		goto __116c;
	} else {
		a1 = s3;     // 10e0 move a1,s3
	};     // 10dc bltz s0,4460

	a0 = s1;     // 10e4 move a0,s1

	__10e8:
	a1 = s3;     // 10ec move a1,s3
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = s1;     // 10f0 move a0,s1
	a1 = s0;     // 10f8 move a1,s0
	func_f64_c(a0, a1);
	a2 = s1;     // 10fc move a2,s1
	a0 = s2;     // 1100 move a0,s2
	a1 = s2;     // 1108 move a1,s2
	xor_64_bytes((void *)a0, (void *)a1, (void *)a2);
	a0 = s1;     // 110c move a0,s1
	a1 = s5;     // 1114 move a1,s5
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = s1;     // 1118 move a0,s1
	a1 = s0;     // 1120 move a1,s0
	func_f64_c(a0, a1);
	a0 = s4;     // 1124 move a0,s4
	a1 = s4;     // 1128 move a1,s4
	a2 = s1;     // 1130 move a2,s1
	xor_64_bytes((void *)a0, (void *)a1, (void *)a2);
	a0 = s2;     // 1134 move a0,s2

	__1138:
	a1 = 1;     // 113c li a1,1
	v0 = func_dd8_c(a0, a1);
	if(v0 != 0) {
		s0 = v0;     // 1144 move s0,v0
		goto __10c8;
	} else {
		s0 = v0;     // 1144 move s0,v0
	};     // 1140 bnez v0,4296

	return;     // 1164 jr ra

	__116c:
	s0 = -s0;     // 1170 negu s0,s0
	func_f28_c(a0, a1);     // 116c jal func_f28
	a0 = s4;     // 1174 move a0,s4
	a1 = s5;     // 117c move a1,s5
	func_f28_c(a0, a1);     // 1178 jal func_f28
	a0 = s1;     // 1184 move a0,s1
	goto __10e8;     // 1180 b 4328
}

void func_1188_c(uint32_t a0)
{
	uint32_t a1, a2, a3, s0, t0, t1, t2, t3, v0, v1, zero;
	zero = 0;

	a1 = zero;     // 118c move a1,zero
	s0 = a0;     // 119c move s0,a0
	v0 = func_dd8_c(a0, a1);
	a0 = v0 + 31;     // 11a0 addiu a0,v0,31
	v1 = (((int32_t)v0) < 0);     // 11a4 slti v1,v0,0
	if(v1 != 0) {
		v0 = a0;
	};     // 11a8 movn v0,a0,v1
	v0 = v0 >> 0x5;     // 11ac sra v0,v0,0x5
	a3 = v0 + 1;     // 11b0 addiu a3,v0,1
	if(((a3 & (1 << 31)) != 0) || a3 == 0) {
		a2 = zero;     // 11b8 move a2,zero
		goto __11fc;
	} else {
		a2 = zero;     // 11b8 move a2,zero
	};     // 11b4 blez a3,4600

	a1 = a3;     // 11bc move a1,a3
	a0 = s0;     // 11c0 move a0,s0

	__11c4:
	t0 = *((uint32_t *)(a0 + 0));     // 11c4 lw t0,0(a0)
	a1 = a1 + -1;     // 11c8 addiu a1,a1,-1
	t2 = t0 << 0x1;     // 11cc sll t2,t0,0x1
	t1 = t2 | a2;     // 11d0 or t1,t2,a2
	*((uint32_t *)(a0 + 0)) = t1;     // 11d4 sw t1,0(a0)
	a2 = t0 >> 0x1f;     // 11d8 srl a2,t0,0x1f
	if(a1 != 0) {
		a0 = a0 + 4;     // 11e0 addiu a0,a0,4
		goto __11c4;
	} else {
		a0 = a0 + 4;     // 11e0 addiu a0,a0,4
	};     // 11dc bnez a1,4548

	if(a2 == 0) {
		goto __11fc;
	}

	t3 = a3 << 0x2;     // 11ec sll t3,a3,0x2
	a1 = t3 + s0;     // 11f0 addu a1,t3,s0
	*((uint32_t *)(a1 + 0)) = a2;     // 11f4 sw a2,0(a1)

	__11fc:
	return;     // 1200 jr ra
}

void func_1208_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t s0, s1, s2, s3, v0, zero;
	zero = 0;

	a0 = a1;     // 120c move a0,a1
	s2 = a1;     // 1214 move s2,a1
	a1 = zero;     // 1218 move a1,zero
	s3 = a2;     // 1224 move s3,a2
	v0 = func_dd8_c(a0, a1);     // 122c jal func_dd8
	s0 = v0 + -233;     // 1234 addiu s0,v0,-233
	a0 = s2;     // 1238 move a0,s2
	a1 = s3;     // 1240 move a1,s3
	func_e58_c(a0, a1);     // 123c jal func_e58
	if(((s0 & (1 << 31)) != 0)) {
		goto __129c;
	}

	s1 = (uint32_t)__bss + 0xc20;     // 124c la s1,__bss + 0xc20
	a0 = s1;     // 1250 move a0,s1

	__1254:
	a1 = 16;     // 1258 li a1,16
	clear_memory((void *)a0, a1);     // 1254 jal func_ed8
	a0 = s1;     // 125c move a0,s1
	a1 = s3;     // 1264 move a1,s3
	copy_32_bytes((void *)a0, (void *)a1);     // 1260 jal func_eb4
	a1 = s0;     // 1268 move a1,s0
	a0 = s1;     // 1270 move a0,s1
	func_f64_c(a0, a1);     // 126c jal func_f64
	a0 = s2;     // 1274 move a0,s2
	a1 = s2;     // 1278 move a1,s2
	a2 = s1;     // 1280 move a2,s1
	xor_64_bytes((void *)a0, (void *)a1, (void *)a2);     // 127c jal func_ef8
	a0 = s2;     // 1284 move a0,s2
	a1 = zero;     // 128c move a1,zero
	v0 = func_dd8_c(a0, a1);     // 1288 jal func_dd8
	s0 = v0 + -233;     // 1290 addiu s0,v0,-233
	if((s0 & (1 << 31)) == 0) {
		a0 = s1;     // 1298 move a0,s1
		goto __1254;
	} else {
		a0 = s1;     // 1298 move a0,s1
	};     // 1294 bgez s0,4692

	__129c:
	return;     // 12b0 jr ra
}

void func_12b8_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t a3, s0, s1, s2, s3, s4, t0, t1, t2, t3, t4, t5, t6, v0, zero;
	zero = 0;

	s4 = (uint32_t)__bss + 0x1220;     // 12c4 la s4,__bss + 0x1220
	s3 = a0;     // 12d0 move s3,a0
	s0 = a1;     // 12d4 move s0,a1
	a0 = s4;     // 12d8 move a0,s4
	a1 = 8;     // 12dc li a1,8
	s1 = a2;     // 12f0 move s1,a2
	clear_memory((void *)a0, a1);
	v0 = (0xbfc3) << 16;     // 12f4 lui v0,0xbfc3
	s2 = (uint32_t)__bss + 0x420;     // 12f8 la s2,__bss + 0x420
	a0 = s2;     // 12fc move a0,s2
	a1 = 16;     // 1304 li a1,16
	clear_memory((void *)a0, a1);
	a1 = s0;     // 1308 move a1,s0
	a0 = s4;     // 1310 move a0,s4
	copy_32_bytes((void *)a0, (void *)a1);
	a1 = s1;     // 1314 move a1,s1
	a0 = s2;     // 131c move a0,s2
	copy_32_bytes((void *)a0, (void *)a1);
	s0 = 1;     // 1320 li s0,1
	t3 = 8;     // 1324 li t3,8
	s1 = zero;     // 1328 move s1,zero
	t2 = (((int32_t)zero) < ((int32_t)t3));     // 132c slt t2,zero,t3

	__1330:
	t0 = s4;     // 1330 move t0,s4
	a3 = 7;     // 1334 li a3,7
	t1 = zero;     // 1338 move t1,zero

	__133c:
	a1 = *((uint32_t *)(t0 + 0));     // 133c lw a1,0(t0)
	a0 = a1 & s0;     // 1340 and a0,a1,s0
	if(a0 == 0) {
		a3 = a3 + -1;     // 1348 addiu a3,a3,-1
		goto __1384;
	} ;     // 1344 beqzl a0,4996

	if(t2 == 0) {
		a3 = a3 + -1;     // 1350 addiu a3,a3,-1
		goto __1384;
	} ;     // 134c beqzl t2,4996

	a2 = s2;     // 1354 move a2,s2
	a0 = t1 + s3;     // 1358 addu a0,t1,s3
	a1 = t3;     // 135c move a1,t3

	__1360:
	t5 = *((uint32_t *)(a0 + 0));     // 1360 lw t5,0(a0)
	t6 = *((uint32_t *)(a2 + 0));     // 1364 lw t6,0(a2)
	a1 = a1 + -1;     // 1368 addiu a1,a1,-1
	t4 = t5 ^ t6;     // 136c xor t4,t5,t6
	*((uint32_t *)(a0 + 0)) = t4;     // 1370 sw t4,0(a0)
	a2 = a2 + 4;     // 1374 addiu a2,a2,4
	if(a1 != 0) {
		a0 = a0 + 4;     // 137c addiu a0,a0,4
		goto __1360;
	} else {
		a0 = a0 + 4;     // 137c addiu a0,a0,4
	};     // 1378 bnez a1,4960

	a3 = a3 + -1;     // 1380 addiu a3,a3,-1

	__1384:
	t0 = t0 + 4;     // 1384 addiu t0,t0,4
	if((a3 & (1 << 31)) == 0) {
		t1 = t1 + 4;     // 138c addiu t1,t1,4
		goto __133c;
	} else {
		t1 = t1 + 4;     // 138c addiu t1,t1,4
	};     // 1388 bgez a3,4924

	a2 = 31;     // 1390 li a2,31
	if(s1 == a2) {
		s1 = s1 + 1;     // 1398 addiu s1,s1,1
		goto __13cc;
	} ;     // 1394 beql s1,a2,5068

	a0 = s2;     // 13a0 move a0,s2
	func_1188_c(a0);     // 139c jal func_1188
	a0 = s2;     // 13a4 move a0,s2
	a1 = zero;     // 13ac move a1,zero
	v0 = func_dd8_c(a0, a1);     // 13a8 jal func_dd8
	t0 = v0 + 31;     // 13b0 addiu t0,v0,31
	t1 = (((int32_t)v0) < 0);     // 13b4 slti t1,v0,0
	if(t1 != 0) {
		v0 = t0;
	};     // 13b8 movn v0,t0,t1
	a3 = v0 >> 0x5;     // 13bc sra a3,v0,0x5
	s0 = s0 << 0x1;     // 13c0 sll s0,s0,0x1
	t3 = a3 + 1;     // 13c4 addiu t3,a3,1
	s1 = s1 + 1;     // 13c8 addiu s1,s1,1

	__13cc:
	t2 = (((int32_t)s1) < 32);     // 13cc slti t2,s1,32
	if(t2 != 0) {
		t2 = (((int32_t)zero) < ((int32_t)t3));     // 13d4 slt t2,zero,t3
		goto __1330;
	} ;     // 13d0 bnezl t2,4912

	return;     // 13f0 jr ra
}

/* this xors 8 words from a1 and a2 and stores the result in a0 */
void func_13f8_c(uint32_t *out, uint32_t *in_1, uint32_t *in_2)
{
	for(int i = 0; i < 8; i++) {
		*out++ = *in_1++ ^ *in_2++;
	}
}

void func_1428_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, a3, t0, t1, t2, t3, t4, t5, t6, v0, v1, zero;
	zero = 0;

	t0 = a0;     // 1428 move t0,a0
	t1 = *((uint32_t *)(a1 + 4));     // 142c lw t1,4(a1)
	a3 = zero;     // 1430 move a3,zero
	a2 = *((uint32_t *)(a1 + 0));     // 1434 lw a2,0(a1)

	__1438:
	a1 = t0 + a3;     // 1438 addu a1,t0,a3
	v1 = *((uint8_t*)(0 + a2));     // 143c lbu v1,0(a2)
	t2 = *((uint8_t*)(0 + a1));     // 1440 lbu t2,0(a1)
	a3 = a3 + 1;     // 1444 addiu a3,a3,1
	v0 = t2 ^ v1;     // 1448 xor v0,t2,v1
	a0 = (((int32_t)a3) < 29);     // 144c slti a0,a3,29
	*((uint8_t *)(a1 + 0)) = (v0 & 0xff);     // 1450 sb v0,0(a1)
	if(a0 != 0) {
		a2 = a2 + 1;     // 1458 addiu a2,a2,1
		goto __1438;
	} else {
		a2 = a2 + 1;     // 1458 addiu a2,a2,1
	};     // 1454 bnez a0,5176

	a2 = t1;     // 145c move a2,t1
	a3 = 29;     // 1460 li a3,29

	__1464:
	t3 = t0 + a3;     // 1464 addu t3,t0,a3
	t6 = *((uint8_t*)(0 + a2));     // 1468 lbu t6,0(a2)
	t5 = *((uint8_t*)(0 + t3));     // 146c lbu t5,0(t3)
	a3 = a3 + 1;     // 1470 addiu a3,a3,1
	t4 = t5 ^ t6;     // 1474 xor t4,t5,t6
	t1 = (((int32_t)a3) < 32);     // 1478 slti t1,a3,32
	*((uint8_t *)(t3 + 0)) = (t4 & 0xff);     // 147c sb t4,0(t3)
	if(t1 != 0) {
		a2 = a2 + 1;     // 1484 addiu a2,a2,1
		goto __1464;
	} else {
		a2 = a2 + 1;     // 1484 addiu a2,a2,1
	};     // 1480 bnez t1,5220

	return;     // 1488 jr rao
}

void func_1490_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t s0, s1, s2, s3, s4, s5, s6, s7;

	s7 = a0;     // 14b8 move s7,a0
	a0 = *((uint32_t *)(a2 + 0));     // 14bc lw a0,0(a2)
	s6 = a2;     // 14c0 move s6,a2
	s5 = a1;     // 14c4 move s5,a1
	a1 = 8;     // 14cc li a1,8
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(s6 + 4));     // 14d0 lw a0,4(s6)
	a1 = 8;     // 14d8 li a1,8
	clear_memory((void *)a0, a1);
	s2 = (uint32_t)__bss + 0x120;     // 14e0 la s2,__bss + 0x120
	a0 = s2;     // 14e4 move a0,s2
	a1 = 16;     // 14ec li a1,16
	clear_memory((void *)a0, a1);
	s1 = (uint32_t)__bss + 0xe20;     // 14f4 la s1,__bss + 0xe20
	a0 = s1;     // 14f8 move a0,s1
	a1 = 16;     // 1500 li a1,16
	clear_memory((void *)a0, a1);
	a1 = (0xbfc3) << 16;     // 1504 lui a1,0xbfc3
	s3 = (uint32_t)__bss + 0x520;     // 1508 la s3,__bss + 0x520
	a2 = *((uint32_t *)(s5 + 4));     // 150c lw a2,4(s5)
	a1 = *((uint32_t *)(s7 + 4));     // 1510 lw a1,4(s7)
	a0 = s3;     // 1518 move a0,s3
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a0 = (0xbfc3) << 16;     // 151c lui a0,0xbfc3
	s4 = (uint32_t)__bss + 0x620;     // 1520 la s4,__bss + 0x620
	a2 = *((uint32_t *)(s5 + 0));     // 1524 lw a2,0(s5)
	a1 = *((uint32_t *)(s7 + 0));     // 1528 lw a1,0(s7)
	a0 = s4;     // 1530 move a0,s4
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a0 = s1;     // 1534 move a0,s1
	a1 = s4;     // 153c move a1,s4
	func_1030_c(a0, a1);
	s0 = (uint32_t)__bss + 0xd20;     // 1544 la s0,__bss + 0xd20
	a0 = s0;     // 1548 move a0,s0
	a1 = 16;     // 1550 li a1,16
	clear_memory((void *)a0, a1);
	a0 = s0;     // 1554 move a0,s0
	a1 = s1;     // 1558 move a1,s1
	a2 = s3;     // 1560 move a2,s3
	func_12b8_c(a0, a1, a2);
	s5 = (uint32_t)data_3400;     // 1568 la s5,__data + 0x400
	a0 = s0;     // 156c move a0,s0
	a1 = s0;     // 1570 move a1,s0
	a2 = s5;     // 1578 move a2,s5
	func_1208_c(a0, a1, a2);
	a2 = (0xbfc3) << 16;     // 157c lui a2,0xbfc3
	a2 = (uint32_t)__bss + 0x0;     // 1580 la a2,__bss + 0x0
	a0 = s3;     // 1584 move a0,s3
	a1 = s0;     // 158c move a1,s0
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a0 = s2;     // 1590 move a0,s2
	a1 = 16;     // 1598 li a1,16
	clear_memory((void *)a0, a1);
	a0 = s2;     // 159c move a0,s2
	a1 = s0;     // 15a0 move a1,s0
	a2 = s0;     // 15a8 move a2,s0
	func_12b8_c(a0, a1, a2);
	a0 = s2;     // 15ac move a0,s2
	a1 = s2;     // 15b0 move a1,s2
	a2 = s5;     // 15b8 move a2,s5
	func_1208_c(a0, a1, a2);
	a0 = s1;     // 15bc move a0,s1
	a1 = s3;     // 15c0 move a1,s3
	a2 = s2;     // 15c8 move a2,s2
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a0 = *((uint32_t *)(s6 + 0));     // 15cc lw a0,0(s6)
	a1 = s1;     // 15d0 move a1,s1
	a2 = s4;     // 15d8 move a2,s4
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a1 = *((uint32_t *)(s7 + 0));     // 15dc lw a1,0(s7)
	a2 = *((uint32_t *)(s6 + 0));     // 15e0 lw a2,0(s6)
	a0 = s3;     // 15e8 move a0,s3
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a2 = *((uint32_t *)(s7 + 4));     // 15ec lw a2,4(s7)
	a1 = *((uint32_t *)(s6 + 0));     // 15f0 lw a1,0(s6)
	a0 = s4;     // 15f8 move a0,s4
	func_13f8_c((uint32_t *)a0, (uint32_t *)a1, (uint32_t *) a2);
	a0 = s1;     // 15fc move a0,s1
	a1 = 16;     // 1604 li a1,16
	clear_memory((void *)a0, a1);
	a0 = s1;     // 1608 move a0,s1
	a1 = s3;     // 160c move a1,s3
	a2 = s0;     // 1614 move a2,s0
	func_12b8_c(a0, a1, a2);
	a0 = s1;     // 1618 move a0,s1
	a1 = s1;     // 161c move a1,s1
	a2 = s5;     // 1624 move a2,s5
	func_1208_c(a0, a1, a2);
	a0 = *((uint32_t *)(s6 + 4));     // 1628 lw a0,4(s6)
	a1 = s1;     // 162c move a1,s1
	a2 = s4;     // 1630 move a2,s4

	/* *a0 = *a1 ^ *a2  (for 32 bytes) */
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
}

void func_1660_c(uint32_t a0, uint32_t a1)
{
	uint32_t a2, s0, s1, s2, s3, s4, s5, s6, s7;

	s7 = a0;     // 1688 move s7,a0
	a0 = *((uint32_t *)(a1 + 0));     // 168c lw a0,0(a1)
	s6 = a1;     // 1690 move s6,a1
	a1 = 8;     // 1698 li a1,8
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(s6 + 4));     // 169c lw a0,4(s6)
	a1 = 8;     // 16a4 li a1,8
	clear_memory((void *)a0, a1);
	s3 = (uint32_t)__bss + 0x720;     // 16ac la s3,__bss + 0x720
	a0 = s3;     // 16b0 move a0,s3
	a1 = 16;     // 16b8 li a1,16
	clear_memory((void *)a0, a1);
	s4 = (uint32_t)__bss + 0xfa0;     // 16c0 la s4,__bss + 0xfa0
	a0 = s4;     // 16c4 move a0,s4
	a1 = 16;     // 16cc li a1,16
	clear_memory((void *)a0, a1);
	s2 = (uint32_t)__bss + 0xb20;     // 16d4 la s2,__bss + 0xb20
	a0 = s2;     // 16d8 move a0,s2
	a1 = 16;     // 16e0 li a1,16
	clear_memory((void *)a0, a1);
	a1 = *((uint32_t *)(s7 + 0));     // 16e4 lw a1,0(s7)
	a0 = s2;     // 16ec move a0,s2
	func_1030_c(a0, a1);
	a1 = (0xbfc3) << 16;     // 16f0 lui a1,0xbfc3
	s1 = (uint32_t)__bss + 0x9a0;     // 16f4 la s1,__bss + 0x9a0
	a0 = s1;     // 16f8 move a0,s1
	a1 = 16;     // 1700 li a1,16
	clear_memory((void *)a0, a1);
	a2 = *((uint32_t *)(s7 + 4));     // 1704 lw a2,4(s7)
	a0 = s1;     // 1708 move a0,s1
	a1 = s2;     // 1710 move a1,s2
	func_12b8_c(a0, a1, a2);
	a0 = (0xbfc3) << 16;     // 1714 lui a0,0xbfc3
	s5 = (uint32_t)data_3400;     // 1718 la s5,__data + 0x400
	a1 = s1;     // 171c move a1,s1
	a0 = s1;     // 1720 move a0,s1
	a2 = s5;     // 1728 move a2,s5
	func_1208_c(a0, a1, a2);
	s0 = (uint32_t)__bss + 0x220;     // 1730 la s0,__bss + 0x220
	a1 = *((uint32_t *)(s7 + 0));     // 1734 lw a1,0(s7)
	a0 = s0;     // 1738 move a0,s0
	a2 = s1;     // 1740 move a2,s1
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
	a2 = (uint32_t)__bss + 0x0;     // 1748 la a2,__bss + 0x0
	a0 = s2;     // 174c move a0,s2
	a1 = s0;     // 1754 move a1,s0
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
	a0 = s3;     // 1758 move a0,s3
	a1 = 16;     // 1760 li a1,16
	clear_memory((void *)a0, a1);
	a0 = s3;     // 1764 move a0,s3
	a1 = s0;     // 1768 move a1,s0
	a2 = s0;     // 1770 move a2,s0
	func_12b8_c(a0, a1, a2);
	a0 = s3;     // 1774 move a0,s3
	a1 = s3;     // 1778 move a1,s3
	a2 = s5;     // 1780 move a2,s5
	func_1208_c(a0, a1, a2);
	a0 = *((uint32_t *)(s6 + 0));     // 1784 lw a0,0(s6)
	a2 = s3;     // 1788 move a2,s3
	a1 = s2;     // 1790 move a1,s2
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
	a0 = s1;     // 1794 move a0,s1
	a1 = 16;     // 179c li a1,16
	clear_memory((void *)a0, a1);
	a2 = (0xbfc3) << 16;     // 17a0 lui a2,0xbfc3
	a1 = s0;     // 17a4 move a1,s0
	a0 = s2;     // 17a8 move a0,s2
	a2 = (uint32_t)data_3460;     // 17ac la a2,__data + 0x460
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
	a2 = *((uint32_t *)(s6 + 0));     // 17b4 lw a2,0(s6)
	a0 = s1;     // 17b8 move a0,s1
	a1 = s2;     // 17c0 move a1,s2
	func_12b8_c(a0, a1, a2);
	a2 = s5;     // 17c4 move a2,s5
	a0 = s1;     // 17c8 move a0,s1
	a1 = s1;     // 17d0 move a1,s1
	func_1208_c(a0, a1, a2);
	a0 = s4;     // 17d4 move a0,s4
	a1 = 16;     // 17dc li a1,16
	clear_memory((void *)a0, a1);
	a1 = *((uint32_t *)(s7 + 0));     // 17e0 lw a1,0(s7)
	a0 = s4;     // 17e4 move a0,s4
	a2 = a1;     // 17ec move a2,a1
	func_12b8_c(a0, a1, a2);
	a0 = s4;     // 17f0 move a0,s4
	a1 = s4;     // 17f4 move a1,s4
	a2 = s5;     // 17fc move a2,s5
	func_1208_c(a0, a1, a2);
	a0 = *((uint32_t *)(s6 + 4));     // 1800 lw a0,4(s6)
	a1 = s1;     // 1804 move a1,s1
	a2 = s4;     // 1808 move a2,s4
	func_13f8_c((void *)a0, (void *)a1, (void *)a2);
}

int func_1838_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t a3, ra, s0, s1, s2, s3, s4, s5, sp, t0, t1, t3, t5, t6, t7, t8, t9, v0, v1;
	uint32_t stack[14];
	sp = (uint32_t)stack;

	s4 = a0;     // 1860 move s4,a0
	a0 = *((uint32_t *)(a2 + 0));     // 1864 lw a0,0(a2)
	s1 = a2;     // 1868 move s1,a2
	t3 = (uint32_t)__bss + 0x820;     // 186c la t3,__bss + 0x820
	t1 = (uint32_t)__bss + 0xaa0;     // 1870 la t1,__bss + 0xaa0
	s3 = a1;     // 1874 move s3,a1
	a1 = 8;     // 1878 li a1,8
	*((uint32_t *)(sp + 16)) = t3;     // 187c sw t3,16(sp)
	*((uint32_t *)(sp + 20)) = t1;     // 1884 sw t1,20(sp)
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(s1 + 4));     // 1888 lw a0,4(s1)
	a1 = 8;     // 1890 li a1,8
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(sp + 16));     // 1894 lw a0,16(sp)
	a1 = 8;     // 189c li a1,8
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(sp + 20));     // 18a0 lw a0,20(sp)
	a1 = 8;     // 18a8 li a1,8
	clear_memory((void *)a0, a1);
	a0 = s4;     // 18ac move a0,s4
	a1 = 1;     // 18b4 li a1,1
	v0 = func_dd8_c(a0, a1);
	a1 = (((int32_t)v0) < 0);     // 18b8 slti a1,v0,0
	a0 = v0 + 31;     // 18bc addiu a0,v0,31
	if(a1 == 0) {
		a0 = v0;
	};     // 18c0 movz a0,v0,a1
	a3 = v0;     // 18c4 move a3,v0
	v0 = a0 >> 0x5;     // 18c8 sra v0,a0,0x5
	t0 = v0 << 0x2;     // 18cc sll t0,v0,0x2
	a0 = *((uint32_t *)(sp + 16));     // 18d0 lw a0,16(sp)
	a1 = *((uint32_t *)(s3 + 0));     // 18d4 lw a1,0(s3)
	a2 = t0 + s4;     // 18d8 addu a2,t0,s4
	v1 = v0 << 0x5;     // 18dc sll v1,v0,0x5
	s0 = a3 - v1;     // 18e0 subu s0,a3,v1
	s2 = *((uint32_t *)(a2 + 0));     // 18e4 lw s2,0(a2)
	s5 = v0 + -1;     // 18ec addiu s5,v0,-1
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(sp + 20));     // 18f0 lw a0,20(sp)
	a1 = *((uint32_t *)(s3 + 4));     // 18f4 lw a1,4(s3)
	s0 = s0 + -1;     // 18f8 addiu s0,s0,-1

	__18fc:
	copy_32_bytes((void *)a0, (void *)a1);

	__1904:
	if(((s0 & (1 << 31)) != 0)) {
		a0 = sp + 16;     // 1908 addiu a0,sp,16
		goto __196c;
	} else {
		a0 = sp + 16;     // 1908 addiu a0,sp,16
	};     // 1904 bltz s0,6508

	a1 = s1;     // 1910 move a1,s1
	func_1660_c(a0, a1);
	a0 = *((uint32_t *)(sp + 16));     // 1914 lw a0,16(sp)
	a1 = *((uint32_t *)(s1 + 0));     // 191c lw a1,0(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(sp + 20));     // 1920 lw a0,20(sp)
	a1 = *((uint32_t *)(s1 + 4));     // 1928 lw a1,4(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	t7 = 1;     // 192c li t7,1
	t6 = t7 << s0;     // 1930 sllv t6,t7,s0
	t5 = t6 & s2;     // 1934 and t5,t6,s2
	a0 = sp + 16;     // 1938 addiu a0,sp,16
	a1 = s3;     // 193c move a1,s3
	a2 = s1;     // 1940 move a2,s1
	if(t5 == 0) {
		s0 = s0 + -1;     // 1948 addiu s0,s0,-1
		goto __1904;
	} else {
		s0 = s0 + -1;     // 1948 addiu s0,s0,-1
	};     // 1944 beqz t5,6404

	func_1490_c(a0, a1, a2);
	a0 = *((uint32_t *)(sp + 16));     // 1954 lw a0,16(sp)
	a1 = *((uint32_t *)(s1 + 0));     // 195c lw a1,0(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(sp + 20));     // 1960 lw a0,20(sp)
	a1 = *((uint32_t *)(s1 + 4));     // 1968 lw a1,4(s1)
	goto __18fc;     // 1964 b 6396

	__196c:
	if(((s5 & (1 << 31)) != 0)) {
		s2 = s5 << 0x2;     // 1970 sll s2,s5,0x2
		goto __1a04;
	} else {
		s2 = s5 << 0x2;     // 1970 sll s2,s5,0x2
	};     // 196c bltz s5,6660

	s4 = s2 + s4;     // 1974 addu s4,s2,s4

	__1978:
	s2 = *((uint32_t *)(s4 + 0));     // 1978 lw s2,0(s4)
	s0 = 31;     // 1980 li s0,31
	goto __198c;     // 197c b 6540

	__1984:
	if(((s0 & (1 << 31)) != 0)) {
		s5 = s5 + -1;     // 1988 addiu s5,s5,-1
		goto __19fc;
	} ;     // 1984 bltzl s0,6652

	__198c:
	a0 = sp + 16;     // 198c addiu a0,sp,16

	__1990:
	a1 = s1;     // 1994 move a1,s1
	func_1660_c(a0, a1);
	a0 = *((uint32_t *)(sp + 16));     // 1998 lw a0,16(sp)
	a1 = *((uint32_t *)(s1 + 0));     // 19a0 lw a1,0(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(sp + 20));     // 19a4 lw a0,20(sp)
	a1 = *((uint32_t *)(s1 + 4));     // 19ac lw a1,4(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	ra = 1;     // 19b0 li ra,1
	t9 = ra << s0;     // 19b4 sllv t9,ra,s0
	t8 = t9 & s2;     // 19b8 and t8,t9,s2
	a0 = sp + 16;     // 19bc addiu a0,sp,16
	a1 = s3;     // 19c0 move a1,s3
	a2 = s1;     // 19c4 move a2,s1
	if(t8 == 0) {
		s0 = s0 + -1;     // 19cc addiu s0,s0,-1
		goto __1984;
	} else {
		s0 = s0 + -1;     // 19cc addiu s0,s0,-1
	};     // 19c8 beqz t8,6532

	func_1490_c(a0, a1, a2);
	a0 = *((uint32_t *)(sp + 16));     // 19d8 lw a0,16(sp)
	a1 = *((uint32_t *)(s1 + 0));     // 19e0 lw a1,0(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(sp + 20));     // 19e4 lw a0,20(sp)
	a1 = *((uint32_t *)(s1 + 4));     // 19ec lw a1,4(s1)
	copy_32_bytes((void *)a0, (void *)a1);
	if((s0 & (1 << 31)) == 0) {
		a0 = sp + 16;     // 19f4 addiu a0,sp,16
		goto __1990;
	} else {
		a0 = sp + 16;     // 19f4 addiu a0,sp,16
	};     // 19f0 bgez s0,6544

	s5 = s5 + -1;     // 19f8 addiu s5,s5,-1

	__19fc:
	if((s5 & (1 << 31)) == 0) {
		s4 = s4 + -4;     // 1a00 addiu s4,s4,-4
		goto __1978;
	} else {
		s4 = s4 + -4;     // 1a00 addiu s4,s4,-4
	};     // 19fc bgez s5,6520

	__1a04:
	a0 = *((uint32_t *)(s1 + 0));     // 1a04 lw a0,0(s1)
	a1 = *((uint32_t *)(sp + 16));     // 1a0c lw a1,16(sp)
	copy_32_bytes((void *)a0, (void *)a1);
	a0 = *((uint32_t *)(s1 + 4));     // 1a10 lw a0,4(s1)
	a1 = *((uint32_t *)(sp + 20));     // 1a18 lw a1,20(sp)
	copy_32_bytes((void *)a0, (void *)a1);
	v0 = 0;
	return v0;     // 1a3c jr ra
}

int func_1a44_c(uint32_t a0)
{
	uint32_t a1, s0, v0;

	s0 = a0;     // 1a54 move s0,a0
	a0 = *((uint32_t *)(a0 + 0));     // 1a58 lw a0,0(a0)
	a1 = (uint32_t)data_3440;     // 1a5c la a1,__data + 0x440
	copy_32_bytes((void *)a0, (void *)a1);     // 1a60 jal func_eb4
	a0 = *((uint32_t *)(s0 + 4));     // 1a64 lw a0,4(s0)
	a1 = (uint32_t)data_3420;     // 1a6c la a1,__data + 0x420
	copy_32_bytes((void *)a0, (void *)a1);     // 1a60 jal func_eb4
	v0 = 0;     // 1a7c move v0,zero
	return v0;     // 1a80 jr ra
}

int func_1a88_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t s0, s1, s2, sp, v0, v1;
	uint32_t stack[10];
	sp = (uint32_t)stack;

	v1 = (uint32_t)__bss + 0xf20;     // 1a90 la v1,__bss + 0xf20
	v0 = (uint32_t)__bss + 0x11a0;     // 1a98 la v0,__bss + 0x11a0
	s2 = a0;     // 1aa4 move s2,a0
	s1 = a1;     // 1aa8 move s1,a1
	a0 = v1;     // 1aac move a0,v1
	a1 = 8;     // 1ab0 li a1,8
	*((uint32_t *)(sp + 20)) = v0;     // 1ab8 sw v0,20(sp)
	*((uint32_t *)(sp + 16)) = v1;     // 1abc sw v1,16(sp)
	s0 = a2;     // 1ac8 move s0,a2
	clear_memory((void *)a0, a1);
	a0 = *((uint32_t *)(sp + 20));     // 1acc lw a0,20(sp)
	a1 = 8;     // 1ad4 li a1,8
	clear_memory((void *)a0, a1);
	a0 = s0;     // 1ad8 move a0,s0
	a1 = s1;     // 1adc move a1,s1
	a2 = sp + 16;     // 1ae4 addiu a2,sp,16
	v0 = func_1838_c(a0, a1, a2);
	s0 = v0;     // 1ae8 move s0,v0
	a0 = s2;     // 1aec move a0,s2
	if(v0 != 0) {
		a1 = sp + 16;     // 1af4 addiu a1,sp,16
		goto __1b00;
	} else {
		a1 = sp + 16;     // 1af4 addiu a1,sp,16
	};     // 1af0 bnez v0,6912

	func_1428_c(a0, a1);

	__1b00:
	v0 = s0;     // 1b00 move v0,s0
	return v0;     // 1b14 jr ra
}

void func_1b1c_c(uint32_t a0, uint8_t *a1, int length, uint32_t a3)
{
	uint32_t a2, s1, v0, v1;

	memcpy(a1, (void *)a0, length);     // 1b48 jal memcpy

	s1 = (uint32_t) a1;     // 1b28 move s1,a1
	a0 = s1;     // 1b3c move a0,s1
	a2 = ((a3 & 0xf0) >> 4) + 16;     // 1b54 addiu a2,a3,16
	v1 = a2 + s1;     // 1b58 addu v1,a2,s1
	v0 = *((uint8_t*)(0 + v1));     // 1b5c lbu v0,0(v1)
	a3 = (a3 & 0xf) + s1;     // 1b64 addu s0,a1,s1
	a0 = *((uint8_t*)(0 + a3));     // 1b68 lbu a0,0(s0)
	*((uint8_t *)(a3 + 0)) = (v0 & 0xff);     // 1b70 sb v0,0(s0)
	*((uint8_t *)(v1 + 0)) = (a0 & 0xff);     // 1b84 sb a0,0(v1)
}

void func_1b88_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t v0, a3, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, v1, zero;
	zero = 0;

	t4 = (uint32_t)data_3484;     // 1b8c la t4,__data + 0x484
	t5 = a1;     // 1b90 move t5,a1
	t3 = a0;     // 1b94 move t3,a0
	t1 = zero;     // 1b98 move t1,zero
	t0 = a1;     // 1b9c move t0,a1
	t2 = t4;     // 1ba0 move t2,t4
	a3 = a2;     // 1ba4 move a3,a2

	__1ba8:
	a0 = t3 + t1;     // 1ba8 addu a0,t3,t1
	t9 = *((uint8_t*)(0 + t2));     // 1bac lbu t9,0(t2)
	t8 = *((uint8_t*)(0 + a0));     // 1bb0 lbu t8,0(a0)
	t1 = t1 + 1;     // 1bb4 addiu t1,t1,1
	t7 = t8 ^ t9;     // 1bb8 xor t7,t8,t9
	*((uint8_t *)(a3 + 0)) = (t7 & 0xff);     // 1bbc sb t7,0(a3)
	v1 = *((uint8_t*)(0 + t0));     // 1bc0 lbu v1,0(t0)
	a1 = (((int32_t)t1) < 16);     // 1bc4 slti a1,t1,16
	t6 = t7 ^ v1;     // 1bc8 xor t6,t7,v1
	*((uint8_t *)(a0 + 0)) = (t6 & 0xff);     // 1bcc sb t6,0(a0)
	a3 = a3 + 1;     // 1bd0 addiu a3,a3,1
	t2 = t2 + 1;     // 1bd4 addiu t2,t2,1
	if(a1 != 0) {
		t0 = t0 + 1;     // 1bdc addiu t0,t0,1
		goto __1ba8;
	} else {
		t0 = t0 + 1;     // 1bdc addiu t0,t0,1
	};     // 1bd8 bnez a1,7080

	a3 = t5 + 16;     // 1be0 addiu a3,t5,16
	t1 = t4 + 16;     // 1be4 addiu t1,t4,16
	a2 = a2 + 16;     // 1be8 addiu a2,a2,16
	t0 = 16;     // 1bec li t0,16

	__1bf0:
	t4 = t3 + t0;     // 1bf0 addu t4,t3,t0
	t6 = *((uint8_t*)(0 + t1));     // 1bf4 lbu t6,0(t1)
	a0 = *((uint8_t*)(0 + t4));     // 1bf8 lbu a0,0(t4)
	t0 = t0 + 1;     // 1bfc addiu t0,t0,1
	v0 = a0 ^ t6;     // 1c00 xor v0,a0,t6
	*((uint8_t *)(a2 + 0)) = (v0 & 0xff);     // 1c04 sb v0,0(a2)
	a1 = *((uint8_t*)(-16 + a3));     // 1c08 lbu a1,-16(a3)
	t2 = (((int32_t)t0) < 20);     // 1c0c slti t2,t0,20
	t5 = v0 ^ a1;     // 1c10 xor t5,v0,a1
	*((uint8_t *)(t4 + 0)) = (t5 & 0xff);     // 1c14 sb t5,0(t4)
	a2 = a2 + 1;     // 1c18 addiu a2,a2,1
	t1 = t1 + 1;     // 1c1c addiu t1,t1,1
	if(t2 != 0) {
		a3 = a3 + 1;     // 1c24 addiu a3,a3,1
		goto __1bf0;
	} else {
		a3 = a3 + 1;     // 1c24 addiu a3,a3,1
	};     // 1c20 bnez t2,7152

	return;     // 1c28 jr ra
}

void func_1c30_c(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
	uint32_t s0, s1, s2, sp, zero;
	zero = 0;
	uint32_t stack[16];
	sp = (uint32_t)stack;

	s1 = a0;     // 1c3c move s1,a0
	s0 = a2;     // 1c40 move s0,a2
	a0 = a0 + a2;     // 1c44 addu a0,a0,a2
	a2 = sp + 24;     // 1c48 addiu a2,sp,24
	*((uint32_t *)(sp + 24)) = zero;     // 1c54 sw zero,24(sp)
	s2 = a3;     // 1c58 move s2,a3
	*((uint32_t *)(sp + 28)) = zero;     // 1c5c sw zero,28(sp)
	*((uint32_t *)(sp + 32)) = zero;     // 1c60 sw zero,32(sp)
	*((uint32_t *)(sp + 36)) = zero;     // 1c64 sw zero,36(sp)
	*((uint32_t *)(sp + 40)) = zero;     // 1c6c sw zero,40(sp)
	func_1b88_c(a0, a1, a2);
	a2 = s1;     // 1c70 move a2,s1
	a3 = s0;     // 1c74 move a3,s0
	a0 = sp + 24;     // 1c78 addiu a0,sp,24
	a1 = 20;     // 1c7c li a1,20
	func_d78_c((uint8_t *)a0, a1, a2, a3, (void *)s2);
	return;     // 1c98 jr ra
}

int func_1ca0_c(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4)
{
	uint32_t s0, s1, s3, s4, sp, t0, t1, v0, v1, zero;
	zero = 0;
	uint32_t stack[12];
	sp = (uint32_t)stack;

	s1 = a0;     // 1ca8 move s1,a0
	a0 = a1;     // 1cac move a0,a1
	a1 = a4; //*((uint32_t *)(sp + 64));     // 1cb0 lw a1,64(sp)
	s0 = s1 + 3;     // 1cb8 addiu s0,s1,3
	v1 = 489;     // 1cbc li v1,489
	a1 = a1 + 4;     // 1cc8 addiu a1,a1,4
	s3 = a3;     // 1ccc move s3,a3
	s4 = a2;     // 1cd0 move s4,a2
	a3 = a0;     // 1cd4 move a3,a0
	a2 = 489;     // 1cd8 li a2,489
	a0 = s0;     // 1cdc move a0,s0
	*((uint16_t *)(sp + 16)) = (v1 & 0xffff);     // 1ce0 sh v1,16(sp)
	func_1c30_c(a0, a1, a2, a3);
	a0 = s0;     // 1cf4 move a0,s0
	a1 = sp + 16;     // 1cf8 addiu a1,sp,16
	a2 = 2;     // 1cfc li a2,2
	a3 = 2;     // 1d04 li a3,2
	s0 = 1;     // 1d08 li s0,1
	*((uint16_t *)(sp + 16)) = (s0 & 0xffff);     // 1d10 sh s0,16(sp)
	v0 = memcmp((void *)a0, (void *)a1, a2);     // 1d0c jal memcmp
	a0 = s1;     // 1d14 move a0,s1
	a1 = s1 + 492;     // 1d18 addiu a1,s1,492
	a2 = 492;     // 1d1c li a2,492
	if(v0 != 0) {
		v1 = 24;     // 1d24 li v1,24
		goto __1d90;
	} else {
		v1 = 24;     // 1d24 li v1,24
	};     // 1d20 bnez v0,7568

	a3 = 492;     // 1d28 li a3,492
	*((uint16_t *)(sp + 16)) = (a3 & 0xffff);     // 1d30 sh a3,16(sp)
	v0 = func_abc_c((void *)a0, (void *)a1, a2);
	a0 = sp + 16;     // 1d34 addiu a0,sp,16
	a1 = s1 + 13;     // 1d38 addiu a1,s1,13
	a2 = 2;     // 1d3c li a2,2
	a3 = zero;     // 1d40 move a3,zero
	if(v0 != 0) {
		v1 = 2;     // 1d48 li v1,2
		goto __1d90;
	} else {
		v1 = 2;     // 1d48 li v1,2
	};     // 1d44 bnez v0,7568

	*((uint8_t *)(s4 + 0)) = (s0 & 0xff);     // 1d50 sb s0,0(s4)
	memcpy((void *)a0, (void *)a1, a2);     // 1d4c jal memcpy
	t1 = *((uint16_t*)(16 + sp));     // 1d54 lhu t1,16(sp)
	a0 = *((uint32_t *)(s3 + 24));     // 1d58 lw a0,24(s3)
	t0 = t1 + 16;     // 1d5c addiu t0,t1,16
	a1 = zero;     // 1d60 move a1,zero
	a2 = 32;     // 1d64 li a2,32
	a3 = 1;     // 1d68 li a3,1
	*((uint16_t *)(sp + 16)) = (t0 & 0xffff);     // 1d70 sh t0,16(sp)
	memset((void *)a0, a1, a2);     // 1d6c jal memset
	a2 = *((int16_t*)(16 + sp));     // 1d74 lh a2,16(sp)
	a0 = *((uint32_t *)(s3 + 24));     // 1d78 lw a0,24(s3)
	a1 = a2 + s1;     // 1d7c addu a1,a2,s1
	a3 = zero;     // 1d80 move a3,zero
	a2 = 30;     // 1d88 li a2,30
	memcpy((void *)a0, (void *)a1, a2);     // 1d84 jal memcpy
	v1 = zero;     // 1d8c move v1,zero

	__1d90:
	v0 = v1;     // 1da8 move v0,v1
	return v0;     // 1dac jr ra
}

int func_1db4_c(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7, uint32_t a8)
{
	int32_t ra, s0, s1, s2, s3, s4, s5, s6, s7, s8, sp, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, v0, v1, zero;
	zero = 0;
	uint32_t stack[196];
	sp = (uint32_t)stack;

	// sp offset by -744
	*((uint32_t*)(sp + 744 + 16)) = a4;
	*((uint32_t*)(sp + 744 + 20)) = a5;
	*((uint32_t*)(sp + 744 + 24)) = a6;
	*((uint32_t*)(sp + 744 + 28)) = a7;
	*((uint32_t*)(sp + 744 + 32)) = a8;

	*((uint32_t *)(sp + 720)) = s4;     // 1db8 sw s4,720(sp)
	s4 = *((uint32_t *)(sp + 776));     // 1dbc lw s4,776(sp)
	a0 = (0xbfc3) << 16;     // 1dc0 lui a0,0xbfc3
	t6 = s4 + 1536;     // 1dc4 addiu t6,s4,1536
	t5 = s4 + 1664;     // 1dc8 addiu t5,s4,1664
	t0 = s4 + 1792;     // 1dcc addiu t0,s4,1792
	t1 = s4 + 1920;     // 1dd0 addiu t1,s4,1920
	t2 = s4 + 2048;     // 1dd4 addiu t2,s4,2048
	t3 = s4 + 2176;     // 1dd8 addiu t3,s4,2176
	t4 = s4 + 2304;     // 1ddc addiu t4,s4,2304
	*((uint32_t *)(sp + 732)) = s7;     // 1de0 sw s7,732(sp)
	*((uint32_t *)(sp + 724)) = s5;     // 1de4 sw s5,724(sp)
	*((uint32_t *)(sp + 716)) = s3;     // 1de8 sw s3,716(sp)
	*((uint32_t *)(sp + 708)) = s1;     // 1df0 sw s1,708(sp)
	*((uint32_t *)(sp + 704)) = s0;     // 1df4 sw s0,704(sp)
	s3 = a1;     // 1df8 move s3,a1
	a0 = s4;     // 1dfc move a0,s4
	a1 = zero;     // 1e00 move a1,zero
	s1 = a2;     // 1e04 move s1,a2
	s7 = a3;     // 1e08 move s7,a3
	a2 = 512;     // 1e0c li a2,512
	a3 = 1;     // 1e10 li a3,1
	s0 = s4 + 512;     // 1e14 addiu s0,s4,512
	*((uint32_t *)(sp + 740)) = ra;     // 1e18 sw ra,740(sp)
	*((uint32_t *)(sp + 256)) = t6;     // 1e1c sw t6,256(sp)
	*((uint32_t *)(sp + 260)) = t5;     // 1e20 sw t5,260(sp)
	*((uint32_t *)(sp + 640)) = t0;     // 1e24 sw t0,640(sp)
	*((uint32_t *)(sp + 124)) = t1;     // 1e28 sw t1,124(sp)
	*((uint32_t *)(sp + 128)) = t2;     // 1e2c sw t2,128(sp)
	*((uint32_t *)(sp + 680)) = t3;     // 1e30 sw t3,680(sp)
	*((uint32_t *)(sp + 684)) = t4;     // 1e34 sw t4,684(sp)
	*((uint32_t *)(sp + 736)) = s8;     // 1e38 sw s8,736(sp)
	*((uint32_t *)(sp + 728)) = s6;     // 1e3c sw s6,728(sp)
	*((uint32_t *)(sp + 712)) = s2;     // 1e40 sw s2,712(sp)
	*((uint16_t *)(sp + 24)) = (zero & 0xffff);     // 1e44 sh zero,24(sp)
	*((uint8_t *)(sp + 672)) = (zero & 0xff);     // 1e48 sb zero,672(sp)
	*((uint8_t *)(sp + 673)) = (zero & 0xff);     // 1e4c sb zero,673(sp)
	s8 = *((uint32_t *)(sp + 772));     // 1e54 lw s8,772(sp)
	memset((void *)a0, a1, a2);
	a0 = s0;     // 1e58 move a0,s0
	a1 = zero;     // 1e5c move a1,zero
	a2 = 512;     // 1e60 li a2,512
	a3 = 1;     // 1e68 li a3,1
	memset((void *)a0, a1, a2);
	v1 = (0xbfc3) << 16;     // 1e6c lui v1,0xbfc3
	s6 = (uint32_t)firmware_signature_3498;     // 1e70 la s6,__data + 0x498
	a0 = s3;     // 1e74 move a0,s3
	a1 = s6;     // 1e78 move a1,s6
	a2 = 16;     // 1e7c li a2,16
	a3 = 2;     // 1e84 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	v0 = (int8_t)v0;     // 1e88 seb v0,v0
	if(v0 != 0) {
		v1 = 3;     // 1e90 li v1,3
		goto __1fa4;
	} else {
		v1 = 3;     // 1e90 li v1,3
	};     // 1e8c bnez v0,8100

	__1e94:
	t9 = *((uint8_t*)(494 + s3));     // 1e94 lbu t9,494(s3)
	a0 = s0;     // 1e98 move a0,s0
	a2 = t9 & 0xf;     // 1e9c andi a2,t9,0xf
	*((uint8_t *)(s1 + 0)) = (a2 & 0xff);     // 1ea0 sb a2,0(s1)
	t8 = *((uint8_t*)(510 + s3));     // 1ea4 lbu t8,510(s3)
	a2 = 1024;     // 1ea8 li a2,1024
	a3 = t8 & 0xf;     // 1eac andi a3,t8,0xf
	*((uint8_t *)(s7 + 0)) = (a3 & 0xff);     // 1eb0 sb a3,0(s7)
	s2 = *((uint8_t *)(s1 + 0));     // 1eb4 lb s2,0(s1)
	a3 = zero;     // 1eb8 move a3,zero
	t7 = s2 << 0x9;     // 1ebc sll t7,s2,0x9
	a1 = t7 + s3;     // 1ec0 addu a1,t7,s3
	a1 = a1 + 1024;     // 1ec4 addiu a1,a1,1024
	s2 = sp + 320;     // 1ecc addiu s2,sp,320
	memcpy((void *)a0, (void *)a1, a2);
	a0 = s0;     // 1ed0 move a0,s0
	a1 = sp + 248;     // 1ed4 addiu a1,sp,248
	a2 = s2;     // 1ed8 move a2,s2
	a3 = sp + 672;     // 1ee0 addiu a3,sp,672
	v0 = func_808_c((void *)a0, (void *)a1, (void *)a2, (void *)a3);
	if(v0 != 0) {
		s0 = v0;     // 1ee8 move s0,v0
		goto __1fa0;
	} else {
		s0 = v0;     // 1ee8 move s0,v0
	};     // 1ee4 bnez v0,8096

	__1eec:
	ra = *((uint8_t *)(s1 + 0));     // 1eec lb ra,0(s1)
	v0 = *((uint8_t *)(s7 + 0));     // 1ef0 lb v0,0(s7)
	a0 = s4;     // 1ef4 move a0,s4
	s7 = ra + v0;     // 1ef8 addu s7,ra,v0
	s1 = s7 << 0x9;     // 1efc sll s1,s7,0x9
	s0 = s1 + s3;     // 1f00 addu s0,s1,s3
	a1 = s0 + 2560;     // 1f04 addiu a1,s0,2560
	a2 = 512;     // 1f08 li a2,512
	a3 = zero;     // 1f10 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a0 = s4;     // 1f14 move a0,s4
	a1 = s8;     // 1f18 move a1,s8
	a2 = sp + 673;     // 1f1c addiu a2,sp,673
	a3 = sp + 616;     // 1f20 addiu a3,sp,616
	*((uint32_t *)(sp + 16)) = s2;     // 1f28 sw s2,16(sp)
	v0 = func_1ca0_c(a0, a1, a2, a3, s2);
	if(v0 != 0) {
		s0 = v0;     // 1f30 move s0,v0
		goto __1fa0;
	} else {
		s0 = v0;     // 1f30 move s0,v0
	};     // 1f2c bnez v0,8096

	__1f34:
	s2 = sp + 32;     // 1f34 addiu s2,sp,32
	a0 = s2;     // 1f38 move a0,s2
	a1 = zero;     // 1f3c move a1,zero
	a2 = 91;     // 1f40 li a2,91
	a3 = 1;     // 1f48 li a3,1
	memset((void *)a0, a1, a2);
	a0 = s2;     // 1f4c move a0,s2
	a1 = s3;     // 1f50 move a1,s3
	a2 = 42;     // 1f54 li a2,42
	a3 = zero;     // 1f5c move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a1 = s6;     // 1f60 move a1,s6
	a0 = s2;     // 1f64 move a0,s2
	a2 = 16;     // 1f68 li a2,16
	a3 = 2;     // 1f70 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	s6 = (int8_t)v0;     // 1f74 seb s6,v0
	if(s6 != 0) {
		s0 = 3;     // 1f7c li s0,3
		goto __1fa0;
	} else {
		s0 = 3;     // 1f7c li s0,3
	};     // 1f78 bnez s6,8096

	__1f80:
	v1 = *((uint8_t *)(sp + 56));     // 1f80 lb v1,56(sp)
	t4 = 126;     // 1f84 li t4,126
	if(v1 != t4) {
		s0 = 8;     // 1f8c li s0,8
		goto __1fa0;
	} else {
		s0 = 8;     // 1f8c li s0,8
	};     // 1f88 bne v1,t4,8096

	__1f90:
	t2 = *((uint32_t *)(sp + 52));     // 1f90 lw t2,52(sp)
	t3 = 512;     // 1f94 li t3,512
	if(t2 == t3) {
		s0 = 3;     // 1f9c li s0,3
		goto __1fd8;
	} else {
		s0 = 3;     // 1f9c li s0,3
	};     // 1f98 beq t2,t3,8152

	__1fa0:
	v1 = s0;     // 1fa0 move v1,s0

	__1fa4:
	ra = *((uint32_t *)(sp + 740));     // 1fa4 lw ra,740(sp)
	s8 = *((uint32_t *)(sp + 736));     // 1fa8 lw s8,736(sp)
	s7 = *((uint32_t *)(sp + 732));     // 1fac lw s7,732(sp)
	s6 = *((uint32_t *)(sp + 728));     // 1fb0 lw s6,728(sp)
	s5 = *((uint32_t *)(sp + 724));     // 1fb4 lw s5,724(sp)
	s4 = *((uint32_t *)(sp + 720));     // 1fb8 lw s4,720(sp)
	s3 = *((uint32_t *)(sp + 716));     // 1fbc lw s3,716(sp)
	s2 = *((uint32_t *)(sp + 712));     // 1fc0 lw s2,712(sp)
	s1 = *((uint32_t *)(sp + 708));     // 1fc4 lw s1,708(sp)
	s0 = *((uint32_t *)(sp + 704));     // 1fc8 lw s0,704(sp)
	v0 = v1;     // 1fcc move v0,v1
	return v0;     // 1fd0 jr ra

	__1fd8:
	t0 = *((uint8_t*)(57 + sp));     // 1fd8 lbu t0,57(sp)
	t1 = 225;     // 1fdc li t1,225
	if(t0 != t1) {
		v1 = s0;     // 1fe4 move v1,s0
		goto __1fa4;
	} else {
		v1 = s0;     // 1fe4 move v1,s0
	};     // 1fe0 bne t0,t1,8100

	__1fe8:
	t6 = (0xbfc3) << 16;     // 1fe8 lui t6,0xbfc3
	a1 = (uint32_t)signature_34b0;     // 1fec la a1,__data + 0x4b0
	a0 = sp + 58;     // 1ff0 addiu a0,sp,58
	a2 = 16;     // 1ff4 li a2,16
	a3 = 2;     // 1ffc li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	t5 = (int8_t)v0;     // 2000 seb t5,v0
	if(t5 != 0) {
		v1 = s0;     // 2008 move v1,s0
		goto __1fa4;
	} else {
		v1 = s0;     // 2008 move v1,s0
	};     // 2004 bnez t5,8100

	__200c:
	s6 = s3 + 42;     // 200c addiu s6,s3,42
	a0 = sp + 74;     // 2010 addiu a0,sp,74
	a1 = s6;     // 2014 move a1,s6
	a2 = 49;     // 2018 li a2,49
	a3 = zero;     // 2020 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a1 = *((uint8_t *)(sp + 90));     // 2024 lb a1,90(sp)
	a0 = 3;     // 2028 li a0,3
	if(a1 != a0) {
		s0 = 5;     // 2030 li s0,5
		goto __1fa0;
	} else {
		s0 = 5;     // 2030 li s0,5
	};     // 202c bne a1,a0,8096

	__2034:
	a0 = *((uint32_t *)(sp + 124));     // 2034 lw a0,124(sp)
	a1 = zero;     // 2038 move a1,zero
	a2 = 32;     // 203c li a2,32
	a3 = 1;     // 2044 li a3,1
	memset((void *)a0, a1, a2);
	a0 = *((uint32_t *)(sp + 128));     // 2048 lw a0,128(sp)
	a1 = zero;     // 204c move a1,zero
	a2 = 32;     // 2050 li a2,32
	a3 = 1;     // 2058 li a3,1
	memset((void *)a0, a1, a2);
	a0 = *((uint32_t *)(sp + 124));     // 205c lw a0,124(sp)
	a1 = s3 + 91;     // 2060 addiu a1,s3,91
	a2 = 30;     // 2064 li a2,30
	a3 = zero;     // 206c move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a0 = *((uint32_t *)(sp + 128));     // 2070 lw a0,128(sp)
	a1 = s3 + 121;     // 2074 addiu a1,s3,121
	a2 = 30;     // 2078 li a2,30
	a3 = zero;     // 2080 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a1 = *((uint8_t *)(sp + 252));     // 2084 lb a1,252(sp)
	a0 = sp + 680;     // 208c addiu a0,sp,680
	v0 = func_1a44_c(a0);
	if(v0 != 0) {
		s0 = v0;     // 2094 move s0,v0
		goto __1fa0;
	} else {
		s0 = v0;     // 2094 move s0,v0
	};     // 2090 bnez v0,8096

	__2098:
	s1 = sp + 91;     // 2098 addiu s1,sp,91
	a2 = *((uint32_t *)(sp + 640));     // 209c lw a2,640(sp)
	a0 = s1;     // 20a0 move a0,s1
	a1 = sp + 124;     // 20a8 addiu a1,sp,124
	v0 = func_1a88_c(a0, a1, a2);
	if(v0 != 0) {
		s0 = v0;     // 20b0 move s0,v0
		goto __1fa0;
	} else {
		s0 = v0;     // 20b0 move s0,v0
	};     // 20ac bnez v0,8096

	__20b4:
	a0 = *((uint32_t *)(sp + 764));     // 20b4 lw a0,764(sp)
	a1 = s1;     // 20b8 move a1,s1
	a2 = 32;     // 20bc li a2,32
	a3 = zero;     // 20c4 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	s0 = s3 + 151;     // 20c8 addiu s0,s3,151
	a0 = *((uint32_t *)(sp + 764));     // 20cc lw a0,764(sp)
	a2 = s0;     // 20d0 move a2,s0
	a1 = zero;     // 20d4 move a1,zero
	a3 = 361;     // 20d8 li a3,361
	s1 = sp + 132;     // 20dc addiu s1,sp,132
	*((uint32_t *)(sp + 16)) = s8;     // 20e4 sw s8,16(sp)
	func_d80_c(a0, a1, a2, a3, s8);
	a1 = s0;     // 20e8 move a1,s0
	a0 = s1;     // 20ec move a0,s1
	a2 = 2;     // 20f0 li a2,2
	a3 = zero;     // 20f8 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a2 = 2;     // 20fc li a2,2
	a1 = s1;     // 2100 move a1,s1
	a0 = sp + 24;     // 2104 addiu a0,sp,24
	a3 = zero;     // 210c move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a2 = *((int16_t*)(24 + sp));     // 2110 lh a2,24(sp)
	t7 = 251;     // 2114 li t7,251
	t8 = a2 + 153;     // 2118 addiu t8,a2,153
	s0 = 3;     // 211c li s0,3
	if(a2 != t7) {
		v1 = (int32_t)(((int16_t)t8));     // 2124 seh v1,t8
		goto __1fa0;
	} else {
		v1 = (int32_t)(((int16_t)t8));     // 2124 seh v1,t8
	};     // 2120 bne a2,t7,8096

	__2128:
	a1 = v1 + s3;     // 2128 addu a1,v1,s3
	a0 = sp + 140;     // 212c addiu a0,sp,140
	a2 = 108;     // 2130 li a2,108
	a3 = zero;     // 2138 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	t9 = *((uint8_t *)(sp + 140));     // 213c lb t9,140(sp)
	s3 = 2;     // 2140 li s3,2
	if(t9 != s3) {
		s0 = 4;     // 2148 li s0,4
		goto __1fa0;
	} else {
		s0 = 4;     // 2148 li s0,4
	};     // 2144 bne t9,s3,8096

	__214c:
	ra = (0xbfc3) << 16;     // 214c lui ra,0xbfc3
	a1 = (uint32_t)signature_34ac;     // 2150 la a1,__data + 0x4ac
	a0 = sp + 141;     // 2154 addiu a0,sp,141
	a2 = 4;     // 2158 li a2,4
	a3 = 2;     // 2160 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	s7 = (int8_t)v0;     // 2164 seb s7,v0
	if(s7 != 0) {
		s0 = 3;     // 216c li s0,3
		goto __1fa0;
	} else {
		s0 = 3;     // 216c li s0,3
	};     // 2168 bnez s7,8096

	__2170:
	s2 = (0xbfc3) << 16;     // 2170 lui s2,0xbfc3
	a1 = (uint32_t)signature_34a8;     // 2174 la a1,__data + 0x4a8
	a0 = sp + 145;     // 2178 addiu a0,sp,145
	a2 = 4;     // 217c li a2,4
	a3 = 2;     // 2184 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	v0 = (int8_t)v0;     // 2188 seb v0,v0
	if(v0 != 0) {
		v1 = *((int8_t *)(sp + 181));     // 2190 lb v1,181(sp)
		goto __1fa0;
	} else {
		v1 = *((int8_t *)(sp + 181));     // 2190 lb v1,181(sp)
	};     // 218c bnez v0,8096

	__2194:
	t4 = -66;     // 2194 li t4,-66
	if(v1 != t4) {
		s0 = 5;     // 219c li s0,5
		goto __1fa0;
	} else {
		s0 = 5;     // 219c li s0,5
	};     // 2198 bne v1,t4,8096

	__21a0:
	a0 = *((uint32_t *)(sp + 768));     // 21a0 lw a0,768(sp)
	a1 = zero;     // 21a4 move a1,zero
	a2 = 512;     // 21a8 li a2,512
	a3 = 1;     // 21b0 li a3,1
	memset((void *)a0, a1, a2);
	t1 = *((uint32_t *)(sp + 768));     // 21b4 lw t1,768(sp)
	s7 = sp + 182;     // 21b8 addiu s7,sp,182
	s3 = t1 + 492;     // 21bc addiu s3,t1,492
	a3 = zero;     // 21c0 move a3,zero
	a0 = s4 + 476;     // 21c4 addiu a0,s4,476
	a1 = s7;     // 21c8 move a1,s7
	a2 = 16;     // 21d0 li a2,16
	memcpy((void *)a0, (void *)a1, a2);
	a0 = s4;     // 21d4 move a0,s4
	a1 = 492;     // 21d8 li a1,492
	a2 = s3;     // 21e0 move a2,s3
	func_97c_c((void *)a0, a1, (void *)a2);
	t2 = *((uint32_t *)(sp + 768));     // 21e4 lw t2,768(sp)
	a1 = s4;     // 21e8 move a1,s4
	s0 = *((uint8_t*)(500 + t2));     // 21ec lbu s0,500(t2)
	a0 = t2;     // 21f0 move a0,t2
	s1 = s0 + t2;     // 21f4 addu s1,s0,t2
	a2 = s0;     // 21f8 move a2,s0
	a3 = zero;     // 2200 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a1 = s7;     // 2204 move a1,s7
	a0 = s1;     // 2208 move a0,s1
	a2 = 16;     // 220c li a2,16
	a3 = zero;     // 2214 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	t3 = 476;     // 2218 li t3,476
	a2 = t3 - s0;     // 221c subu a2,t3,s0
	a1 = s0 + s4;     // 2220 addu a1,s0,s4
	a0 = s1 + 16;     // 2224 addiu a0,s1,16
	a3 = zero;     // 222c move a3,zero
	memcpy((void *)a0, (void *)a1, a2);
	a2 = *((uint32_t *)(sp + 768));     // 2230 lw a2,768(sp)
	a0 = s3;     // 2234 move a0,s3
	a1 = 16;     // 2238 li a1,16
	a3 = 492;     // 223c li a3,492
	*((uint32_t *)(sp + 16)) = s8;     // 2244 sw s8,16(sp)
	func_d2c_c((void *)a0, a1, a2, a3, (void *)s8);
	a0 = s6;     // 2248 move a0,s6
	a1 = sp + 228;     // 224c addiu a1,sp,228
	a2 = 450;     // 2254 li a2,450
	v0 = func_abc_c((void *)a0, (void *)a1, a2);
	if(v0 != 0) {
		s0 = 2;     // 225c li s0,2
		goto __1fa0;
	} else {
		s0 = 2;     // 225c li s0,2
	};     // 2258 bnez v0,8096

	__2260:
	a0 = sp + 324;     // 2260 addiu a0,sp,324
	a1 = sp + 149;     // 2264 addiu a1,sp,149
	a2 = 16;     // 2268 li a2,16
	a3 = 2;     // 2270 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	s0 = (int8_t)v0;     // 2274 seb s0,v0
	if(s0 == 0) {
		a0 = *((uint32_t *)(sp + 760));     // 227c lw a0,760(sp)
		goto __2288;
	} else {
		a0 = *((uint32_t *)(sp + 760));     // 227c lw a0,760(sp)
	};     // 2278 beqz s0,8840

	__2280:
	s0 = 1;     // 2284 li s0,1
	goto __1fa0;     // 2280 b 8096

	__2288:
	a1 = sp + 688;     // 2288 addiu a1,sp,688
	a2 = 16;     // 228c li a2,16
	a3 = 2;     // 2290 li a3,2
	*((uint32_t *)(sp + 688)) = zero;     // 2294 sw zero,688(sp)
	*((uint32_t *)(sp + 692)) = zero;     // 2298 sw zero,692(sp)
	*((uint32_t *)(sp + 696)) = zero;     // 229c sw zero,696(sp)
	*((uint32_t *)(sp + 700)) = zero;     // 22a4 sw zero,700(sp)
	v0 = memcmp((void *)a0, (void *)a1, a2);
	if(v0 == 0) {
		v1 = s0;     // 22ac move v1,s0
		goto __1fa4;
	} else {
		v1 = s0;     // 22ac move v1,s0
	};     // 22a8 beqz v0,8100

	__22b0:
	a0 = *((uint32_t *)(sp + 760));     // 22b0 lw a0,760(sp)
	a1 = sp + 165;     // 22b4 addiu a1,sp,165
	a2 = 16;     // 22b8 li a2,16
	a3 = 2;     // 22c0 li a3,2
	v0 = memcmp((void *)a0, (void *)a1, a2);
	s4 = (int8_t)v0;     // 22c4 seb s4,v0
	s0 = 10;     // 22c8 li s0,10
	if(s4 == 0) {
		s0 = s4;
	};     // 22d0 movz s0,s4,s4
	goto __1fa0;     // 22cc b 8096
}

struct inituse_detail {
	uint8_t session_key[32];
	uint8_t loc32[16];
	uint8_t loc48[512];
	uint8_t loc560[16384];
	uint8_t loc16944[512];
	uint8_t loc17456[2432];
};

// NB this isn't used yet
struct glbuffer_detail {
	uint8_t loc0[256];
	uint32_t unused_1;
	uint16_t rounds_to_perform;
	uint16_t unused_2;
	uint8_t key[32];
	uint32_t unused_3;
};

/* Better name might be fw_decrypt_atj2127.
 * Decrypts (32 * count) bytes in-place in buf using session_key.
*/
void func_268c_c(uint32_t *buf, uint32_t *session_key, int count)
{
	uint32_t key[8];
	int i;

	for(i = 0; i < 8; i++) {
		key[i] = atj2127_key[i] ^ session_key[i];
	}

	while(count > 0) {
		uint32_t rollover = buf[7] ^ session_key[7];

		buf[0] ^= key[1];
		buf[1] ^= key[2];
		buf[2] ^= key[3];
		buf[3] ^= key[4];
		buf[4] ^= key[5];
		buf[5] ^= key[6];
		buf[6] ^= key[7];
		buf[7] ^= key[1] ^ key[4];

		key[1] = key[2];
		key[2] = key[3];
		key[3] = key[4];
		key[4] = key[5];
		key[5] = key[6];
		key[6] = key[7];
		key[7] = rollover;

		buf += 8;
		count -= 1;
	}

	return;
}

int func_fw_decrypt_init_c(struct decrypt_struct *decrypt)
{
	int ret;

	/* Ensure we got what we expect */
	if(decrypt->InOutLen != DECRYPT_INOUT_LENGTH)
		return 48;

	if(decrypt->InOutLen - 2048 != (16 * 1024))
		return 48; // TODO clearly unnecessary

	if(decrypt->initusebufferlen != DECRYPT_INIT_LENGTH)
		return 48;

	struct inituse_detail *inituse = (struct inituse_detail *)decrypt->initusebuffer;
	assert(decrypt->initusebufferlen == sizeof(struct inituse_detail));

	/* Clear buffer */
	memset(decrypt->initusebuffer, 0, DECRYPT_INIT_LENGTH);

	/* 2358 */
	int8_t sp_40, sp_41;
	if((ret = func_1db4_c(decrypt->FileLength, // a0
					decrypt->pInOutBuffer,
					&sp_40,
					&sp_41,
					decrypt->initusebuffer + 32, // a4 (sp + 16)
					decrypt->initusebuffer, // a5 (sp + 20)
					decrypt->initusebuffer + 48, // a6 (sp + 24)
					decrypt->pGLBuffer, // a7 (sp + 28)
					decrypt->initusebuffer + 17456)) != 0) // a8 (sp + 32)
		return ret;

	// The firmware check routine above returns two sector counts minus 1
	// We end up copying the sectors as follows:
	// <start of file>
	//  * skip 512 bytes
	//  * copy sp_40 sectors plus 1
	//  * skip 1024 bytes
	//  * copy sp_41 sectors plus 1
	//  * skip 512 bytes
	//  * copy 30 - sp_40 - sp_41 sectors (for a total of 16k copied)
	// The sectors are concatenated into initUseBuffer and decrypted.

	int32_t sp_40_bytes = (((int32_t)sp_40) * 512) + 512;
	int32_t sp_41_bytes = (((int32_t)sp_41) * 512) + 512;

	/* 23a0 moved up */

	/* 23b4 */
	memset(inituse->loc560, 0, (16 * 1024));

	uint8_t *sectors_src = decrypt->pInOutBuffer + 512; /* 23c8 */
	uint8_t *sectors_dst = inituse->loc560;

	memcpy(sectors_dst, sectors_src, sp_40_bytes);

	sectors_src += sp_40_bytes + 1024; /* 23ec */
	sectors_dst += sp_40_bytes;
	memcpy(sectors_dst, sectors_src, sp_41_bytes);

	sectors_src += sp_41_bytes + 512; /* 2418 */
	sectors_dst += sp_41_bytes;
	memcpy(sectors_dst, sectors_src, (32 * 512) - sp_40_bytes - sp_41_bytes);

	/* This is really weird. This is passed to the decrypt-sector function and
	 * determines how much of each 512-byte sector to decrypt, where for every
	 * 32MB of size above the first 32MB, one 32 byte chunk of each sector
	 * (starting from the end) will remain unencrypted, up to a maximum of 480
	 * bytes of plaintext. Was this a speed-related thing? It just seems
	 * completely bizarre.
	*/
	int16_t rounds_to_perform = 16 - (decrypt->FileLength >> 0x19);
	if(rounds_to_perform <= 0)
		rounds_to_perform = 1;

	// Decrypt the concatenated block.
	uint8_t *current_sector = inituse->loc560; // 245c
	int length = 16 * 1024;

	while(length >= 512) {
		func_268c_c((uint32_t *)current_sector, (uint32_t *)inituse, rounds_to_perform); // 246c
		length -= 512;
		current_sector += 512;
	}

	// decrypt partial sector at the end.
	if(length != 0) { // 2510
		// TODO: This is clearly dead code, so what's it for?
		memcpy(inituse->loc16944, inituse->loc560, length);
		func_268c_c((uint32_t *)(inituse->loc16944), (uint32_t *)inituse, rounds_to_perform);
		memcpy(inituse->loc560, inituse->loc16944, length);
	}

	// The -2048 stuff here and below is because we skipped (512 + 1024 + 512)
	// bytes of data when copying in with the memcpy calls above.

	// Copy the decrypted data to the output buffer: it's always going to be 16k
	memcpy(decrypt->pInOutBuffer, inituse->loc560, decrypt->InOutLen-2048); // 2498

	// Store the number of rounds for later
	memcpy(&(decrypt->pGLBuffer[260]), &rounds_to_perform, 2);

	// Store encrypt key or encryption initial state?
	memcpy(&(decrypt->pGLBuffer[264]), inituse, 32);

	// Return the number of bytes decrypted.
	decrypt->InOutLen -= 2048;
	
	return 0; // success
}

// TODO
void func_fw_decrypt_run_c(uint32_t a0, uint32_t a1, uint32_t a2)
{
	uint32_t a3, ra, s0, s1, s2, s3, s4, s5, sp, v0, v1, zero;
	zero = 0;
	uint32_t stack[14];
	sp = (uint32_t)stack;

	a3 = (0xbfc3) << 16;     // 2550 lui a3,0xbfc3
	v1 = (0xbfc3) << 16;     // 2554 lui v1,0xbfc3
	*((uint32_t *)(sp + 36)) = s3;     // 2558 sw s3,36(sp)
	v0 = (0xbfc3) << 16;     // 255c lui v0,0xbfc3
	s3 = (uint32_t)__bss + 0x1520;     // 2560 la s3,__bss + 0x1520
	*((uint32_t *)(sp + 48)) = ra;     // 2564 sw ra,48(sp)
	*((uint32_t *)(sp + 44)) = s5;     // 2568 sw s5,44(sp)
	*((uint32_t *)(sp + 40)) = s4;     // 256c sw s4,40(sp)
	*((uint32_t *)(sp + 32)) = s2;     // 2570 sw s2,32(sp)
	*((uint32_t *)(sp + 28)) = s1;     // 2578 sw s1,28(sp)
	*((uint32_t *)(sp + 24)) = s0;     // 257c sw s0,24(sp)
	s5 = (uint32_t)__bss + 0x1320;     // 2580 la s5,__bss + 0x1320
	s0 = a2;     // 2584 move s0,a2
	s1 = a0;     // 2588 move s1,a0
	s2 = a1;     // 258c move s2,a1
	a0 = s3;     // 2590 move a0,s3
	a1 = zero;     // 2594 move a1,zero
	a2 = 32;     // 2598 li a2,32
	a3 = 1;     // 25a0 li a3,1
	memset((void *)a0, a1, a2);     // 259c jal memset
	a0 = s5;     // 25a4 move a0,s5
	a1 = zero;     // 25a8 move a1,zero
	a2 = 512;     // 25ac li a2,512
	a3 = 1;     // 25b4 li a3,1
	memset((void *)a0, a1, a2);     // 25b0 jal memset
	a0 = sp + 16;     // 25b8 addiu a0,sp,16
	a1 = s0 + 260;     // 25bc addiu a1,s0,260
	a2 = 2;     // 25c0 li a2,2
	a3 = zero;     // 25c8 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);     // 25c4 jal memcpy
	a0 = s3;     // 25cc move a0,s3
	a1 = s0 + 264;     // 25d0 addiu a1,s0,264
	a2 = 32;     // 25d4 li a2,32
	a3 = zero;     // 25dc move a3,zero
	memcpy((void *)a0, (void *)a1, a2);     // 25d8 jal memcpy
	a2 = (((int32_t)s2) < 512);     // 25e4 slti a2,s2,512
	goto __25fc;     // 25e0 b 9724

	__25e8:
	a2 = *((int16_t*)(16 + sp));     // 25e8 lh a2,16(sp)
	s2 = s2 + -512;     // 25f0 addiu s2,s2,-512
	func_268c_c((void *)a0, (void *)a1, a2);
	s1 = s1 + 512;     // 25f4 addiu s1,s1,512
	a2 = (((int32_t)s2) < 512);     // 25f8 slti a2,s2,512

	__25fc:
	a0 = s1;     // 25fc move a0,s1
	if(a2 == 0) {
		a1 = s3;     // 2604 move a1,s3
		goto __25e8;
	} else {
		a1 = s3;     // 2604 move a1,s3
	};     // 2600 beqz a2,9704

	if(s2 != 0) {
		ra = *((uint32_t *)(sp + 48));     // 260c lw ra,48(sp)
		goto __2630;
	} else {
		ra = *((uint32_t *)(sp + 48));     // 260c lw ra,48(sp)
	};     // 2608 bnez s2,9776

	return;     // 2628 jr ra

	__2630:
	a0 = s5;     // 2630 move a0,s5
	a1 = s1;     // 2634 move a1,s1
	a2 = s2;     // 2638 move a2,s2
	a3 = zero;     // 2640 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);     // 263c jal memcpy
	a2 = *((int16_t*)(16 + sp));     // 2644 lh a2,16(sp)
	a0 = s5;     // 2648 move a0,s5
	a1 = s3;     // 2650 move a1,s3
	func_268c_c((void *)a0, (void *)a1, a2);     // 264c jal func_268c
	a0 = s1;     // 2654 move a0,s1
	a1 = s5;     // 2658 move a1,s5
	a2 = s2;     // 265c move a2,s2
	a3 = zero;     // 2664 move a3,zero
	memcpy((void *)a0, (void *)a1, a2);     // 2660 jal memcpy
}

