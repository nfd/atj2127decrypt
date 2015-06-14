#ifndef DECRYPT_IMPL_H
#define DECRYPT_IMPL_H
#include <stdint.h>

/* Scratch and i/o buffer sizes required by the assembly-language portion */
#define DECRYPT_INOUT_LENGTH 18432
#define DECRYPT_GL_LENGTH 300
#define DECRYPT_INIT_LENGTH 19888

struct decrypt_struct {
   unsigned char *pInOutBuffer;
   long InOutLen;
   long FileLength;
   unsigned char *pGLBuffer;
   unsigned char *initusebuffer;
   long initusebufferlen;
};

#define KEY_LENGTH 20

void func_97c_c(uint8_t *encstart, int length, uint8_t *scratch);
int func_abc_c(uint8_t *encstart, uint8_t *kworking, int length);
int func_b1c_c(uint8_t *enc);
int func_1db4(int file_length, uint8_t *data, int8_t *sector_count_1, int8_t *sector_count_2, uint8_t *inituse_plus_32, uint8_t *inituse, uint8_t *inituse_plus_48, uint8_t *pGLBuffer, uint8_t *inituse_plus_17456);
int func_268c(uint8_t *encrypted, uint8_t *working, int extra_512k_chunks);
int func_fw_decrypt_init_c(struct decrypt_struct *decrypt);

// readable names for 'external' interface
#define rodata_descramble func_b1c_c

#endif // DECRYPT_IMPL_H
