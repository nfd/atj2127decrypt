#ifndef DECRYPT_IMPL_H
#define DECRYPT_IMPL_H
#include <stdint.h>

#define RODATALENGTH 1024
#define KEY_LENGTH 20

void func_97c_c(uint8_t *encstart, int length, uint8_t *scratch);
int func_abc_c(uint8_t *encstart, uint8_t *kworking, int length);
int func_b1c_c(uint8_t *enc);

// readable names for 'external' interface
#define rodata_descramble func_b1c_c

#endif // DECRYPT_IMPL_H
