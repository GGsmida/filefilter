#ifndef __AESCRYPT_H__
#define __AESCRYPT_H__

#include "aes.h"
#include "sha256.h"

typedef struct {
    char aes[3];
    unsigned char version;
    unsigned char last_block_size;
} aescrypt_hdr;

typedef char sha256_t[32];

#endif // __AESCRYPT_H__
