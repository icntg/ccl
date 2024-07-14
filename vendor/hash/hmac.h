#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef _CIPHER_HMAC_ALL_NADEP5YSUHVMJ2Z7TUM57YN4_H
#define _CIPHER_HMAC_ALL_NADEP5YSUHVMJ2Z7TUM57YN4_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "sha256.h"

#define KEY_IO_PAD_SIZE 64

typedef struct {
    SHA256_Context shaContext;    /* SHA context */
    uint8_t k_o_pad[KEY_IO_PAD_SIZE]; /* outer padding - key XORd with opad */
} HMAC256_Context;

int32_t HMAC256$$$Init(HMAC256_Context *ctx, const void *key, size_t size);
int32_t HMAC256$$$Update(HMAC256_Context *ctx, const void *data, size_t size);
int32_t HMAC256$$$Final(HMAC256_Context *ctx, uint8_t hmac[SHA256_DIGEST_SIZE]);

int32_t hmac256(const void *key, size_t key_size, const void *data, size_t data_size, uint8_t *hmac);
//int HMAC256_Simple(const void *key, size_t key_size,
//                    const void *data, size_t data_size, uint8_t hmac[SHA256_DIGEST_SIZE]);

#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_HMAC_ALL_H */