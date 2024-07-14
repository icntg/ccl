///https://github.com/mygityf/cipher/blob/master/cipher/sha256.c
#include <string.h>
#include <errno.h>
#include "hmac.h"
#include "sha256.h"

#define block_size KEY_IO_PAD_SIZE
#define hash_size SHA256_DIGEST_SIZE

//static const size_t block_size = KEY_IO_PAD_SIZE;
//static const size_t hash_size = SHA256_DIGEST_SIZE;

int32_t HMAC256$$$Init(HMAC256_Context* ctx, const void* key, size_t size) {
    if (NULL == ctx || NULL == key || 0 == size) {
        return EADDRNOTAVAIL;
    }

    const uint8_t* _key = (const uint8_t *)key;
    size_t _size = size;
    uint8_t k_i_pad[block_size];
    memset(k_i_pad, 0, block_size);
    uint8_t temp_key[hash_size];
    memset(temp_key, 0, hash_size);
    if (size > block_size) {
        sha256(key, size, temp_key);
        _key = temp_key;
        _size = hash_size;
    }
    size_t i;
    for (i = 0; i < _size; i++) {
        k_i_pad[i] = _key[i] ^ 0x36u;
        ctx->k_o_pad[i] = _key[i] ^ 0x5cu;
    }
    for (; i < block_size; i++) {
        k_i_pad[i] = 0x36u;
        ctx->k_o_pad[i] = 0x5cu;
    }
    SHA256$$$Init(&ctx->shaContext);
    SHA256$$$Update(&ctx->shaContext, k_i_pad, block_size);
    return 0;
}
int32_t HMAC256$$$Update(HMAC256_Context* ctx, const void* data, size_t size) {
    if (NULL == ctx || NULL == data || 0 == size) {
        return EADDRNOTAVAIL;
    }
    return SHA256$$$Update(&ctx->shaContext, data, size);
}
int32_t HMAC256$$$Final(HMAC256_Context* ctx, uint8_t hmac[SHA256_DIGEST_SIZE]) {
    if (NULL == ctx || NULL == hmac) {
        return EADDRNOTAVAIL;
    }
    SHA256$$$Final(&ctx->shaContext, hmac);
    SHA256$$$Init(&ctx->shaContext);
    SHA256$$$Update(&ctx->shaContext, ctx->k_o_pad, block_size);
    SHA256$$$Update(&ctx->shaContext, hmac, hash_size);
    SHA256$$$Final(&ctx->shaContext, hmac);
    return 0;
}

int32_t hmac256(const void* key, size_t key_size, const void* data, size_t data_size, uint8_t* hmac) {
    if (NULL == key || 0 == key_size || NULL == data || 0 == data_size || NULL == hmac) {
        return EADDRNOTAVAIL;
    }
    HMAC256_Context ctx;
    HMAC256$$$Init(&ctx, key, key_size);
    HMAC256$$$Update(&ctx, data, data_size);
    HMAC256$$$Final(&ctx, hmac);
    return 0;
}

//int HMAC256_Simple(const void *key, size_t key_size,
//                    const void *data, size_t data_size, uint8_t hmac[SHA256_DIGEST_SIZE]) {
////    SHA256_Context context;
////    uint8_t k_i_pad[KEY_IO_PAD_SIZE];    /* inner padding - key XORd with ipad  */
////    uint8_t k_o_pad[KEY_IO_PAD_SIZE];    /* outer padding - key XORd with opad */
////    size_t i;
////
////    /* start out by storing key in pads */
////    memset(k_i_pad, 0, sizeof(k_i_pad));
////    memset(k_o_pad, 0, sizeof(k_o_pad));
////    memcpy(k_i_pad, key, key_size);
////    memcpy(k_o_pad, key, key_size);
////
////    /* XOR key with ipad and opad values */
////    for (i = 0; i < KEY_IO_PAD_SIZE; i++) {
////        k_i_pad[i] ^= 0x36u;
////        k_o_pad[i] ^= 0x5cu;
////    }
////
////    // perform inner SHA256
////    SHA256_Init(&context);                    /* init context for 1st pass */
////    SHA256_Update(&context, k_i_pad, KEY_IO_PAD_SIZE);      /* start with inner pad */
////    SHA256_Update(&context, data, data_size); /* then text of datagram */
////    SHA256_Final(&context, hmac);             /* finish up 1st pass */
////
////    // perform outer SHA256
////    SHA256_Init(&context);                   /* init context for 2nd pass */
////    SHA256_Update(&context, k_o_pad, KEY_IO_PAD_SIZE);     /* start with outer pad */
////    SHA256_Update(&context, hmac, SHA256_DIGEST_SIZE);     /* then results of 1st hash */
////    SHA256_Final(&context, hmac);          /* finish up 2nd pass */
//
//    if (NULL == key || 0 == key_size || NULL == data || 0 == data_size || NULL == hmac) {
//        return EADDRNOTAVAIL;
//    }
//    HMAC256_Context ctx;
//    HMAC256_Init(&ctx, key, key_size);
//    HMAC256_Update(&ctx, data, data_size);
//    HMAC256_Final(&ctx, hmac);
//    return 0;
//}