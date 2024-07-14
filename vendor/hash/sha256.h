///https://github.com/mygityf/cipher/blob/master/cipher/sha256.c


#ifndef _CIPHER_SHA256_YMZAXRXXWWRKNEBXSYDPP4W5_H
#define _CIPHER_SHA256_YMZAXRXXWWRKNEBXSYDPP4W5_H

#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#define SHA256_DIGEST_SIZE 32u
    //typedef unsigned int uint32;
    typedef struct {
        uint32_t h[8];
        uint8_t block[64];
        int blk_used;
        uint32_t len_hi, len_lo;
    } SHA256_Context;

    //int SHA256_Simple(const void *data, size_t size, uint8_t message_digest[SHA256_DIGEST_SIZE]);

    int32_t SHA256$$$Init(SHA256_Context* ctx);
    int32_t SHA256$$$Update(SHA256_Context* ctx, const void* data, size_t size);
    int32_t SHA256$$$Final(SHA256_Context* ctx, uint8_t message_digest[SHA256_DIGEST_SIZE]);

    int32_t sha256(const void* data, size_t size, uint8_t* message_digest);

#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_SHA256_H */