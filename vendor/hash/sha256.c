///https://github.com/mygityf/cipher/blob/master/cipher/sha256.c
/*
 * SHA-256 algorithm as described at
 *
 *   http://csrc.nist.gov/cryptval/shs.html
 */
#include <string.h>
#include "sha256.h"
#include <errno.h>

 /* ----------------------------------------------------------------------
  * Core SHA256 algorithm: processes 16-word blocks into a message digest.
  */

#define ror(x, y) ( ((x) << (32-y)) | (((uint32_t)(x)) >> (y)) )
#define shr(x, y) ( (((uint32_t)(x)) >> (y)) )
#define Ch(x, y, z) ( ((x) & (y)) ^ (~(x) & (z)) )
#define Maj(x, y, z) ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define bigsigma0(x) ( ror((x),2) ^ ror((x),13) ^ ror((x),22) )
#define bigsigma1(x) ( ror((x),6) ^ ror((x),11) ^ ror((x),25) )
#define smallsigma0(x) ( ror((x),7) ^ ror((x),18) ^ shr((x),3) )
#define smallsigma1(x) ( ror((x),17) ^ ror((x),19) ^ shr((x),10) )

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)((value) >> 24), \
  (cp)[1] = (unsigned char)((value) >> 16), \
  (cp)[2] = (unsigned char)((value) >> 8), \
  (cp)[3] = (unsigned char)(value) )

static void SHA256_Core_Init(SHA256_Context* s) {
    s->h[0] = 0x6a09e667;
    s->h[1] = 0xbb67ae85;
    s->h[2] = 0x3c6ef372;
    s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f;
    s->h[5] = 0x9b05688c;
    s->h[6] = 0x1f83d9ab;
    s->h[7] = 0x5be0cd19;
}

static void SHA256_Block(SHA256_Context* s, const uint32_t* block) {
    uint32_t w[80];
    memset(w, 0, sizeof(w));
    uint32_t a, b, c, d, e, f, g, h;
    static const uint32_t k[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    int t;

    for (t = 0; t < 16; t++)
        w[t] = block[t];

    for (t = 16; t < 64; t++)
        w[t] = smallsigma1(w[t - 2]) + w[t - 7] + smallsigma0(w[t - 15]) + w[t - 16];

    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    f = s->h[5];
    g = s->h[6];
    h = s->h[7];

    for (t = 0; t < 64; t += 8) {
        uint32_t t1, t2;

#define ROUND(j, a, b, c, d, e, f, g, h) \
        t1 = h + bigsigma1(e) + Ch(e,f,g) + k[j] + w[j]; \
        t2 = bigsigma0(a) + Maj(a,b,c); \
        d = d + t1; h = t1 + t2;

        ROUND(t + 0, a, b, c, d, e, f, g, h);
        ROUND(t + 1, h, a, b, c, d, e, f, g);
        ROUND(t + 2, g, h, a, b, c, d, e, f);
        ROUND(t + 3, f, g, h, a, b, c, d, e);
        ROUND(t + 4, e, f, g, h, a, b, c, d);
        ROUND(t + 5, d, e, f, g, h, a, b, c);
        ROUND(t + 6, c, d, e, f, g, h, a, b);
        ROUND(t + 7, b, c, d, e, f, g, h, a);
    }

    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}

/* ----------------------------------------------------------------------
 * Outer SHA256 algorithm: take an arbitrary length byte string,
 * convert it into 16-word blocks with the prescribed padding at
 * the end, and pass those blocks to the core SHA256 algorithm.
 */

#define BLKSIZE 64

int32_t SHA256$$$Init(SHA256_Context* ctx) {
    if (NULL == ctx) {
        return EADDRNOTAVAIL;
    }
    SHA256_Core_Init(ctx);
    ctx->blk_used = 0;
    ctx->len_hi = ctx->len_lo = 0;
    return 0;
}

int32_t SHA256$$$Update(SHA256_Context* ctx, const void* data, size_t size) {
    if (NULL == ctx || NULL == data || 0 == size) {
        return EADDRNOTAVAIL;
    }
    uint8_t* q = (uint8_t*)data;
    uint32_t wordblock[16];
    memset(wordblock, 0, sizeof(wordblock));
    uint32_t lenw = size;
    int i;

    /*
     * Update the length field.
     */
    ctx->len_lo += lenw;
    ctx->len_hi += (ctx->len_lo < lenw);

    if (ctx->blk_used && ctx->blk_used + size < BLKSIZE) {
        /*
         * Trivial case: just add to the block.
         */
        memcpy(ctx->block + ctx->blk_used, q, size);
        ctx->blk_used += size;
    }
    else {
        /*
         * We must complete and process at least one block.
         */
        while (ctx->blk_used + size >= BLKSIZE) {
            memcpy(ctx->block + ctx->blk_used, q, BLKSIZE - ctx->blk_used);
            q += BLKSIZE - ctx->blk_used;
            size -= BLKSIZE - ctx->blk_used;
            /* Now process the block. Gather bytes big-endian into words */
            for (i = 0; i < 16; i++) {
                wordblock[i] =
                    (((uint32_t)ctx->block[i * 4 + 0]) << 24u) |
                    (((uint32_t)ctx->block[i * 4 + 1]) << 16u) |
                    (((uint32_t)ctx->block[i * 4 + 2]) << 8u) |
                    (((uint32_t)ctx->block[i * 4 + 3]) << 0u);
            }
            SHA256_Block(ctx, wordblock);
            ctx->blk_used = 0;
        }
        memcpy(ctx->block, q, size);
        ctx->blk_used = size;
    }
    return 0;
}

int32_t SHA256$$$Final(SHA256_Context* ctx, uint8_t message_digest[SHA256_DIGEST_SIZE]) {
    if (NULL == ctx || NULL == message_digest) {
        return EADDRNOTAVAIL;
    }
    int i;
    int pad;
    unsigned char c[64];
    uint32_t len_hi, len_lo;

    if (ctx->blk_used >= 56)
        pad = 56 + 64 - ctx->blk_used;
    else
        pad = 56 - ctx->blk_used;

    len_hi = (ctx->len_hi << 3u) | (ctx->len_lo >> (32u - 3u));
    len_lo = (ctx->len_lo << 3u);

    memset(c, 0, pad);
    c[0] = 0x80;
    SHA256$$$Update(ctx, &c, pad);

    c[0] = (len_hi >> 24u) & 0xFFu;
    c[1] = (len_hi >> 16u) & 0xFFu;
    c[2] = (len_hi >> 8u) & 0xFFu;
    c[3] = (len_hi >> 0u) & 0xFFu;
    c[4] = (len_lo >> 24u) & 0xFFu;
    c[5] = (len_lo >> 16u) & 0xFFu;
    c[6] = (len_lo >> 8u) & 0xFFu;
    c[7] = (len_lo >> 0u) & 0xFFu;

    SHA256$$$Update(ctx, &c, 8);

    for (i = 0; i < 8; i++) {
        message_digest[i * 4 + 0] = (ctx->h[i] >> 24u) & 0xFFu;
        message_digest[i * 4 + 1] = (ctx->h[i] >> 16u) & 0xFFu;
        message_digest[i * 4 + 2] = (ctx->h[i] >> 8u) & 0xFFu;
        message_digest[i * 4 + 3] = (ctx->h[i] >> 0u) & 0xFFu;
    }
    return 0;
}

int32_t sha256(const void* data, size_t size, uint8_t* message_digest) {
    if (NULL == data || 0 == size) {
        return EADDRNOTAVAIL;
    }
    SHA256_Context ctx;
    SHA256$$$Init(&ctx);
    SHA256$$$Update(&ctx, data, size);
    SHA256$$$Final(&ctx, message_digest);
    return 0;
}

//int SHA256_Simple(const void *data, size_t size, uint8_t message_digest[SHA256_DIGEST_SIZE]) {
//    if (NULL == data || 0 == size) {
//        return EADDRNOTAVAIL;
//    }
//    SHA256_Context ctx;
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, data, size);
//    SHA256_Final(&ctx, message_digest);
//    return 0;
//}