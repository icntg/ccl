#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto.h"

#include "../../vendor/hash/hmac.h"
#include "../../vendor/crypto/rc4/rc4.h"


static int32_t calcKeys(
    const void *inSecret, size_t inSecretSize,
    const uint8_t inNonce[SIZE_NONCE],
    uint8_t outEncKey[SIZE_HMAC32],
    uint8_t outMacKey[SIZE_HMAC32]
) {
    int32_t retCode;
    if (NULL == inSecret || inSecretSize <= 0 || NULL == inNonce || NULL == outEncKey || NULL == outMacKey) {
        retCode = EADDRNOTAVAIL;
        goto __ERROR__;
    }
    // 计算加密key
    retCode = hmac256(inNonce, SIZE_NONCE, inSecret, inSecretSize, outEncKey);
    if (0 != retCode) {
        goto __ERROR__;
    }
    // 计算校验key
    retCode = hmac256(inSecret, inSecretSize, inNonce, SIZE_NONCE, outMacKey);
    if (0 != retCode) {
        goto __ERROR__;
    }
    goto __FREE__;
__ERROR__:
    do {
    } while (0);
__FREE__:
    return retCode;
}

/**
 * 不安全的随机字节生成函数。在缺少系统随机数支持的情况下使用。
 * 随机数种子 依赖 1.当前时间；2.外部传入的buffer参数地址；3.buffer前四字节的内容；4.size的地址和内容
 * buffer参数地址有可能在栈上，也可能在堆里，也可能在全局变量中。
 * 总之一切是为了增加随机性。
 * @param buffer
 * @param size
 * @return
 */
int32_t Crypto$$$RandomBufferInsecure(void *buffer, const size_t size) {
    if (NULL == buffer || size <= 0) {
        return EADDRNOTAVAIL;
    }

    const int32_t result = 0;
    static unsigned int last_round = 0;
    uint64_t buffer_address64 = 0;
    memmove(&buffer_address64, &buffer, sizeof(void *));
    unsigned int buffer_address32 = (buffer_address64 >> 32) ^ buffer_address64;
    uint64_t size_address64 = 0;
    memmove(&size_address64, &size, sizeof(void *));
    unsigned int buffer_size32 = (size_address64 << 16) ^ (size_address64 >> 16);
    const unsigned int seed = ~((unsigned int) time(NULL) ^ buffer_address32 ^ *(unsigned int *) buffer) ^
                              buffer_size32 ^ size ^ last_round;

    memset(buffer, 0, size);
    srand(seed);
    for (size_t i = 0; i < size; i++) {
        uint8_t *p = buffer;
        p += i;
        const int r = rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
        const uint8_t n = r & 0xff;
        *p = n;
        const size_t j = (r | i) % sizeof(unsigned int);
        ((uint8_t *) &last_round)[j] ^= (uint8_t) (n + i);
    }
    return result & (int32_t) size;
}

/**
 *
 * @param inSecret
 * @param inSecretSize
 * @param inNonce
 * @param inMessage
 * @param inMessageSize
 * @param outHmac16
 * @param outEncrypted
 * @param outEncryptedSize
 * @return
 */
int32_t Crypto$$$Encrypt(
    const void *inSecret, const size_t inSecretSize,
    const void *inNonce,
    const void *inMessage, const size_t inMessageSize,
    void *outHmac16,
    void *outEncrypted, size_t *outEncryptedSize
) {
    int32_t retCode;
    if (NULL == outEncrypted && NULL != outEncryptedSize && inMessageSize > 0) {
        // calculate the size of out buffer
        size_t nBytes = 0;
        retCode = Crypto$$$EncodeInteger(inMessageSize, NULL, &nBytes);
        *outEncryptedSize = SIZE_HMAC16 + SIZE_NONCE + nBytes + inMessageSize;
        return retCode | EAGAIN;
    }
    if (NULL == inSecret || inSecretSize <= 0 ||
        NULL == inMessage || inMessageSize <= 0 ||
        NULL == inNonce || NULL == outHmac16 ||
        NULL == outEncrypted || NULL == outEncryptedSize
    ) {
        return EADDRNOTAVAIL;
    }

    size_t nLengthBytes = 0;
    uint8_t encKey[SIZE_HMAC32], macKey[SIZE_HMAC32], hash_e[SIZE_HMAC32], hash_l[SIZE_HMAC32];
    uint8_t *pl = (uint8_t *) outHmac16 + SIZE_HMAC8; {
        uint8_t lengthBytes[8];
        memset(lengthBytes, 0, 8);
        retCode = Crypto$$$EncodeInteger(inMessageSize, lengthBytes, &nLengthBytes);
        if (0 != retCode) {
            goto __ERROR__;
        }
        memset(outEncrypted, 0, nLengthBytes + inMessageSize);
        memmove(outEncrypted, lengthBytes, nLengthBytes);
    }


    memset(encKey, 0, SIZE_HMAC32);
    memset(macKey, 0, SIZE_HMAC32);
    memset(hash_l, 0, SIZE_HMAC32);
    memset(hash_e, 0, SIZE_HMAC32);

    memset(outHmac16, 0, SIZE_HMAC16);

    retCode = calcKeys(inSecret, inSecretSize, inNonce, encKey, macKey);
    if (0 != retCode) {
        goto __ERROR__;
    }

    // 计算 HashL
    HMAC256_Context ctx;
    memset(&ctx, 0, sizeof(HMAC256_Context));
    retCode = HMAC256$$$Init(&ctx, macKey, SIZE_HMAC32);
    retCode |= HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    retCode |= HMAC256$$$Update(&ctx, outEncrypted, nLengthBytes);
    retCode |= HMAC256$$$Final(&ctx, hash_l);
    if (0 != retCode) {
        goto __ERROR__;
    }

    retCode = rc4(
        encKey,
        SIZE_HMAC32,
        inMessage,
        inMessageSize,
        (uint8_t *) outEncrypted + nLengthBytes
    );
    if (0 != retCode) {
        goto __ERROR__;
    }

    // 计算 HashE
    retCode = HMAC256$$$Init(&ctx, macKey, SIZE_HMAC32);
    retCode |= HMAC256$$$Update(&ctx, hash_l, SIZE_HMAC8);
    retCode |= HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    retCode |= HMAC256$$$Update(&ctx, outEncrypted, nLengthBytes + inMessageSize);
    retCode |= HMAC256$$$Final(&ctx, hash_e);
    if (0 != retCode) {
        goto __ERROR__;
    }
    memmove(outHmac16, hash_e, SIZE_HMAC8);
    memmove(pl, hash_l, SIZE_HMAC8);

    *outEncryptedSize = nLengthBytes + inMessageSize;

    goto __FREE__;
__ERROR__:
    do {
    } while (0);
__FREE__:
    return retCode;
}

int32_t Crypto$$$Decrypt(
    const void *inSecret, size_t inSecretSize,
    const void *inHmac16, const void *inNonce,
    const void *inEncodedSizeAndEncrypted,
    void *outMessage, size_t *outMessageSize
) {
    int32_t retCode;
    if (NULL == outMessage && NULL != outMessageSize && NULL != inEncodedSizeAndEncrypted) {
        // 只提取长度信息
        size_t nLengthBytes;
        int64_t encryptedSize;
        retCode = Crypto$$$DecodeInteger(inEncodedSizeAndEncrypted, &encryptedSize, &nLengthBytes);
        if (0 != retCode) {
            goto __ERROR__;
        }
        retCode |= EAGAIN;
        goto __FREE__;
    }

    if (NULL == inSecret || inSecretSize <= 0 ||
        NULL == inHmac16 || NULL == inNonce ||
        NULL == inEncodedSizeAndEncrypted ||
        NULL == outMessage || NULL == outMessageSize) {
        return EADDRNOTAVAIL;
    }


    size_t nLengthBytes;
    int64_t encryptedSize;
    uint8_t encKey[SIZE_HMAC32], macKey[SIZE_HMAC32], expected[SIZE_HMAC32];
    HMAC256_Context ctx;

    memset(encKey, 0, SIZE_HMAC32);
    memset(macKey, 0, SIZE_HMAC32);
    memset(expected, 0, SIZE_HMAC32);
    uint8_t *pl = (uint8_t *) inHmac16 + SIZE_HMAC8;

    retCode = Crypto$$$DecodeInteger(inEncodedSizeAndEncrypted, &encryptedSize, &nLengthBytes);
    if (0 != retCode) {
        goto __ERROR__;
    }

    retCode = calcKeys(inSecret, inSecretSize, inNonce, encKey, macKey);
    if (0 != retCode) {
        goto __ERROR__;
    }

    // 校验 Hash-L
    memset(&ctx, 0, sizeof(HMAC256_Context));
    HMAC256$$$Init(&ctx, macKey, SIZE_HMAC32);
    HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    HMAC256$$$Update(&ctx, inEncodedSizeAndEncrypted, nLengthBytes);
    HMAC256$$$Final(&ctx, expected);

    if (0 != memcmp(expected, pl, SIZE_HMAC8)) {
        retCode = EBADMSG;
        goto __ERROR__;
    }

    // 校验 Hash-E
    memset(&ctx, 0, sizeof(HMAC256_Context));
    HMAC256$$$Init(&ctx, macKey, SIZE_HMAC32);
    HMAC256$$$Update(&ctx, pl, SIZE_HMAC8);
    HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    HMAC256$$$Update(&ctx, inEncodedSizeAndEncrypted, nLengthBytes + encryptedSize);
    HMAC256$$$Final(&ctx, expected);


    if (0 != memcmp(inHmac16, expected, SIZE_HMAC8)) {
        retCode = EBADMSG;
        goto __ERROR__;
    }

    const uint8_t *encrypted = (uint8_t *) inEncodedSizeAndEncrypted + nLengthBytes;
    retCode = rc4(
        encKey,
        SIZE_HMAC32,
        encrypted,
        encryptedSize,
        outMessage
    );
    if (0 != retCode) {
        goto __ERROR__;
    }
    *outMessageSize = encryptedSize;
    goto __FREE__;

__ERROR__:
    do {
    } while (0);
    // PASS;
__FREE__:

    return retCode;
}

int32_t Crypto$$$EncodeInteger(const int64_t inInteger, uint8_t outBuffer[8], size_t *outSize) {
    if (NULL == outBuffer || NULL == outSize) {
        return EADDRNOTAVAIL;
    }
    int32_t retCode = 0;
    // string s;
    static int64_t _max_ = 1;
    if (1 == _max_) {
        _max_ = _max_ << 42;
    }
    if (inInteger < 0 || inInteger >= _max_) {
        return EINVAL;
    }
    if (inInteger < 128) {
        outBuffer[0] = (uint8_t) inInteger;
        *outSize = 1;
        goto __FREE__;
    }
    uint8_t buffer[8];
    memset(buffer, 0, 8);
    int idx = 0; {
        int64_t n = inInteger;

        while (n > 0) {
            int64_t fn = n & 0x3f;
            n = n >> 6;
            int64_t v = (uint8_t) ((0x80 | fn) & 0xbf);
            buffer[idx] = v;
            idx++;
            int64_t hlc = 8 - idx - 2;
            if (n >= (1 << hlc)) {
                continue;
            }
            int64_t hh = ((1 << (idx + 1)) - 1) << (hlc + 1);
            int64_t hb = hh | n;
            buffer[idx] = (uint8_t) hb;
            idx++;
            break;
        }
    }
    if (idx > 6) {
        retCode = EINVAL;
        goto __ERROR__;
    }
    *outSize = idx;
    if (NULL != outBuffer) {
        memset(outBuffer, 0, 8);
        for (int i = 0; i < idx; i++) {
            int j = idx - i - 1;
            outBuffer[j] = buffer[i];
        }
    }
    goto __FREE__;
__ERROR__:
    do {
    } while (0);
__FREE__:
    return retCode;
}

int32_t Crypto$$$DecodeInteger(const void *inBuffer, int64_t *outInteger, size_t *outNBytes) {
    if (NULL == inBuffer || NULL == outInteger || NULL == outNBytes) {
        return EADDRNOTAVAIL;
    }
    const uint8_t *s = inBuffer;
    const uint8_t header = s[0];
    if (s[0] >> 7 == 0) {
        *outInteger = header;
        *outNBytes = 1;
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < 7; i++) {
        const size_t rn = 7 - i;
        if (((header >> rn) & 1u) == 0u) {
            n = i;
            break;
        }
    }
    if (n == 0) {
        return EINVAL;
    }
    int64_t tail = 0;
    for (size_t i = 1; i < n; i++) {
        if (s[i] >> 6 != 2) {
            return -(int64_t) i - 1;
        }
        tail = (tail << 6) | (s[i] & 0x3f);
    }
    const uint8_t mask = (1 << (8 - n)) - 1;
    const int64_t offset = 6 * (n - 1);
    *outInteger = ((header & mask) << offset) | tail;
    *outNBytes = n;
    return 0;
}

int32_t Crypto$$$DecryptStream(
    const void *inSecret, const size_t inSecretSize,
    const void *inStream,
    void *outMessage, size_t *outMessageSize
) {
    const uint8_t *hmac16 = inStream;
    const uint8_t *nonce = (const uint8_t *) inStream + SIZE_HMAC16;
    const uint8_t *stream = (const uint8_t *) inStream + SIZE_HMAC16 + SIZE_NONCE;

    int64_t encryptedSize;
    size_t nBytes;
    Crypto$$$DecodeInteger(stream, &encryptedSize, &nBytes);


    return Crypto$$$Decrypt(
        inSecret, inSecretSize,
        hmac16, nonce,
        stream,
        outMessage, outMessageSize
    );
}

int32_t Crypto$$$DecryptBlock(
    const void *inSecret, const size_t inSecretSize,
    const CryptoBlock *inBlock,
    void *outMessage, size_t *outMessageSize
) {
    return Crypto$$$DecryptStream(
        inSecret, inSecretSize,
        inBlock,
        outMessage, outMessageSize
    );
}
