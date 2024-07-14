#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto.h"

#include "../../vendor/hash/hmac.h"
#include "../../vendor/crypto/rc4/rc4.h"


// int32_t Crypto$$$SetRandomFunction(const FuncPtr$$$Crypto$$$RandomBuffer func)
// {
//     random = func;
//     return 0;
// }

/**
 * 不安全的随机字节生成函数。
 * 依赖当前时间和外部传入的buffer参数地址。
 * buffer参数地址有可能在栈上，也可能在堆里，也可能在全局变量中。
 * 总之是为了增加随机性。
 * @param buffer
 * @param size
 * @return
 */
int32_t Crypto$$$RandomBufferInsecure(void* buffer, const size_t size)
{
    const int32_t result = 0;
    const size_t n = size / sizeof(unsigned int);
    const size_t m = size % sizeof(unsigned int);
    uint8_t* _buffer = buffer;
    memset(buffer, 0, size);

    const unsigned int seed = ~((unsigned int)time(NULL) ^ (unsigned int)buffer);
    srand(seed);
    for (size_t i = 0; i < n; i++)
    {
        unsigned int r = (unsigned int)rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
        memcpy(_buffer + i * sizeof(unsigned int), &r, sizeof(unsigned int));
    }
    if (m > 0)
    {
        const unsigned int r = (unsigned int)rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
        memcpy(_buffer + sizeof(unsigned int) * n, &r, m);
    }
    return result & (int32_t)size;
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
    const void* inSecret, const size_t inSecretSize,
    const void* inNonce,
    const void* inMessage, const size_t inMessageSize,
    void* outHmac16,
    void* outEncrypted, size_t* outEncryptedSize
)
{
    int32_t retCode = 0;
    if (NULL != outEncryptedSize && inMessageSize > 0)
    {
        // calculate the size of out buffer
        size_t nbytes = 0;
        retCode = Crypto$$$EncodeUint32(inMessageSize, NULL, &nbytes);
        *outEncryptedSize = SIZE_HMAC16 + SIZE_NONCE + nbytes + inMessageSize;
        return EAGAIN;
    }
    if (NULL == inSecret || inSecretSize <= 0 ||
        NULL == inMessage || inMessageSize <= 0 ||
        NULL == inNonce || NULL == outHmac16 ||
        NULL == outEncrypted || NULL == outEncryptedSize
    )
    {
        return EADDRNOTAVAIL;
    }

    size_t nLengthBytes;

    {
        uint8_t lengthBytes[8];
        retCode = Crypto$$$EncodeUint32(inMessageSize, lengthBytes, &nLengthBytes);
        if (0 != retCode)
        {
            goto __ERROR__;
        }
        memset(outEncrypted, 0, nLengthBytes + inMessageSize);
        memcpy(outEncrypted, lengthBytes, nLengthBytes);
    }

    uint8_t enc_key[SIZE_HMAC32], hsh_key[SIZE_HMAC32], enc_hash[SIZE_HMAC32];
    memset(enc_key, 0, SIZE_HMAC32);
    memset(hsh_key, 0, SIZE_HMAC32);
    memset(enc_hash, 0, SIZE_HMAC32);

    memset(outHmac16, 0, SIZE_HMAC16);

    retCode = hmac256(inNonce, SIZE_NONCE, inSecret, inSecretSize, enc_key);
    if (0 != retCode)
    {
        goto __ERROR__;
    }
    retCode = hmac256(inSecret, inSecretSize, inNonce, SIZE_NONCE, hsh_key);
    if (0 != retCode)
    {
        goto __ERROR__;
    }

    retCode = rc4(
        enc_key,
        SIZE_HMAC32,
        inMessage,
        inMessageSize,
        (uint8_t *)outEncrypted + nLengthBytes
    );
    if (0 != retCode)
    {
        goto __ERROR__;
    }

    uint8_t hmac_buffer[SIZE_HMAC32];
    memset(hmac_buffer, 0, SIZE_HMAC32);
    HMAC256_Context ctx;
    memset(&ctx, 0, sizeof(HMAC256_Context));
    retCode = HMAC256$$$Init(&ctx, hsh_key, SIZE_HMAC32);
    retCode |= HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    retCode |= HMAC256$$$Update(&ctx, outEncrypted, nLengthBytes + inMessageSize);
    retCode |= HMAC256$$$Final(&ctx, hmac_buffer);
    if (0 != retCode)
    {
        goto __ERROR__;
    }
    memcpy(outHmac16, hmac_buffer, SIZE_HMAC16);

    *outEncryptedSize = nLengthBytes + inMessageSize;

    goto __FREE__;
__ERROR__:
    do
    {
    }
    while (0);
__FREE__:
    return retCode;
}

int32_t Crypto$$$Decrypt(
    const void* inSecret, size_t inSecretSize,
    const void* inHmac16, const void* inNonce,
    const void* inEncodedSizeAndEncrypted,
    void* outMessage, size_t* outMessageSize
)
{
    if (NULL == inSecret || inSecretSize <= 0 ||
        NULL == inHmac16 || NULL == inNonce ||
        NULL == inEncodedSizeAndEncrypted ||
        NULL == outMessage || NULL == outMessageSize)
    {
        return EADDRNOTAVAIL;
    }
    int32_t retCode = 0;

    size_t nLengthBytes;
    uint32_t encryptedSize;
    retCode = Crypto$$$DecodeUint32(inEncodedSizeAndEncrypted, &encryptedSize, &nLengthBytes);
    if (0 != retCode)
    {
        goto __ERROR__;
    }


    uint8_t enc_key[SIZE_HMAC32], hsh_key[SIZE_HMAC32], expected_hash[SIZE_HMAC32];
    memset(enc_key, 0, SIZE_HMAC32);
    memset(hsh_key, 0, SIZE_HMAC32);
    memset(expected_hash, 0, SIZE_HMAC32);

    retCode = hmac256(inSecret, inSecretSize, inNonce, SIZE_NONCE, hsh_key);
    if (0 != retCode)
    {
        goto __ERROR__;
    }

    HMAC256_Context ctx;
    memset(&ctx, 0, sizeof(HMAC256_Context));
    HMAC256$$$Init(&ctx, hsh_key, SIZE_HMAC32);
    HMAC256$$$Update(&ctx, inNonce, SIZE_NONCE);
    HMAC256$$$Update(&ctx, inEncodedSizeAndEncrypted, nLengthBytes + encryptedSize);
    HMAC256$$$Final(&ctx, expected_hash);

    if (0 != memcmp(inHmac16, expected_hash, SIZE_HMAC16))
    {
        retCode = EBADMSG;
        goto __ERROR__;
    }

    retCode = hmac256(inNonce, SIZE_NONCE, inSecret, inSecretSize, enc_key);
    if (0 != retCode)
    {
        goto __ERROR__;
    }
    const uint8_t* encrypted = (uint8_t*)inEncodedSizeAndEncrypted + nLengthBytes;
    retCode = rc4(
        enc_key,
        SIZE_HMAC32,
        encrypted,
        encryptedSize,
        outMessage
    );
    if (0 != retCode)
    {
        goto __ERROR__;
    }
    *outMessageSize = encryptedSize;
    goto __FREE__;

__ERROR__:
    do
    {
    }
    while (0);
    // PASS;
__FREE__:

    return retCode;
}

int32_t Crypto$$$EncodeUint32(const uint32_t inInteger, uint8_t outBuffer[8], size_t* outSize)
{
    if (NULL == outSize)
    {
        return EADDRNOTAVAIL;
    }
    int32_t retCode = 0;
    // string s;
    if (inInteger < 0 || inInteger >= (1 << 31))
    {
        return EINVAL;
    }
    if (inInteger < 128)
    {
        outBuffer[0] = (uint8_t)inInteger;
        goto __FREE__;
    }
    uint8_t buffer[8];
    memset(buffer, 0, 8);
    int idx = 0;
    {
        uint32_t n = inInteger;

        while (n > 0)
        {
            uint32_t fn = n & 0x3f;
            n = n >> 6;
            uint32_t v = (uint8_t)((0x80 | fn) & 0xbf);
            buffer[idx] = v;
            idx++;
            uint32_t hlc = 8 - idx - 2;
            if (n >= (1 << hlc))
            {
                continue;
            }
            uint32_t hh = ((1 << (idx + 1)) - 1) << (hlc + 1);
            uint32_t hb = hh | n;
            buffer[idx] = (uint8_t)hb;
            idx++;
            break;
        }
    }
    if (idx > 6)
    {
        retCode = EINVAL;
        goto __ERROR__;
    }
    *outSize = idx;
    if (NULL != outBuffer)
    {
        memset(outBuffer, 0, 8);
        for (int i = 0; i < idx; i++)
        {
            int j = idx - i - 1;
            outBuffer[j] = buffer[i];
        }
    }
    goto __FREE__;
__ERROR__:
    do
    {
    }
    while (0);
__FREE__:
    return retCode;
}

int32_t Crypto$$$DecodeUint32(const void* inBuffer, uint32_t* outInteger, size_t* outNBytes)
{
    if (NULL == inBuffer || NULL == outInteger || NULL == outNBytes)
    {
        return EADDRNOTAVAIL;
    }
    const uint8_t* s = inBuffer;
    const uint8_t header = s[0];
    if (s[0] >> 7 == 0)
    {
        *outInteger = header;
        *outNBytes = 1;
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < 7; i++)
    {
        const size_t rn = 7 - i;
        if (((header >> rn) & 1u) == 0u)
        {
            n = i;
            break;
        }
    }
    if (n == 0)
    {
        return EINVAL;
    }
    uint32_t tail = 0;
    for (size_t i = 1; i < n; i++)
    {
        if (s[i] >> 6 != 2)
        {
            return -(int32_t)i - 1;
        }
        tail = (tail << 6) | (s[i] & 0x3f);
    }
    const uint8_t mask = (1 << (8 - n)) - 1;
    const uint32_t offset = 6 * (n - 1);
    *outInteger = ((header & mask) << offset) | tail;
    *outNBytes = n;
    return 0;
}

int32_t Crypto$$$DecryptStream(
    const void* inSecret, const size_t inSecretSize,
    const void* inStream,
    void* outMessage, size_t* outMessageSize
)
{
    const uint8_t* hmac16 = inStream;
    const uint8_t* nonce = (const uint8_t*)inStream + SIZE_HMAC16;
    const uint8_t* stream = (const uint8_t*)inStream + SIZE_HMAC16 + SIZE_NONCE;

    uint32_t encryptedSize;
    size_t nbytes;
    Crypto$$$DecodeUint32(stream, &encryptedSize, &nbytes);


    return Crypto$$$Decrypt(
        inSecret, inSecretSize,
        hmac16, nonce,
        stream,
        outMessage, outMessageSize
    );
}

int32_t Crypto$$$DecryptBlock(
    const void* inSecret, const size_t inSecretSize,
    const CryptoBlock* inBlock,
    void* outMessage, size_t* outMessageSize
)
{
    return Crypto$$$DecryptStream(
        inSecret, inSecretSize,
        inBlock,
        outMessage, outMessageSize
    );
}
