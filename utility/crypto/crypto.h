#ifndef GALAXY_CRYPTO_LDW6PQQOEGQH4JQPCZ3VJQPH_H
#define GALAXY_CRYPTO_LDW6PQQOEGQH4JQPCZ3VJQPH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIZE_NONCE 8u
#define SIZE_HMAC8 8u
#define SIZE_HMAC16 16u
#define SIZE_HMAC32 32u

typedef struct crypto_block_st
{
    uint8_t HashE[SIZE_HMAC8]; // mac256(HashL + Nonce + Length + Enc)
    uint8_t HashL[SIZE_HMAC8]; // mac256(Nonce + Length)
    uint8_t Nonce[SIZE_NONCE];
    uint8_t EncodedSizeAndEncrypted[];
} CryptoBlock;

typedef int32_t (*FuncPtr$$$Crypto$$$RandomBuffer)(void* buffer, size_t size);

int32_t Crypto$$$RandomBufferInsecure(void* buffer, size_t size);

// int32_t Crypto$$$SetRandomFunction(FuncPtr$$$Crypto$$$RandomBuffer func);

int32_t Crypto$$$EncodeInteger(int64_t inInteger, uint8_t outBuffer[8], size_t* outSize);

int32_t Crypto$$$DecodeInteger(const void* inBuffer, int64_t* outInteger, size_t* outNBytes);

int32_t Crypto$$$Encrypt(
    const void* inSecret, size_t inSecretSize,
    const void* inNonce,
    const void* inMessage, size_t inMessageSize,
    void* outHmac16,
    void* outEncrypted, size_t* outEncryptedSize
);

int32_t Crypto$$$Decrypt(
    const void* inSecret, size_t inSecretSize,
    const void* inHmac16, const void* inNonce,
    const void* inEncodedSizeAndEncrypted,
    void* outMessage, size_t* outMessageSize
);

int32_t Crypto$$$DecryptStream(
    const void* inSecret, size_t inSecretSize,
    const void* inStream,
    void* outMessage, size_t* outMessageSize
);

int32_t Crypto$$$DecryptBlock(
    const void* inSecret, size_t inSecretSize,
    const CryptoBlock* inBlock,
    void* outMessage, size_t* outMessageSize
);

#ifdef __cplusplus
}
#endif

#endif //GALAXY_CRYPTO_LDW6PQQOEGQH4JQPCZ3VJQPH_H