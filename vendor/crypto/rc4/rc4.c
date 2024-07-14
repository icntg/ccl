#include "rc4.h"
#include "errno.h"
#include <string.h>


int32_t RC4$$$Init(const void* key, size_t len, void* outSBox) {
    if (NULL == key || len <= 0 || NULL == outSBox) {
        return EADDRNOTAVAIL;
    }
    int32_t i = 0, j = 0;
    uint8_t tmp = 0;
    uint8_t* box = outSBox;
    const uint8_t* k = key;
    for (i = 0; i < RC4_MAX; i++) {
        box[i] = i;
    }
    for (i = j = 0; i < RC4_MAX; i++) {
        j = (j + k[i % len] + box[i]) % RC4_MAX;
        tmp = box[i];
        box[i] = box[j];
        box[j] = tmp;
    }
    return 0;
}

int32_t RC4$$$Crypto(void* sBox, const void* in, size_t len, void* out) {
    if (NULL == sBox || NULL == in || len <= 0 || NULL == out) {
        return EADDRNOTAVAIL;
    }
    size_t i = 0, j = 0, k = 0;
    uint8_t tmp = 0;
    uint8_t* box = sBox;
    const uint8_t* _in = in;
    uint8_t* _out = out;
    for (k = 0; k < len; k++) {
        i = (i + 1) % RC4_MAX;
        j = (j + box[i]) % RC4_MAX;
        tmp = box[i];
        box[i] = box[j];
        box[j] = tmp;
        uint8_t t = (box[i] + box[j]) % RC4_MAX;
        _out[k] = _in[k] ^ box[t];
    }
    return 0;
}

int32_t rc4(const void* key, size_t key_size, const void* data, size_t data_size, void* out) {
    if (NULL == key || key_size <= 0 || NULL == data || data_size <= 0 || NULL == out) {
        return EADDRNOTAVAIL;
    }
    int32_t result = 0;
    uint8_t sbox[256];
    memset(sbox, 0, 256);
    result = RC4$$$Init(key, key_size, sbox);
    if (0 != result) {
        return -1;
    }
    result = RC4$$$Crypto(sbox, data, data_size, out);
    if (0 != result) {
        return -1;
    }
    return 0;
}
