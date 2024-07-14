#include <string.h>
#include <errno.h>
#include "base64.h"


static char BUFFER_DEC_TAB[256] = { 0 };
static char* DEC_TAB = NULL;
static const uint8_t MOD_TAB[] = { 0, 2, 1 };

static void makeDecodeTable() {
    memset(BUFFER_DEC_TAB, -1, 256);
    for (size_t i = 0; i < strlen(BASE64_ENC_TABLE); i++) {
        size_t j = (size_t)BASE64_ENC_TABLE[i];
        BUFFER_DEC_TAB[j] = (char)i;
    }
    DEC_TAB = BUFFER_DEC_TAB;
}

int32_t Codec$$$UrlSafeBase64Encode(const void* in, size_t len, char* out) {
    if (NULL == in || len <= 0 || NULL == out) {
        return EADDRNOTAVAIL;
    }
    const uint8_t* _in = (const uint8_t*)in;
    int32_t outLen = 4 * ((len + 2) / 3);
    bzero(out, outLen + 1);
    for (size_t i = 0, j = 0; i < len;) {

        uint32_t octet_a = i < len ? (unsigned char)_in[i++] : 0;
        uint32_t octet_b = i < len ? (unsigned char)_in[i++] : 0;
        uint32_t octet_c = i < len ? (unsigned char)_in[i++] : 0;

        uint32_t triple = ((unsigned)octet_a << 0x10u) + ((unsigned)octet_b << 0x08u) + octet_c;

        out[j++] = BASE64_ENC_TABLE[(triple >> 3u * 6u) & 0x3Fu];
        out[j++] = BASE64_ENC_TABLE[(triple >> 2u * 6u) & 0x3Fu];
        out[j++] = BASE64_ENC_TABLE[(triple >> 1u * 6u) & 0x3Fu];
        out[j++] = BASE64_ENC_TABLE[(triple >> 0u * 6u) & 0x3Fu];
    }

    for (size_t i = 0; i < MOD_TAB[len % 3]; i++) {
        out[outLen - 1 - i] = '=';
    }

    return 0;
}


int32_t Codec$$$UrlSafeBase64Decode(const char* in, void* out, size_t* outSize, char** endPtr) {
    if (NULL == in || NULL == out) {
        return EADDRNOTAVAIL;
    }
    if (NULL == DEC_TAB) {
        makeDecodeTable();
    }
    uint8_t* _out = (uint8_t*)out;
    size_t inLen = strlen(in);
    if (inLen % 4 != 0) {
        return -1;
    }
    *outSize = inLen / 4 * 3;
    bzero(out, *outSize);
    if (in[inLen - 1] == '=') {
        (*outSize)--;
    }
    if (in[inLen - 2] == '=') {
        (*outSize)--;
    }

    for (size_t i = 0, j = 0; i < inLen;) {
        uint32_t s[4] = { 0 };
        for (size_t k = 0; k < 4; k++) {
            if (NULL != endPtr) {
                *endPtr = (char*)(in) + i;
            }
            char c = in[i];
            char t = c == '=' ? 0 : DEC_TAB[(size_t)c];
            if (t < 0 || t > 63) {
                return -2;
            }
            s[k] = (uint32_t)t;
            i++;
        }
        uint32_t sextet_a = s[0];
        uint32_t sextet_b = s[1];
        uint32_t sextet_c = s[2];
        uint32_t sextet_d = s[3];

        uint32_t triple = (sextet_a << 3u * 6u)
            + (sextet_b << 2u * 6u)
            + (sextet_c << 1u * 6u)
            + (sextet_d << 0u * 6u);

        if (j < *outSize) _out[j++] = (triple >> 2u * 8u) & 0xFFu;
        if (j < *outSize) _out[j++] = (triple >> 1u * 8u) & 0xFFu;
        if (j < *outSize) _out[j++] = (triple >> 0u * 8u) & 0xFFu;
    }
    if (NULL != endPtr) {
        *endPtr = NULL;
    }
    return 0;
}

int32_t Codec$$$Base16Encode(const void* in, size_t len, char* out) {
    if (NULL == in || len <= 0 || NULL == out) {
        return EADDRNOTAVAIL;
    }
    const uint8_t* _in = (const uint8_t*)in;
    int32_t n = (len << 1u) + 1;
    bzero(out, n);
    for (size_t i = 0; i < len; i++) {
        uint8_t c = _in[i];
        char hi = HEX_CHARS[((unsigned)c >> 4u) & 0x0fu];
        char lo = HEX_CHARS[c & 0x0fu];
        out[i * 2] = hi;
        out[i * 2 + 1] = lo;
    }
    return 0;
}