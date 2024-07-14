#ifdef __cplusplus
extern "C" {
#endif

#ifndef GALAXY_RC4_E5OSH6YQHBIGAWH4IEQWICL5_H
#define GALAXY_RC4_E5OSH6YQHBIGAWH4IEQWICL5_H

#include <stdint.h>
#include <stdlib.h>

#define RC4_MAX 256u

int32_t RC4$$$Init(const void* key, size_t len, void* outSBox);

int32_t RC4$$$Crypto(void* sBox, const void* in, size_t len, void* out);

int32_t rc4(const void* key, size_t key_size, const void* data, size_t data_size, void* out);

#endif //GALAXY_RC4_H

#ifdef __cplusplus
}
#endif