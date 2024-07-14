#ifdef __cplusplus
extern "C" {
#endif

#ifndef GALAXY_BASE64_SM73KBJEBYOQH6NIJC7OIWPF_H
#define GALAXY_BASE64_SM73KBJEBYOQH6NIJC7OIWPF_H



#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#if (defined(WIN32) || defined(_WIN32)) && !defined(UNIX)
/* Do windows stuff */
    #include <Windows.h>
#ifndef bzero
    #define bzero ZeroMemory
#endif
#elif defined(UNIX) && !(defined(WIN32) || defined(_WIN32))
/* Do linux stuff */
#else
/* Error, both can't be defined or undefined same time */
#endif

#define BASE64_ENC_TABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
#define HEX_CHARS "0123456789abcdef"

/*********************** FUNCTION DECLARATIONS **********************/
// Returns the size of the output. If called with out = NULL, will just return
// the size of what the output would have been (without a terminating NULL).
int32_t Codec$$$UrlSafeBase64Encode(const void* in, size_t len, char* out);

// Returns the size of the output. If called with out = NULL, will just return
// the size of what the output would have been (without a terminating NULL).
int32_t Codec$$$UrlSafeBase64Decode(const char* in, void* out, size_t* outSize, char** endPtr);

int32_t Codec$$$Base16Encode(const void* in, size_t len, char* out);

#endif //GALAXY_BASE64_H

#ifdef __cplusplus
}
#endif