#include <stdio.h>
#include <stdint.h>
#include <tchar.h>
#include "cutest/cutest.h"

#include "../utility/crypto/crypto.h"
#include "../vendor/codec/base64.h"

static void TestUtilityCrypto(CuTest *tc) {
    unsigned char nonce[8];
    for(int t = 0; t < 16; t++)
    {
        Crypto$$$RandomBufferInsecure(nonce, 8);
        uint8_t* p = nonce;
        for (int i = 0; i < 8; i++)
        {
            printf("%02x", *p);
            p++;
            fflush(stdout);
        }
        puts("");
        fflush(stdout);
    }

    memcpy(nonce, "\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    TCHAR a[] = "Things base and vile, holding no quantity, love can transpose to from and dignity: love looks not with the eyes, but with mind. (A Midsummer Night’s Dream 1.1)\n\t卑贱和劣行在爱情看来都不算数，都可以被转化成美满和庄严：爱情不用眼睛辨别，而是用心灵来判断/爱用的不是眼睛，而是心。——《仲夏夜之梦》";
    TCHAR key[] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

    uint8_t enc_buf[4096], dec_buf[4096], buffer[8192];
    memset(enc_buf, 0, sizeof(enc_buf));
    memset(dec_buf, 0, sizeof(dec_buf));
    memset(buffer, 0, sizeof(buffer));
    const size_t size = _tcslen(a) + 1;
    size_t nbytes;
    Crypto$$$Encrypt(key, 32, nonce, a, size, enc_buf, enc_buf + 24, &nbytes);
    memcpy(enc_buf + 16, nonce, 8);
    printf("nbytes = %ld\n", nbytes);
    Codec$$$Base16Encode(enc_buf, 16 + nbytes, buffer);
    printf("%s\n", (PCTSTR)buffer);

    Crypto$$$DecryptStream(key, 32, enc_buf, dec_buf, &nbytes);
    printf("nbytes = %ld\n", nbytes);
    printf("message = %s\n", (PCTSTR)dec_buf);

    CuAssertStrEquals(tc, 0, _tcscmp(a, dec_buf));
}

CuSuite* TestUtilityCryptoSuite() {
    CuSuite* suite = CuSuiteNew();
    SUITE_ADD_TEST(suite, TestUtilityCrypto);
    return suite;
}