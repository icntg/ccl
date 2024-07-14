#ifndef BUFFER_PKWVGMMCNC3FPZFHNFCH6HOX_H
#define BUFFER_PKWVGMMCNC3FPZFHNFCH6HOX_H

#include <stdint.h>
#include <stdbool.h>

#define STRING_BUFFER_DEFAULT_LENGTH 256u
#define NULLCHAR '\0'


//Length new string buffers are initialized with

typedef struct buffer_byte_t
{
    size_t capacity; //max length
    size_t length; //current length
    uint8_t* buffer; //content
} BUFFER_BYTE;

BUFFER_BYTE* Buffer$$$Alloc();
void Buffer$$$Free(BUFFER_BYTE* b);
void Buffer$$$RequestCapacity(BUFFER_BYTE* b, size_t c);
void Buffer$$$AppendByte(BUFFER_BYTE* b, uint8_t c);
void Buffer$$$AppendBytes(BUFFER_BYTE* b, const void* s, size_t size);
void Buffer$$$InsertByte(BUFFER_BYTE* b, size_t pos, uint8_t c);
void Buffer$$$InsertBytes(BUFFER_BYTE* b, size_t pos, const void* s, size_t size);
void Buffer$$$Load(BUFFER_BYTE* b, const void* s, size_t size);
uint8_t *Buffer$$$Export(BUFFER_BYTE* b, void **ptr);
void Buffer$$$Print(BUFFER_BYTE* b, bool hex);

#endif //BUFFER_PKWVGMMCNC3FPZFHNFCH6HOX_H
