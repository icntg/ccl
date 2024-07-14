/**
 * from https://gist.github.com/meipp/a9022ac4d9b31a788ebcbdeb28a20ff0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"


//Creates new string buffer of default length and returns pointer to it.
BUFFER_BYTE* Buffer$$$Alloc()
{
    BUFFER_BYTE* b = malloc(sizeof(BUFFER_BYTE));
    b->capacity = STRING_BUFFER_DEFAULT_LENGTH;
    b->length = 0;
    b->buffer = malloc(b->capacity * sizeof(uint8_t));
    return b;
}

//Frees a buffer
void Buffer$$$Free(BUFFER_BYTE* b)
{
    if (b)
    {
        free(b->buffer);
        memset(b, 0, sizeof(BUFFER_BYTE));
        free(b);
    }
}

//Ensures that a given buffer has capacity of at least the size requested.
//I.e. ensures that a given buffer can store a string of specified length.
//Capacity is doubled until it suffices the requested size.
void Buffer$$$RequestCapacity(BUFFER_BYTE* b, const size_t c)
{
    const size_t old_capacity = b->capacity;

    while (b->capacity < c)
        b->capacity *= 2;

    uint8_t* s = malloc(b->capacity * sizeof(uint8_t));
    memcpy(s, b->buffer, old_capacity);

    free(b->buffer);
    b->buffer = s;
}

//Appends single char to buffer.
void Buffer$$$AppendByte(BUFFER_BYTE* b, const uint8_t c)
{
    Buffer$$$RequestCapacity(b, b->length + 1);
    b->buffer[b->length++] = c;
}

//Appends string of given length to buffer.
void Buffer$$$AppendBytes(BUFFER_BYTE* b, const void* s, const size_t size)
{
    Buffer$$$RequestCapacity(b, b->length + size);
    memcpy(b->buffer + b->length, s, size * sizeof(uint8_t));
    b->length += size;
}

//Inserts char at given position.
void Buffer$$$InsertByte(BUFFER_BYTE* b, const size_t pos, const uint8_t c)
{
    Buffer$$$RequestCapacity(b, b->length + 1);
    memmove(b->buffer + pos + 1, b->buffer + pos, (b->length - pos) * sizeof(uint8_t));
    b->buffer[pos] = c;
    b->length++;
}

//Inserts string of given length at given position.
void Buffer$$$InsertBytes(BUFFER_BYTE* b, size_t pos, const void* s, const size_t size)
{
    Buffer$$$RequestCapacity(b, b->length + size);
    memmove(b->buffer + pos + size, b->buffer + pos, (b->length - pos) * sizeof(uint8_t));
    memcpy(b->buffer + pos, s, size * sizeof(uint8_t));
    b->length += size;
}

//Loads given string into buffer.
void Buffer$$$Load(BUFFER_BYTE* b, const void* s, const size_t size)
{
    Buffer$$$RequestCapacity(b, size);
    b->length = size;
    memcpy(b->buffer, s, size * sizeof(uint8_t));
}

//Stores buffer content in and returns newly allocated block.
//If p != NULL, *p will also point to new block.
//The exported string will be null terminated.
uint8_t* Buffer$$$Export(BUFFER_BYTE* b, void** ptr)
{
    if (NULL == ptr)
    {
        return NULL;
    }
    uint8_t* s = malloc((b->length + 1) * sizeof(uint8_t));
    memset(s, 0, b->length + 1);
    memcpy(s, b->buffer, b->length * sizeof(uint8_t));
    s[b->length] = NULLCHAR;
    *ptr = s;
    return s;
}

//Prints buffer content to stdout.
//Only defined for char_t = char.
void Buffer$$$Print(BUFFER_BYTE* b, const bool hex)
{
    if (!hex)
    {
        Buffer$$$RequestCapacity(b, b->length + 1);
        b->buffer[b->length] = NULLCHAR;
        printf("%s", (const char*)b->buffer);
    }
    else
    {
        for(size_t i = 0; i < b->length; i++)
        {
            printf("%02x", b->buffer[i]);
        }
        printf("\n");
    }
}
