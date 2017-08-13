/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include "ber.h"

uint8_t *
ber_encode_vlint(uint8_t *out, uint32_t num)
{
    *out-- = (uint8_t) (num & 0x7F);
    num >>= 7;

    while (num) {
        *out-- = (uint8_t) ((num & 0x7F) | 0x80);
        num >>= 7;
    }

    return out;
}

uint8_t *
ber_decode_vlint(uint8_t *buf, uint32_t *num)
{
    int i;

    *num = (uint32_t) (*buf & 0x7F);
    for (i = 0; i < 4; ++i) {
        if ((*buf++ & 0x80) == 0) {
            return buf;
        }

        *num <<= 7;
        *num |= (*buf & 0x7F);
    }

    /* if 5th byte is not the last one,
     * the vlint is too long - invalid */
    return NULL;
}

uint8_t *
ber_encode_int(uint8_t *out, uint32_t num)
{
    uint8_t *out_end = out;
    uint8_t len;

    do {
        *out-- = (uint8_t) (num & 0xFF);
        num >>= 8;
    } while (num);

    len = (uint8_t) ((out_end - out) & 0xFF);
    *out-- = len;
    *out-- = BER_DATA_T_INTEGER;

    return out;
}

uint8_t *
ber_decode_int(uint8_t *buf, uint32_t *num)
{
    uint8_t i, len;

    buf++; /* ignore ber type, assume it's integer */
    len = *buf++;
    if (len > 4) {
        return NULL; /* won't fit in uint32_t */
    }

    *num = (uint32_t) (*buf++ & 0xFF);
    for (i = 1; i < len; ++i) {
        *num <<= 8;
        *num |= (uint8_t) (*buf++ & 0xFF);
    }

    return buf;
}

uint8_t *
ber_encode_length(uint8_t *out, uint32_t length)
{
    uint8_t *out_end = out;

    if (length < 0x80) {
        *out-- = (uint8_t) length;
        return out;
    }

    while (length) {
        *out-- = (uint8_t) (length & 0xFF);
        length >>= 8;
    }

    *out = (uint8_t) ((out_end - out) | 0x80);
    out--;

    return out;
}

uint8_t *
ber_decode_length(uint8_t *buf, uint32_t *length)
{
    uint8_t i, length_bytes;

    if ((*buf & 0x80) == 0) {
        *length = (uint32_t) *buf++;
        return buf;
    }

    length_bytes = (uint8_t) (*buf++ & 0x7F);
    if (length_bytes > 4) {
        return NULL; /* won't fit in uint32_t */
    }

    *length = (uint32_t) *buf++;
    for (i = 1; i < length_bytes; ++i) {
        *length <<= 8;
        *length |= *buf++;
    }

    return buf;
}

uint8_t *
ber_encode_string_len(uint8_t *out, const char *str, uint32_t str_len)
{
    uint32_t i;

    str += str_len - 1;
    for (i = 0; i < str_len; ++i) {
        *out-- = (uint8_t) *str--;
    }

    out = ber_encode_length(out, str_len);
    *out-- = BER_DATA_T_OCTET_STRING;

    return out;
}

uint8_t *
ber_encode_string(uint8_t *out, const char *str)
{
    uint32_t str_len = (uint32_t) strlen(str);

    return ber_encode_string_len(out, str, str_len);
}

uint8_t *
ber_decode_string_len_buffer(uint8_t *buf, const char **str, uint32_t *str_len)
{
    buf++;  /* ignore ber type, assume it's string */
    buf = ber_decode_length(buf, str_len);
    if (buf == NULL) {
        return NULL;
    }

    *str = (const char *) buf;

    return buf + *str_len;
}

uint8_t *
ber_decode_string_buffer(uint8_t *buf, const char **str, uint32_t maxlen, uint8_t *next)
{
    uint32_t str_len;

    buf = ber_decode_string_len_buffer(buf, str, &str_len);
    if (buf == NULL || str_len > maxlen) {
        return NULL;
    }

    *next = *buf;
    *buf = 0;

    return buf;
}

uint8_t *
ber_decode_string_alloc(uint8_t *buf, char **str, uint32_t maxlen)
{
    uint32_t str_len;

    buf++;  /* ignore ber type, assume it's string */
    buf = ber_decode_length(buf, &str_len);
    if (buf == NULL || str_len > maxlen) {
        return NULL;
    }

    *str = malloc(str_len + 1); /* +1 for NUL */
    if (*str == NULL) {
        return NULL;
    }

    memcpy(*str, buf, str_len);
    (*str)[str_len] = 0;

    return buf + str_len;
}

uint8_t *
ber_encode_null(uint8_t *out)
{
    *out-- = 0x00;
    *out-- = BER_DATA_T_NULL;

    return out;
}

uint8_t *
ber_decode_null(uint8_t *buf)
{
    return buf + 2;
}

struct ber_data {
    char type;
    union {
        uint32_t u;
        char *s;
    } value;
};

uint8_t *
ber_fprintf(uint8_t *out, char *fmt, ...)
{
    size_t fmt_len = strlen(fmt);
    va_list args;
    struct ber_data args_arr[128];
    struct ber_data *args_ptr = args_arr;

    if (fmt_len & 1) {
        return NULL;
    }

    va_start(args, fmt);
    while (*fmt++) {
        args_ptr->type = *fmt;
        switch (args_ptr->type) {
            case 'u':
                args_ptr->value.u = va_arg(args, uint32_t);
                break;
            case 's':
                args_ptr->value.s = va_arg(args, char *);
                break;
            case 'n':
                break;
            default:
                return NULL;
        }

        ++fmt;
        ++args_ptr;
    }
    va_end(args);

    while (--args_ptr >= args_arr) {
        switch (args_ptr->type) {
            case 'u':
                out = ber_encode_int(out, args_ptr->value.u);
                break;
            case 's':
                out = ber_encode_string_len(out, args_ptr->value.s,
                                            (uint32_t) strlen(args_ptr->value.s));
                break;
            case 'n':
                out = ber_encode_null(out);
                break;
            default:
                return NULL;
        }
    }
    
    return out + 1;
}

uint8_t *
ber_sscanf(uint8_t *buf, char *fmt, ...)
{
    va_list args;
    const char *str;
    uint32_t str_len;

    va_start(args, fmt);
    while (*fmt) {
        if (*fmt != '%') {
            return NULL;
        }

        switch (*++fmt) {
            case 'u':
                buf = ber_decode_int(buf, va_arg(args, uint32_t *));
                break;
            case 'a':
            case 'm':
                if (*++fmt != 's') {
                    return NULL;
                }

                buf = ber_decode_string_len_buffer(buf, &str, &str_len);
                *va_arg(args, char **) = strndup(str, str_len);
                break;
            case 'n':
                buf = ber_decode_null(buf);
                break;
            default:
                return NULL;
        }

        ++fmt;
    }
    va_end(args);

    return buf;
}

