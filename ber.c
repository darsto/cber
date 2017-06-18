/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include <stdarg.h>
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
ber_encode_length(uint8_t *out, uint32_t length)
{
    uint8_t length_bytes;

    if (length > 0x7F) {
        *out-- = (uint8_t) (length & 0xFF);
        length_bytes = 1;

        if (length > 0xFF) {
            *out-- = (uint8_t) ((length >> 8) & 0xFF);
            length_bytes = 2;
        }

        *out-- = (uint8_t) (length_bytes | 0x80);
    } else {
        *out-- = (uint8_t) length;
    }
    
    return out;
}

uint8_t *
ber_encode_string(uint8_t *out, const char *str, uint32_t str_len)
{
    uint32_t i;

    assert(str_len <= 0xFFFF); /* Sanity check */

    str += str_len - 1;
    for (i = 0; i < str_len; ++i) {
        *out-- = (uint8_t) *str--;
    }

    out = ber_encode_length(out, str_len);
    *out-- = BER_DATA_T_OCTET_STRING;

    return out;
}

uint8_t *
ber_encode_null(uint8_t *out)
{
    *out-- = 0x00;
    *out-- = BER_DATA_T_NULL;

    return out;
}

uint8_t *
ber_encode_data(uint8_t *out, int count, struct ber_data *data)
{
    struct ber_data *data_ptr;
    int i;

    for(i = count - 1; i >= 0; --i) {
        data_ptr = &data[i];
        switch (data_ptr->type) {
            case BER_DATA_T_INTEGER:
                out = ber_encode_int(out, data_ptr->u);
                break;
            case BER_DATA_T_OCTET_STRING:
                out = ber_encode_string(out, data_ptr->s, (uint32_t) strlen(data_ptr->s));
                break;
            case BER_DATA_T_NULL:
                out = ber_encode_null(out);
                break;
            default:
                return NULL;
        }
    }

    return out;
}

uint8_t *
ber_fprintf(uint8_t *out, char *fmt, ...)
{
    size_t fmt_len = strlen(fmt);
    va_list args;
    struct ber_data args_arr[128];
    struct ber_data *args_ptr = args_arr;
    uint8_t *ret;

    if (fmt_len & 1) {
        return NULL;
    }

    va_start(args, fmt);
    while (*fmt) {
        switch (*++fmt) {
            case 'u':
                args_ptr->type = BER_DATA_T_INTEGER;
                args_ptr->u = va_arg(args, uint32_t);
                break;
            case 's':
                args_ptr->type = BER_DATA_T_OCTET_STRING;
                args_ptr->s = va_arg(args, char *);
                break;
            case 'n':
                args_ptr->type = BER_DATA_T_NULL;
                break;
            default:
                return NULL;
        }

        ++fmt;
        ++args_ptr;
    }
    --args_ptr;
    va_end(args);

    ret = ber_encode_data(out, (int) (args_ptr - args_arr), args_arr);
    assert(ret);
    
    return ret + 1;
}
