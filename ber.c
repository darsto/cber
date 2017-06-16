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
ber_encode_string(uint8_t *out, const char *str, uint32_t str_len)
{
    uint8_t str_len_len;
    uint32_t i;

    assert(str_len <= 0xFFFF); /* Sanity check */

    str += str_len - 1;
    for (i = 0; i < str_len; ++i) {
        *out-- = (uint8_t) *str--;
    }

    if (str_len > 0x7F) { // TODO: or forced long form
        *out-- = (uint8_t) (str_len & 0xFF);
        str_len_len = 1;

        if (str_len > 0xFF) {
            *out-- = (uint8_t) ((str_len >> 8) & 0xFF);
            str_len_len = 2;
        }

        *out-- = (uint8_t) (str_len_len | 0x80);
    } else {
        *out-- = (uint8_t) str_len;
    }

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

static uint8_t *
encode_ber_data(uint8_t *out, int count, struct ber_data *data)
{
    for(; count >= 0; --count, --data) {
        switch (data->type) {
            case BER_DATA_T_INTEGER:
                out = ber_encode_int(out, data->u);
                break;
            case BER_DATA_T_OCTET_STRING:
                out = ber_encode_string(out, data->s, (uint32_t) strlen(data->s));
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
ber_encode_data(uint8_t *out, uint32_t data_count, ...)
{
    va_list args;
    struct ber_data *args_arr[128];
    int i;

    va_start(args, data_count);
    for (i = 0; i < data_count; ++i) {
        args_arr[i] = va_arg(args, struct ber_data *);
    }
    --i;
    va_end(args);

    return encode_ber_data(out, i, args_arr[i]) + 1;
}

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

    return encode_ber_data(out, (int) (args_ptr - args_arr), args_ptr) + 1;
}
