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

/** ASN.1 primitives */
enum ber_data_type {
    BER_DATA_T_INTEGER = 0x02,
    BER_DATA_T_OCTET_STRING = 0x04,
    BER_DATA_T_NULL = 0x05,
};

uint8_t *
ber_encode_vlint(uint8_t *buf, uint32_t num)
{
    *buf-- = (uint8_t) (num & 0x7F);
    num >>= 7;

    while (num) {
        *buf-- = (uint8_t) ((num & 0x7F) | 0x80);
        num >>= 7;
    }

    return buf;
}

uint8_t *
ber_encode_int(uint8_t *buf, uint32_t num)
{
    size_t len;

    len = buf - ber_encode_vlint(buf, num);
    *(buf - len) = (uint8_t) len;
    *(buf - len - 1) = BER_DATA_T_INTEGER;

    return buf - len - 2;
}

uint8_t *
ber_encode_string(uint8_t *buf, const char *str, uint32_t str_len)
{
    uint8_t str_len_len;
    uint32_t i;

    assert(str_len <= 0xFFFF); /* Sanity check */

    str += str_len - 1;
    for (i = 0; i < str_len; ++i) {
        *buf-- = (uint8_t) *str--;
    }

    if (str_len > 0x7F) { // TODO: or forced long form
        *buf-- = (uint8_t) (str_len & 0xFF);
        str_len_len = 1;

        if (str_len > 0xFF) {
            *buf-- = (uint8_t) ((str_len >> 8) & 0xFF);
            str_len_len = 2;
        }

        *buf-- = (uint8_t) (str_len_len | 0x80);
    } else {
        *buf-- = (uint8_t) str_len;
    }

    *buf-- = BER_DATA_T_OCTET_STRING;

    return buf;
}

uint8_t *
ber_encode_null(uint8_t *buf)
{
    *buf-- = 0x00;
    *buf-- = BER_DATA_T_NULL;

    return buf;
}

struct uni_type {
    char type;
    union {
        uint32_t u;
        char *s;
    };
};

uint8_t *
ber_fprintf(uint8_t *out, char *fmt, ...)
{
    size_t fmt_len = strlen(fmt);
    va_list args;
    struct uni_type args_arr[128];
    struct uni_type *args_ptr = args_arr;

    if (fmt_len & 1) {
        return NULL;
    }

    va_start(args, fmt);

    while (*fmt) {
        args_ptr->type = *++fmt;
        switch (*fmt) {
            case 'u':
                args_ptr->u = va_arg(args, uint32_t);
                break;
            case 's':
                args_ptr->s = va_arg(args, char *);
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

    --args_ptr;
    while (args_ptr >= args_arr) {
        switch (args_ptr->type) {
            case 'u':
                out = ber_encode_int(out, args_ptr->u);
                break;
            case 's':
                out = ber_encode_string(out, args_ptr->s, (uint32_t) strlen(args_ptr->s));
                break;
            case 'n':
                out = ber_encode_null(out);
                break;
            default:
                return NULL;
        }

        --args_ptr;
    }
    
    return ++out;
}
