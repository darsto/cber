/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "ber.h"

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