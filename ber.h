/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#ifndef BER_H
#define BER_H

#include <stdint.h>

enum ber_data_type {
    /* ASN.1 primitives */
    BER_DATA_T_INTEGER = 0x02,
    BER_DATA_T_OCTET_STRING = 0x04,
    BER_DATA_T_NULL = 0x05,
};

/** Encode variable-length integer */
uint8_t *ber_encode_vlint(uint8_t *buf, uint32_t num);

uint8_t *ber_encode_int(uint8_t *buf, uint32_t num);
uint8_t *ber_encode_string(uint8_t *buf, const char *str, uint32_t str_len);
uint8_t *ber_encode_null(uint8_t *buf);

#endif //BER_H

