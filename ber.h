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

/**
 * Encode variable-length unsigned 32-bit integer.
 * Note that this function is does not check against output buffer overflow.
 * It will write at most 5 bytes.
 * @param buf pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param num number to encode in any expected endianness
 * @return pointer to the next empty byte in the given buffer.
 * Will always be smaller than given buf pointer.
 */
uint8_t *ber_encode_vlint(uint8_t *buf, uint32_t num);

/**
 * Encode integer in BER.
 * Note that this function is does not check against output buffer overflow.
 * It will write at most 7 bytes.
 * @param buf pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param num number to encode in any expected endianness
 * @return pointer to the next empty byte in the given buffer.
 * Will always be smaller than given buf param.
 */
uint8_t *ber_encode_int(uint8_t *buf, uint32_t num);

/**
 * Encode octet string in BER.
 * Note that this function is does not check against output buffer overflow.
 * It will write at most 3+strlen(str) bytes.
 * @param buf pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param str string to encode (pointer to the **first** char)
 * @param str_len length of given string
 * @return pointer to the next empty byte in the given buffer.
 * Will always be smaller than given buf param.
 */
uint8_t *ber_encode_string(uint8_t *buf, const char *str, uint32_t str_len);

/**
 * Encode NULL in BER.
 * Note that this function is does not check against output buffer overflow.
 * It will write exactly 2 bytes.
 * @param buf pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @return pointer to the next empty byte in the given buffer.
 * Will always be smaller than given buf param.
 */
uint8_t *ber_encode_null(uint8_t *buf);

/**
 * Encode data in BER using fprintf-like syntax.
 * Note that this function is does not check against output buffer overflow.
 * @param buf pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param fmt c printf-like format string. It supports only format specifiers.
 * Any detected non format specifier will cause to return with NULL.
 * @param ... c printf-like parameters specified in fmt field
 * @return pointer to the first byte of encoded sequence in given buffer or NULL
 * if fmt parsing error occured.
 */
uint8_t *ber_fprintf(uint8_t *out, char *fmt, ...);

#endif //BER_H