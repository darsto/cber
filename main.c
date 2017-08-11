/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <ctype.h>
#include <memory.h>
#include <assert.h>
#include <stdlib.h>
#include "ber.h"
#include "snmp.h"

static char
to_printable(int n)
{
    static const char *trans_table = "0123456789abcdef";

    return trans_table[n & 0xf];
}

int
hexdump_line(const char *data, const char *data_start, const char *data_end)
{
    static char buf[256] = {0};

    char *buf_ptr = buf;
    int relative_addr = (int) (data - data_start);
    size_t i, j;

    for (i = 0; i < 2; ++i) {
        buf_ptr[i] = ' ';
    }
    buf_ptr += i;

    for (i = 0; i < sizeof(void *); ++i) {
        buf_ptr[i] = to_printable(
            relative_addr >> (sizeof(void *) * 4 - 4 - i * 4));
    }
    buf_ptr += i;

    buf_ptr[0] = ':';
    buf_ptr[1] = ' ';
    buf_ptr += 2;

    for (j = 0; j < 8; ++j) {
        for (i = 0; i < 2; ++i) {
            if (data < data_end) {
                buf[10 + 5 * 8 + 4 + i + 2*j] = (char) (isprint(*data) ? *data : '.');

                buf_ptr[i * 2] = to_printable(*data >> 4);
                buf_ptr[i * 2 + 1] = to_printable(*data);

                ++data;
            } else {
                buf[10 + 5 * 8 + 4 + i + 2*j] = 0;

                buf_ptr[i * 2] = ' ';
                buf_ptr[i * 2 + 1] = ' ';
            }
        }

        buf_ptr[4] = ' ';
        buf_ptr += 5;
    }

    buf[10 + 5 * 8 + 2] = '|';
    buf[10 + 5 * 8 + 3] = ' ';

    printf("%s\n", buf);

    return (int) (i * j);
}

void
hexdump(const char *title, const void *data, size_t len)
{
    const char *data_ptr = data;
    const char *data_start = data_ptr;
    const char *data_end = data_ptr + len;

    printf("%s = {\n", title);
    while (data_ptr < data_end) {
        data_ptr += hexdump_line(data_ptr, data_start, data_end);
    }
    printf("}\n");
}

void
snmp_msg_test(uint8_t *buf, uint8_t *buf_end)
{
    struct snmp_msg_header msg_header = {0};
    struct snmp_varbind varbind = {0};
    uint32_t oid[] = { 1, 3, 6, 1, 4, 1, 26609, 2, 1, 1, 2, 0, SNMP_MSG_OID_END };
    uint8_t *out;

    msg_header.snmp_ver = 0;
    msg_header.community = "private";
    msg_header.pdu_type = SNMP_DATA_T_PDU_GET_REQUEST;
    msg_header.request_id = 0x0B;

    varbind.value_type = SNMP_DATA_T_NULL;
    varbind.oid = oid;

    out = snmp_encode_msg(buf_end, &msg_header, 1, &varbind);
    hexdump("snmp_encode_msg", out, buf_end - out + 1);
}

void
snmp_oid_test(uint8_t *buf, uint8_t *buf_end)
{
    uint32_t oid[] = { 1, 3, 6, 1, 4, 1, 26609, 2, 1, 1, 2, 0, SNMP_MSG_OID_END };
    uint32_t dec_oid[13];
    uint8_t *enc_out, *dec_out;
    uint32_t oid_len = sizeof(dec_oid) / sizeof(dec_oid[0]);

    assert(sizeof(oid) == sizeof(dec_oid));

    enc_out = snmp_encode_oid(buf_end, oid);
    dec_out = snmp_decode_oid(enc_out + 1, dec_oid, &oid_len);

    assert(dec_out == buf_end + 1);
    assert(oid_len == 13);
    assert(memcmp(oid, dec_oid, oid_len) == 0);
}

void
ber_fprintf_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    uint32_t num1, num2;
    char *str = NULL;

    enc_out = ber_fprintf(buf_end, "%u%u%s", 64, 103, "testing_strings_123");
    dec_out = ber_sscanf(enc_out, "%u%u%ms", &num1, &num2, &str);

    assert(dec_out == buf_end + 1);
    assert(num1 == 64);
    assert(num2 == 103);
    assert(strcmp("testing_strings_123", str) <= 0);

    free(str);
}

void
ber_data_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    struct ber_data data[3] = {
        { .type = BER_DATA_T_INTEGER, .value.u = 64 },
        { .type = BER_DATA_T_INTEGER, .value.u = 103 },
        { .type = BER_DATA_T_OCTET_STRING, .value.s = "testing_strings_123" },
    };
    struct ber_data dec_data[3] = {0};

    enc_out = ber_encode_data(buf_end, sizeof(data) / sizeof(data[0]), data);
    dec_out = ber_decode_data(enc_out + 1, sizeof(data) / sizeof(data[0]), dec_data);

    assert(dec_out == buf_end + 1);
    assert(dec_data[0].type == data[0].type);
    assert(dec_data[0].value.u == data[0].value.u);
    assert(dec_data[1].type == data[1].type);
    assert(dec_data[1].value.u == data[1].value.u);
    assert(dec_data[2].type == data[2].type);
    assert(strcmp(dec_data[2].value.s, data[2].value.s) == 0);

    free(dec_data[2].value.s);
}

void
ber_vlint_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    uint32_t values[] = { 42, 67, 128, 129, 179, 255, 256, 258, 400, 4096, 65536 };
    uint32_t i, num;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        enc_out = ber_encode_vlint(buf_end, values[i]);
        dec_out = ber_decode_vlint(enc_out + 1, &num);
        assert(num == values[i]);
        assert(dec_out == buf_end + 1);
    }
}

void
ber_int_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    uint32_t values[] = { 42, 67, 128, 129, 179, 255, 256, 258, 400, 4096, 65536 };
    uint32_t i, num;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        enc_out = ber_encode_int(buf_end, values[i]);
        dec_out = ber_decode_int(enc_out + 1, &num);
        assert(num == values[i]);
        assert(dec_out == buf_end + 1);
    }
}

void
ber_length_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    uint32_t values[] = { 42, 67, 128, 129, 179, 255, 256, 258, 400, 4096, 65536 };
    uint32_t i, num;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        enc_out = ber_encode_length(buf_end, values[i]);
        dec_out = ber_decode_length(enc_out + 1, &num);
        assert(num == values[i]);
        assert(dec_out == buf_end + 1);
    }
}

void
ber_string_test(uint8_t *buf, uint8_t *buf_end)
{
    uint8_t *enc_out, *dec_out;
    const char *values[] = { "a", "ab", "test123", "testing_longer_name" };
    const char *str;
    uint32_t i, str_len;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        enc_out = ber_encode_string(buf_end, values[i], strlen(values[i]));
        dec_out = ber_decode_cnstring(enc_out + 1, &str, &str_len);
        assert(str_len == strlen(values[i]));
        assert(strncmp(str, values[i], str_len) == 0);
        assert(dec_out == buf_end + 1);
    }
}

int
main(void)
{
    uint8_t buf[1024];
    uint8_t *buf_end = buf + sizeof(buf) - 1;

    memset(buf, -1, 1024); //for debug purposes
    ber_vlint_test(buf, buf_end);
    memset(buf, -1, 1024);
    ber_int_test(buf, buf_end);
    memset(buf, -1, 1024);
    ber_length_test(buf, buf_end);
    memset(buf, -1, 1024);
    ber_string_test(buf, buf_end);
    memset(buf, -1, 1024);
    ber_data_test(buf, buf_end);
    memset(buf, -1, 1024);
    ber_fprintf_test(buf, buf_end);
    memset(buf, -1, 1024);
    snmp_oid_test(buf, buf_end);
    memset(buf, -1, 1024);
    snmp_msg_test(buf, buf_end);

    return 0;
}
