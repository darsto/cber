/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "ber.h"
#include "snmp.h"

uint8_t *
snmp_encode_oid(uint8_t *out, uint32_t *oid)
{
    uint32_t *oid_start = oid;
    uint8_t *out_start = out;

    while (*oid != SNMP_MSG_OID_END) {
        ++oid;
    }
    --oid;

    while (oid != oid_start) {
        out = ber_encode_vlint(out, *oid);
        --oid;
    }

    out = ber_encode_vlint(out + 1, *(out + 1) + 40 * *oid);
    out = ber_encode_length(out, (uint32_t) (out_start - out));
    *out-- = SNMP_DATA_T_OBJECT;

    return out;
}

uint8_t *
snmp_decode_oid(uint8_t *buf, uint32_t *oid, uint32_t *oid_len)
{
    uint32_t *oid_start = oid;
    uint8_t *buf_end;
    uint32_t len;
    div_t first;

    buf++; /* ignore ber type, assume it's an object */
    buf = ber_decode_length(buf, &len);
    if (buf == NULL) {
        return NULL;
    }

    buf_end = buf + len;

    first = div(*buf++, 40);
    *oid++ = (uint32_t) first.quot;
    *oid++ = (uint32_t) first.rem;

    while (buf != buf_end) {
        --(*oid_len);
        if (*oid_len == 0) {
            return NULL;
        }

        buf = ber_decode_vlint(buf, oid);
        ++oid;
    }

    *oid++ = SNMP_MSG_OID_END;
    *oid_len = (uint32_t) (oid - oid_start);

    return buf;
}

uint8_t *
snmp_encode_msg(uint8_t *out, struct snmp_msg_header *header,
                uint32_t varbind_num, struct snmp_varbind *varbinds)
{
    va_list args;
    struct snmp_varbind *varbind;
    uint8_t *out_end = out;
    uint8_t *out_prev;
    int i;

    /* writing varbinds */
    for(i = varbind_num - 1; i >= 0; --i) {
        varbind = &varbinds[i];
        out_prev = out;

        switch (varbind->value_type) {
            case SNMP_DATA_T_INTEGER:
                out = ber_encode_int(out, varbind->value.i);
                break;
            case SNMP_DATA_T_OCTET_STRING:
                out = ber_encode_string(out, varbind->value.s,
                                        (uint32_t) strlen(varbind->value.s));
                break;
            case SNMP_DATA_T_NULL:
                out = ber_encode_null(out);
                break;
            default:
                return NULL;
        }

        out = snmp_encode_oid(out, varbind->oid);
        out = ber_encode_length(out, (uint32_t) (out_prev - out));
        *out-- = SNMP_DATA_T_SEQUENCE;
    }

    out = ber_encode_length(out, (uint32_t) (out_end - out));
    *out-- = SNMP_DATA_T_SEQUENCE;

    /* writing pdu header */
    out = ber_encode_int(out, header->error_index);
    out = ber_encode_int(out, header->error_status);
    out = ber_encode_int(out, header->request_id);

    out = ber_encode_length(out, (uint32_t) (out_end - out));
    *out-- = header->pdu_type;

    /* writing the rest of snmp msg data */
    out = ber_encode_string(out, header->community, (uint32_t) strlen(header->community));
    out = ber_encode_int(out, header->snmp_ver);

    out = ber_encode_length(out, (uint32_t) (out_end - out));
    *out = SNMP_DATA_T_SEQUENCE;

    return out;
}
