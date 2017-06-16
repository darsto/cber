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

    while (*oid != SNMP_MSG_OID_END) {
        ++oid;
    }
    --oid;

    while (oid != oid_start) {
        out = ber_encode_vlint(out, *oid);
        --oid;
    }

    out = ber_encode_vlint(out + 1, *(out + 1) + 40 * *oid);
    return out;
}

uint8_t *
snmp_encode_msg(uint8_t *out, struct snmp_msg_header *header, uint32_t varbind_num, ...)
{
    va_list args;
    struct snmp_varbind *args_arr[32];
    struct snmp_varbind *args_ptr;
    uint8_t *out_end = out;
    uint8_t *out_prev_seq;
    uint8_t *out_prev;
    int i;

    va_start(args, varbind_num);
    for (i = 0; i < varbind_num; ++i) {
        args_arr[i] = va_arg(args, struct snmp_varbind *);
    }
    va_end(args);

    /* writing varbinds */
    for(--i; i >= 0; --i) {
        args_ptr = args_arr[i];
        out_prev_seq = out;

        switch (args_ptr->value_type) {
            case SNMP_DATA_T_INTEGER:
                out = ber_encode_int(out, args_ptr->value.i);
                break;
            case SNMP_DATA_T_OCTET_STRING:
                out = ber_encode_string(out, args_ptr->value.s,
                                        (uint32_t) strlen(args_ptr->value.s));
                break;
            case SNMP_DATA_T_NULL:
                out = ber_encode_null(out);
                break;
            default:
                return NULL;
        }

        out_prev = out;
        out = snmp_encode_oid(out, args_ptr->oid);
        out = ber_encode_vlint(out, (uint32_t) (out_prev - out));
        *out-- = SNMP_DATA_T_OBJECT;

        out = ber_encode_vlint(out, (uint32_t) (out_prev_seq - out));
        *out-- = SNMP_DATA_T_SEQUENCE;
    }

    out = ber_encode_vlint(out, (uint32_t) (out_end - out));
    *out-- = SNMP_DATA_T_SEQUENCE;

    /* writing pdu header */
    out = ber_encode_int(out, header->error_index);
    out = ber_encode_int(out, header->error_status);
    out = ber_encode_int(out, header->request_id);

    out = ber_encode_vlint(out, (uint32_t) (out_end - out));
    *out-- = header->pdu_type;

    /* writing the rest of snmp msg data */
    out = ber_encode_string(out, header->community, (uint32_t) strlen(header->community));
    out = ber_encode_int(out, header->snmp_ver);

    out = ber_encode_vlint(out, (uint32_t) (out_end - out));
    *out = SNMP_DATA_T_SEQUENCE;

    return out;
}
