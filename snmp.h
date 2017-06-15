/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#ifndef BER_SNMP_H
#define BER_SNMP_H

#include <stdint.h>

enum snmp_pdu_type {
    SNMP_PDU_GET_REQUEST = 0xA0,
    SNMP_PDU_GET_NEXT_REQUEST = 0xA1,
    SNMP_PDU_GET_RESPONSE = 0xA2,
    SNMP_PDU_SET_REQUEST = 0xA3,
    SNMP_PDU_TRAP = 0xA4,
};

struct snmp_msg_header {
    uint32_t snmp_ver;
    const char *community;
    enum snmp_pdu_type pdu_type;
    uint32_t request_id;
    uint32_t error_status;
    uint32_t error_index;
};

#define SNMP_MSG_OID_END ((uint32_t) -1)

enum snmp_data_type {
    SNMP_DATA_T_INTEGER = 0x02,
    SNMP_DATA_T_OCTET_STRING = 0x04,
    SNMP_DATA_T_NULL = 0x05,
};

struct snmp_varbind {
    uint32_t *oid;
    enum snmp_data_type value_type;
    union snmp_varbind_val {
        uint32_t i;
        const char *s;
    } value;
};

uint8_t *snmp_encode_oid(uint8_t *out, uint32_t *oid);
uint8_t *snmp_encode_msg(uint8_t *out, struct snmp_msg_header *header, uint32_t varbind_num, ...);

#endif //BER_SNMP_H
