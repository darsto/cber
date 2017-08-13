/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#ifndef BER_SNMP_H
#define BER_SNMP_H

#include <stdint.h>

#define SNMP_MSG_OID_END ((uint32_t) -1)
#define SNMP_MSG_OID_LEN 32

/** BER data types used by this SNMP library */
enum snmp_data_type {
    SNMP_DATA_T_INTEGER = 0x02,
    SNMP_DATA_T_OCTET_STRING = 0x04,
    SNMP_DATA_T_NULL = 0x05,
    
    SNMP_DATA_T_OBJECT = 0x06,
    SNMP_DATA_T_SEQUENCE = 0x30,

    SNMP_DATA_T_PDU_GET_REQUEST = 0xA0,
    SNMP_DATA_T_PDU_GET_NEXT_REQUEST = 0xA1,
    SNMP_DATA_T_PDU_GET_RESPONSE = 0xA2,
    SNMP_DATA_T_PDU_SET_REQUEST = 0xA3,
    SNMP_DATA_T_PDU_TRAP = 0xA4,
};

/** Header data for SNMP message */
struct snmp_msg_header {
    uint32_t snmp_ver;
    const char *community;
    enum snmp_data_type pdu_type;
    uint32_t request_id;
    uint32_t error_status;
    uint32_t error_index;
};

/** Actual data in SNMP message */
struct snmp_varbind {
    uint32_t oid[SNMP_MSG_OID_LEN];
    enum snmp_data_type value_type;
    union snmp_varbind_val {
        uint32_t i;
        const char *s;
    } value;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode SNMP Object IDentifier as BER object.
 * This function does not add any additional trailing zeros to the OID.
 * @param out pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param oid array of integers forming OID terminated with SNMP_MSG_OID_END
 * @return pointer to the next empty byte in the given buffer.
 * Will always be smaller than given buf pointer.
 */
uint8_t *snmp_encode_oid(uint8_t *out, uint32_t *oid);

/**
 * Decode SNMP Object IDentifier from BER object.
 * Note that this function does not check against input buffer overflow.
 * It will read at most *oid_len * 5 + 6.
 * @param buf pointer to the **beginning** of the input buffer.
 * The first byte should be SNMP_DATA_T_OBJECT. However, this function
 * does not check against it.
 * @param buf_len size of *buf*. If decoded OID length exceeds this value,
 * the function will return NULL.
 * @param oid array to be filled by this function. The OID will be terminated
 * with SNMP_MSG_OID_END. In case this function returns NULL, the content of
 * this param is undefined.
 * @param oid_len pointer to max size of *oid* array. Underlying value will
 * be replaced with the actual, decoded OID length. In case this function
 * returns NULL, the content of this param is undefined.
 * @return pointer to the next empty byte in the given buffer or NULL in case
 * BER object length is invalid or malloc() failed.
 */
uint8_t *snmp_decode_oid(uint8_t *buf, uint32_t buf_len, uint32_t *oid, uint32_t *oid_len);

/**
 * Encode given SNMP message (GetRequest, GetNextRequest, GetResponse, SetRequest).
 * Trap PDU is not supported.
 * @param out pointer to the **end** of the output buffer.
 * The first encoded byte will be put in buf, next one in (buf - 1), etc.
 * @param header header to be encoded
 * @param varbind_num number of following snmp_varbind* items
 * @param varbinds pointer to array of varbinds to be encoded
 * @return pointer to the first byte of encoded sequence in given buffer or NULL
 * if varbinds parsing error occured.
 */
uint8_t *snmp_encode_msg(uint8_t *out, struct snmp_msg_header *header,
                         uint32_t varbind_num, struct snmp_varbind *varbinds);

/**
 * Decode given SNMP message (GetRequest, GetNextRequest, GetResponse, SetRequest).
 * Trap PDU is not supported. This function will modify input buffer, further
 * SNMP decode might not be possible.
 * @param buf pointer to the **beginning** of the input buffer.
 * The first byte should be SNMP_DATA_T_SEQUENCE. However, this function
 * does not check against it. The buffer has to have at least 12 bytes and has
 * to be at least 18 bytes bigger than *buf_len* param. That's because length
 * check is only done occasionally when dealing with very dynamic-length data.
 * @param buf_len max size of *buf*. If decoded msg length exceeds this value,
 * the function will return NULL.
 * @param header header structure to be filled with decoded data
 * @param varbind_num pointer to max size of *varbinds* array. Underlying value
 * will be replaced with the actual, decoded varbinds num. In case this function
 * returns NULL, the content of this param is undefined.
 * @param varbinds pointer to array of varbinds to be decoded. All strings will
 * be taken directly from input buffer, without any additional allocation.
 * @return
 */
uint8_t *snmp_decode_msg(uint8_t *buf, uint32_t buf_len, struct snmp_msg_header *header,
                         uint32_t *varbind_num, struct snmp_varbind *varbinds);

#ifdef __cplusplus
}
#endif

#endif //BER_SNMP_H
