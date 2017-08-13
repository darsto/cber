# C99 BER codec

![Status](https://img.shields.io/badge/status-stable-green.svg)
[![License](https://img.shields.io/github/license/darsto/ber.svg)](LICENSE)

Minimalistic ISO C99 codec for serializing data in ASN.1 BER format.
It does not use any external dependencies.

For efficiency reasons, all data structures are being encoded backwards. Decoding however, is being done as normal.

When encoding, the library doesn't protect against output buffer overflow. If necessary, all checks should be done by the user.

When decoding, the amount of input buffer overflow checks is minimal.

It is required that all input/output buffers should be at least **n** bytes before coding data.

## Usage

```c
int main(void) {
    uint8_t buf[6];
    uint8_t *buf_end = buf + sizeof(buf) - 1;
    uint8_t *enc_out, *dec_out;
    uint32_t enc_num = 42, dec_num;

    enc_out = ber_encode_int(buf_end, enc_num);
    dec_out = ber_decode_int(enc_out + 1, &dec_num);

    assert(dec_out == buf_end + 1);
    assert(enc_num == dec_num);

    return 0;
}
```

For full usage example, please see snmp.c file. It is user-ready SNMPv1 codec library which under-the-hood uses BER library with all overflow checks included.
