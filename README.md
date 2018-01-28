# C99 BER codec

![Status](https://img.shields.io/badge/status-stable-green.svg)
[![License](https://img.shields.io/github/license/darsto/ber.svg)](LICENSE)

Minimalistic ISO C99 codec for serializing data in ASN.1 BER format.
It does not use any external dependencies.

For efficiency reasons, all data structures are being encoded backwards. Decoding is done as normal.

When encoding, the library doesn't protect against output buffer overflow. If necessary, all checks should be done by the user.

When decoding, the amount of input buffer overflow checks is minimal.

It is required that all input/output buffers should be at least **n** bytes before coding data. Please check the internal documentation in `ber.h` for details.

## Usage

```c
int main(void) {
    uint8_t buf[6] = {0}; /* initialized for showcase purposes, not necessary */
    uint8_t *buf_end = buf + sizeof(buf) - 1;
    uint8_t *enc_out, *dec_out;
    uint32_t enc_num = 42, dec_num;

    enc_out = ber_encode_int(buf_end, enc_num);
    /* buf == { 0, 0, 0, 0x2, 0x1, 0x2a }, enc_out == &buf[2] */
    dec_out = ber_decode_int(enc_out + 1, &dec_num);

    assert(dec_out == buf_end + 1);
    assert(enc_num == dec_num);

    return 0;
}
```

This library should be used directly inside the application. Simply copy the `ber.c` and `ber.h` files to your project.

For full usage example, please see snmp.c file. It is an SNMPv1 codec which uses BER library under the hood. It includes all error checks and is user-ready.

## Running tests

This library comes with a simple unit tests that can be run as following.

```
git clone git@github.com:darsto/ber.git
cd ber
make
./ber-test
```

You should see some output similar to the one below.

```
# Testing variable-length-integer coding.
ber_encode_vlint(42) = {
  00000000: 2a                                      | *
}
ber_encode_vlint(67) = {
  00000000: 43                                      | C
}
ber_encode_vlint(128) = {
  00000000: 8100                                    | ..
}
ber_encode_vlint(129) = {
  00000000: 8101                                    | ..
}
ber_encode_vlint(179) = {
  00000000: 8133                                    | .3
}

[...]

# Testing BER integer coding
ber_encode_int(42) = {
  00000000: 0201 2a                                 | ..*
}
ber_encode_int(67) = {
  00000000: 0201 43                                 | ..C
}
ber_encode_int(128) = {
  00000000: 0201 80                                 | ...
}
ber_encode_int(129) = {
  00000000: 0201 81                                 | ...
}
ber_encode_int(179) = {
  00000000: 0201 b3                                 | ...
}

[...]

# Testing BER string coding
ber_encode_string("a") = {
  00000000: 0401 61                                 | ..a
}
ber_encode_string("ab") = {
  00000000: 0402 6162                               | ..ab
}
ber_encode_string("test123") = {
  00000000: 0407 7465 7374 3132 33                  | ..test123
}
ber_encode_string("testing_longer_name") = {
  00000000: 0413 7465 7374 696e 675f 6c6f 6e67 6572 | ..testing_longer
  00000010: 5f6e 616d 65                            | _name
}

[...]

# Testing fprintf syntax-like coding.
ber_fprintf("%u%u%s", 64, 103, "testing_strings_123") = {
  00000000: 0140 0201 6704 1374 6573 7469 6e67 5f73 | .@..g..testing_s
  00000010: 7472 696e 6773 5f31 3233                | trings_123
}

[...]
```