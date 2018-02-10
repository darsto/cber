Here's a brief performance comparison against [TinyBER](https://github.com/cloudtools/tinyber), a BER codec designed for the same purpose.

There are 2 test cases:

 - encode integers to fill ~8MB buffer
 - encode integers, then decode them from ~8MB buffer

## Encoding

ber_enc.c

```
#include <string.h>
#include <stdint.h>
#include "ber.h"

uint8_t buf[4096 * 2000];

int
main(void)
{
	uint8_t *buf_end = buf + sizeof(buf) - 1;
	uint32_t x = -3141;

	memset (buf, 0, sizeof(buf));

	for (int i = 0; i < sizeof(buf) / 6; i++) {
		__asm volatile ("");
		buf_end = ber_encode_int(buf_end, x);
	}

	return 0;
}
```

tinyber_enc.c

```
#include <string.h>
#include <stdint.h>
#include "tinyber.h"

uint8_t buffer[4096 * 2000];
buf_t obuf;

int
main (int argc, char * argv[])
{
	asn1int_t x = -3141;

	init_obuf (&obuf, buffer, sizeof(buffer));
	memset (buffer, 0, sizeof(buffer));

	for (int i = 0; i < sizeof(buffer); i += 6) {
		__asm volatile ("");
		encode_INTEGER (&obuf, &x);
	}

	return 0;
}
```

```
# gcc -O3 ber_enc.c ber/ber.c -o ber_enc
# perf stat -r 30 -dd ./ber_enc

 Performance counter stats for './ber_enc' (30 runs):

         10.981587      task-clock (msec)         #    0.976 CPUs utilized            ( +-  0.35% )
                 0      context-switches          #    0.012 K/sec                    ( +- 47.34% )
                 0      cpu-migrations            #    0.000 K/sec
             2,043      page-faults               #    0.186 M/sec                    ( +-  0.01% )
         4,154,712      cycles                    #    0.378 GHz                      ( +- 13.19% )  (0.00%)
         7,299,072      stalled-cycles-frontend   #  175.68% frontend cycles idle     ( +-  2.46% )
        42,147,467      instructions              #   10.14  insn per cycle
                                                  #    0.17  stalled cycles per insn  ( +-  2.71% )
        10,647,139      branches                  #  969.545 M/sec                    ( +-  0.01% )
             4,593      branch-misses             #    0.04% of all branches          ( +-  0.82% )
         2,981,449      L1-dcache-loads           #  271.495 M/sec                    ( +-  0.03% )
           299,325      L1-dcache-load-misses     #   10.04% of all L1-dcache hits    ( +-  0.03% )
            19,379      LLC-loads                 #    1.765 M/sec                    ( +-  0.20% )
             4,311      LLC-load-misses           #   44.49% of all LL-cache hits     ( +-  2.26% )
   <not supported>      L1-icache-loads
            11,034      L1-icache-load-misses                                         ( +-  9.66% )  (84.78%)
         2,835,637      dTLB-loads                #  258.217 M/sec                    ( +-  1.20% )  (48.49%)
     <not counted>      dTLB-load-misses                                              (0.00%)
     <not counted>      iTLB-loads                                                    (0.00%)
     <not counted>      iTLB-load-misses                                              (0.00%)

       0.011252688 seconds time elapsed                                          ( +-  0.33% )
```

```
# gcc -O3 tinyber_enc.c tinyber/data/tinyber.c -o tinyber_enc
# perf stat -r 30 -dd ./tinyber_enc

 Performance counter stats for './tinyber_enc' (30 runs):

         21.032823      task-clock (msec)         #    0.989 CPUs utilized            ( +-  0.18% )
                 0      context-switches          #    0.006 K/sec                    ( +- 47.34% )
                 0      cpu-migrations            #    0.000 K/sec
             2,042      page-faults               #    0.097 M/sec                    ( +-  0.01% )
        19,737,055      cycles                    #    0.938 GHz                      ( +- 18.61% )  (21.26%)
         7,317,555      stalled-cycles-frontend   #   37.08% frontend cycles idle     ( +-  2.35% )
        54,969,945      instructions              #    2.79  insn per cycle
                                                  #    0.13  stalled cycles per insn  ( +-  2.96% )
        19,859,057      branches                  #  944.194 M/sec                    ( +-  1.90% )
             3,667      branch-misses             #    0.02% of all branches          ( +-  0.89% )
        16,463,064      L1-dcache-loads           #  782.732 M/sec                    ( +-  0.32% )
           257,244      L1-dcache-load-misses     #    1.56% of all L1-dcache hits    ( +-  0.05% )
            19,551      LLC-loads                 #    0.930 M/sec                    ( +-  0.20% )
             2,628      LLC-load-misses           #   26.88% of all LL-cache hits     ( +-  5.09% )
   <not supported>      L1-icache-loads
            10,061      L1-icache-load-misses                                         ( +- 10.39% )  (91.45%)
        18,339,689      dTLB-loads                #  871.956 M/sec                    ( +-  0.17% )  (72.45%)
             7,446      dTLB-load-misses          #    0.04% of all dTLB cache hits   ( +-  2.97% )  (34.44%)
                13      iTLB-loads                #    0.599 K/sec                    ( +- 18.55% )  (15.44%)
               191      iTLB-load-misses          # 1514.81% of all iTLB cache hits   ( +- 31.30% )  (0.95%)

       0.021267667 seconds time elapsed                                          ( +-  0.18% )
```

## Decoding

ber_dec.c

```
#include <string.h>
#include <stdint.h>
#include "ber.h"

uint8_t buf[4096 * 2000];
uint32_t dec;

int
main(void)
{
	uint8_t *buf_ptr = buf + sizeof(buf) - 1;
	uint32_t x = -3141;

	memset (buf, 0, sizeof(buf));

	for (int i = 0; i < sizeof(buf) / 6; i++) {
		__asm volatile ("");
		buf_ptr = ber_encode_int(buf_ptr, x);
	}

	buf_end += 1;

	for (int i = 0; i < sizeof(buf) / 6; i++) {
		__asm volatile ("");
		buf_ptr = ber_decode_int(buf_ptr, &dec);
	}

	return 0;
}
```

tinyber_dec.c

```
#include <string.h>
#include <stdint.h>
#include "tinyber.h"

uint8_t buffer[4096 * 2000];
buf_t obuf;
buf_t ibuf;
asn1raw_t d;
asn1int_t s;

int
main (int argc, char * argv[])
{
	  asn1int_t n = -3141;

	  init_obuf (&obuf, buffer, sizeof(buffer));
	  memset (buffer, 0, sizeof(buffer));

	  for (int i = 0; i < sizeof(buffer); i += 6) {
		  __asm volatile ("");
		  encode_INTEGER (&obuf, &n);
	  }

	  init_ibuf (&ibuf, buffer, sizeof(buffer));
	  for (int i = 0; i < sizeof(buffer); i += 6) {
		  __asm volatile ("");
		  decode_TLV(&d, &ibuf);
		  s = decode_INTEGER (&d);
	  }

	  return 0;
}
```


```
# gcc -O3 ber_dec.c ber/ber.c -o ber_dec
# perf stat -r 30 -dd ./ber_dec

 Performance counter stats for './ber_dec' (30 runs):

         18.660727      task-clock (msec)         #    0.985 CPUs utilized            ( +-  0.20% )
                 0      context-switches          #    0.007 K/sec                    ( +- 47.34% )
                 0      cpu-migrations            #    0.000 K/sec
             2,042      page-faults               #    0.109 M/sec                    ( +-  0.01% )
         4,399,731      cycles                    #    0.236 GHz                      ( +- 12.30% )  (0.00%)
         7,410,326      stalled-cycles-frontend   #  168.43% frontend cycles idle     ( +-  2.46% )
        43,533,258      instructions              #    9.89  insn per cycle
                                                  #    0.17  stalled cycles per insn  ( +-  3.08% )
        14,422,759      branches                  #  772.894 M/sec                    ( +-  1.86% )
             4,029      branch-misses             #    0.03% of all branches          ( +-  2.27% )
        11,172,770      L1-dcache-loads           #  598.732 M/sec                    ( +-  0.01% )
           427,737      L1-dcache-load-misses     #    3.83% of all L1-dcache hits    ( +-  0.03% )
            22,359      LLC-loads                 #    1.198 M/sec                    ( +-  0.19% )
             5,178      LLC-load-misses           #   46.32% of all LL-cache hits     ( +-  1.68% )
   <not supported>      L1-icache-loads
            10,662      L1-icache-load-misses                                         ( +- 10.87% )  (90.51%)
        13,865,183      dTLB-loads                #  743.014 M/sec                    ( +-  1.27% )  (69.17%)
            14,096      dTLB-load-misses          #    0.10% of all dTLB cache hits   ( +-  3.16% )  (26.34%)
                30      iTLB-loads                #    0.002 M/sec                    ( +- 27.81% )  (5.92%)
     <not counted>      iTLB-load-misses                                              (0.00%)

       0.018937613 seconds time elapsed                                          ( +-  0.19% )
```

```
# gcc -O3 tinyber_dec.c tinyber/data/tinyber.c -o tinyber_dec
# perf stat -r 30 -dd ./tinyber_dec

 Performance counter stats for './tinyber_dec' (30 runs):

         31.977396      task-clock (msec)         #    0.991 CPUs utilized            ( +-  0.24% )
                 0      context-switches          #    0.005 K/sec                    ( +- 41.52% )
                 0      cpu-migrations            #    0.000 K/sec
             2,042      page-faults               #    0.064 M/sec                    ( +-  0.01% )
        79,648,069      cycles                    #    2.491 GHz                      ( +-  0.24% )  (25.01%)
        32,977,501      stalled-cycles-frontend   #   41.40% frontend cycles idle     ( +-  1.18% )  (24.99%)
       177,696,789      instructions              #    2.23  insn per cycle
                                                  #    0.19  stalled cycles per insn  ( +-  0.26% )  (37.48%)
        41,066,220      branches                  # 1284.227 M/sec                    ( +-  1.05% )  (45.92%)
             3,878      branch-misses             #    0.01% of all branches          ( +-  4.18% )  (94.34%)
        16,937,767      L1-dcache-loads           #  529.679 M/sec                    ( +-  1.64% )
           253,689      L1-dcache-load-misses     #    1.50% of all L1-dcache hits    ( +-  0.35% )
            10,178      LLC-loads                 #    0.318 M/sec                    ( +-  3.34% )
             4,925      LLC-load-misses           #   96.78% of all LL-cache hits     ( +-  3.01% )
   <not supported>      L1-icache-loads
            10,701      L1-icache-load-misses                                         ( +- 10.27% )  (94.41%)
        36,440,507      dTLB-loads                # 1139.571 M/sec                    ( +-  0.24% )  (81.93%)
             5,498      dTLB-load-misses          #    0.02% of all dTLB cache hits   ( +-  1.23% )  (56.93%)
                 4      iTLB-loads                #    0.133 K/sec                    ( +- 10.36% )  (44.42%)
                91      iTLB-load-misses          # 2127.34% of all iTLB cache hits   ( +-  3.27% )  (31.92%)

       0.032252313 seconds time elapsed                                          ( +-  0.24% )
```

## Setup

Benchmarks above have been done on a following machine:

```
Intel(R) Xeon(R) CPU E5-2609 v2 @ 2.50GHz
Debian GNU/Linux 9.1 (stretch)
gcc (Debian 6.3.0-18) 6.3.0 20170516
```