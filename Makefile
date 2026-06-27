CC = gcc
CFLAGS = -std=gnu99 -pedantic -Wall -Wextra \
    -Werror -Wno-missing-braces -Wno-missing-field-initializers \
    -Wno-unused-variable -Wno-unused-parameter -Wformat=2 -Wswitch-default \
    -Wcast-align -Wpointer-arith -Wbad-function-cast \
    -Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
    -Wcast-qual -Wshadow -Wunreachable-code -Wlogical-op -Wfloat-equal \
    -Wstrict-aliasing=2 -Wredundant-decls -Wold-style-definition
LDFLAGS =
SOURCES = main.c snmp.c ber.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = ber-test
CLANG_FORMAT = clang-format
FORMAT_SOURCES = $(SOURCES) ber.h snmp.h
AFL_EXECUTABLE = afl-test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean fmt afl

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) $(AFL_EXECUTABLE)
	rm -rf ./afl-tmp

fmt:
	$(CLANG_FORMAT) -i $(FORMAT_SOURCES)

afl: afl-ber-decode afl-snmp-decode

FUZZ_TIME = 300
FUZZ_ENV = AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_UNTIL_CRASH=1

$(AFL_EXECUTABLE): main.c snmp.c ber.c
	./afl-seeds.sh
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-gcc $(CFLAGS) main.c snmp.c ber.c -o $(AFL_EXECUTABLE)

afl-%-decode afl-%-encode: $(AFL_EXECUTABLE)
	$(FUZZ_ENV) TEST_TARGET=$@ afl-fuzz \
		-i ./afl-tmp/input/$* \
		-o ./afl-tmp/$(patsubst afl-%,%,$@) \
		-V $(FUZZ_TIME) -- ./$(AFL_EXECUTABLE)
