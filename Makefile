CC = gcc
CFLAGS = -std=gnu99 -pedantic -Wall -Wextra \
    -Werror -Wno-missing-braces -Wno-missing-field-initializers \
    -Wno-unused-variable -Wno-unused-parameter -Wformat=2 -Wswitch-default \
    -Wcast-align -Wpointer-arith -Wbad-function-cast \
    -Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
    -Wcast-qual -Wshadow -Wunreachable-code -Wlogical-op -Wfloat-equal \
    -Wstrict-aliasing=2 -Wredundant-decls -Wold-style-definition
LDFLAGS =
SOURCES = snmp.c ber.c main.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = ber-test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
