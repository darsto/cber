cmake_minimum_required(VERSION 3.7)
project(ber)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -pedantic -Wall -Wextra \
    -Werror -Wno-missing-braces -Wno-missing-field-initializers \
    -Wno-unused-variable -Wno-unused-parameter -Wformat=2 -Wswitch-default \
    -Wcast-align -Wpointer-arith -Wbad-function-cast \
    -Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
    -Wcast-qual -Wshadow -Wunreachable-code -Wlogical-op -Wfloat-equal \
    -Wstrict-aliasing=2 -Wredundant-decls -Wold-style-definition")

set(SOURCE_FILES main.c ber.c ber.h snmp.c snmp.h)
add_executable(ber ${SOURCE_FILES})