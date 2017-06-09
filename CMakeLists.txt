cmake_minimum_required(VERSION 3.7)
project(ber)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c ber.c ber.h)
add_executable(ber ${SOURCE_FILES})