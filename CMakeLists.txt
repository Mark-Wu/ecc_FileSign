cmake_minimum_required(VERSION 3.13)
project(FileSign C)

set(CMAKE_C_STANDARD 99)

add_executable(FileSign main.c sign.c sign.c sign.h)

target_link_libraries(FileSign dl)
target_link_libraries(FileSign crypto ssl)
