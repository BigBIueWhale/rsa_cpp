cmake_minimum_required(VERSION 3.0.0)
project(cryptb VERSION 0.1.0)

set(Boost_INCLUDE_DIR C:/boost_1_80_0)

include_directories(src/rsa_cpp)
add_subdirectory(src/rsa_cpp)
include_directories(src/Main)
add_subdirectory(src/Main)
