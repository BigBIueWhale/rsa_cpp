cmake_minimum_required(VERSION 3.0.0)
project(cryptb VERSION 0.1.0)

include_directories(src/rsa_cpp)
add_subdirectory(src/rsa_cpp)
include_directories(src/Main)
add_subdirectory(src/Main)
