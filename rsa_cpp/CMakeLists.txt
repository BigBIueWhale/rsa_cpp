cmake_minimum_required(VERSION 3.0.0)
project(cryptb VERSION 0.1.0)

include(CTest)
enable_testing()

add_library(cryptb STATIC prime.cpp random_engine.cpp rsa.cpp sha512.cpp)
target_include_directories(cryptb PUBLIC "C:\\boost_1_77_0")
add_executable(example main.cpp)
target_link_libraries(example PUBLIC cryptb)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
