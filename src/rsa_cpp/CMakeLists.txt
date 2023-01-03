add_library(cryptb STATIC prime.cpp random_engine.cpp rsa.cpp sha512.cpp prime.hpp random_engine.hpp rsa.hpp sha512.hpp)
target_include_directories(cryptb PUBLIC "C:\\boost_1_80_0")
