# This is a C++20 project
The RSA implementation contains a few components
* SHA512 hash function
* Pseudo random number generator (uses SHA512)
* Prime number generator (uses boost::multiprecision::miller_rabin_test)
* RSA public-private key pair generator
# rsa_cpp
Simple RSA Implementation\
Uses boost::endian and boost::multiprecision::cpp_int and C++20 features.

# Simplicity Is The First Step To Security
It doesn't have to be complicated.\
A human is more likely to be compromized than a 1024 bit prime number. That's a fact.
