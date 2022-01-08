# This is a C++20 project
The RSA implementation contains a few components
* SHA512 hash function
* Pseudo random number generator (uses SHA512)
* Prime number generator (uses boost::multiprecision::miller_rabin_test)
* RSA public-private key pair generator
# using namespace cryptb
e is always 65537 and d is always positive. Couldn't be simpler!\
This library aspires to keep only the bare minimum for a fully functioning secure general purpose cryptosystem.\
In the future we will support symmetric encryption and older versions of C++.
# Pitfalls
Since this is vanilla RSA with no fancy padding etc. there are only two ways to use this library securely.
* Choose a random number in the range \[0, N) and encrypt it using cryptb::rsa::encrypt.
* Take the SHA512 hash of some unique binary information (such as a PDF file) and convert that into a number, and then sign it using cryptb::rsa::sign
\
\
**Don't**
* Try to encrypt the same large random number more than once (Chinese remainder theorem attack).
* Use RSA for anything but key exchange and digital signatures.
# rsa_cpp
Simple RSA Implementation\
Uses boost::endian and boost::multiprecision::cpp_int and C++20 features.
# Simplicity Is The First Step To Security
It doesn't have to be complicated.\
A human is more likely to be compromized than a 1024 bit prime number. That's a fact.
