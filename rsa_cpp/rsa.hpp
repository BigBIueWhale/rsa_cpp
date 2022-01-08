#pragma once

#include "random_engine.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/optional.hpp>

namespace cryptb
{
	class rsa
	{
		// Private key- for decrypting / digital signing
		// DON'T SHARE d WITH THE CLIENT!
		// Tends to be a number with around 2048 bits.
		boost::multiprecision::cpp_int d{ 0 };

		// It's completely safe to share e and N with the entire world.
		// In fact, you should.

		// Public key- for encrypting / verifying digital signature
		// Tends to be a very small number. Choosing the number 3 for example, is common.
		boost::multiprecision::cpp_int e{ 0 };

		// Public key- for everything. N is needed for all operations.
		// Tends to be a number with about 4096 bits.
		boost::multiprecision::cpp_int N{ 0 };

		// A pure mathematical function to solve for d such that:
		// ((e * d) modulo PhiN) == 1
		// e and PhiN must already be coprime.
		static boost::multiprecision::cpp_int findd(const boost::multiprecision::cpp_int& PhiN, const boost::multiprecision::cpp_int& e);

	public:
		rsa(const rsa&) = default;
		rsa(rsa&&) = default;
		rsa& operator=(const rsa&) = default;
		rsa& operator=(rsa&&) = default;

		// Constructor for generating RSA public-private key pair using the given random engine.
		//
		// When "num_bytes_in_prime_number" == 128 that's 2048-bit RSA
		// Should take a second and a half (very expensive function, call on an asynchronous thread).
		// 
		// "num_bytes_in_prime_number" must be at least 2
		//
		rsa(random_engine& rand, const int num_bytes_in_prime_number = 128);

		// Constructor for loading RSA public-private key pairs from values
		rsa(boost::multiprecision::cpp_int&& e, boost::multiprecision::cpp_int&& d, boost::multiprecision::cpp_int&& N) :
			e(std::move(e)), d(std::move(d)), N(std::move(N)) {}

		// Private secret key, don't share.
		const boost::multiprecision::cpp_int& get_d() const
		{
			return this->d;
		}

		// Public key, no danger. Allowed to reveal to the entire world.
		const boost::multiprecision::cpp_int& get_e() const
		{
			return this->e;
		}

		// Public key, no danger. Allowed to reveal to the entire world.
		const boost::multiprecision::cpp_int& get_N() const
		{
			return this->N;
		}

		// powm(a, b, c) == power(a, b) modulo c
		// When computing powm in one operation that can reduce the
		// computation time down from millions of years to mere microseconds.
		//
		// Technically powm treats negative exponents differently than power(a, b)
		// but in the function "rsa::findd()" we made sure that the returned
		// d is positive so in our use case we're only dealing with positive numbers.
		//

		// "original_message" should either be a large random number
		// otherwise the entire algorithm will be insecure.
		// That's because if the same clear-text message is sent to e or more recipients in an encrypted way,
		// and the receivers share the same exponent e, but different p, q, and therefore n,
		// then it's easy to decrypt the original clear-text message via the Chinese remainder theorem.
		// 
		// Basically: only use the "encrypt" function with an original_message that is a large
		// random number.
		//
		// You should check that:
		// 0 <= "original_message" < N
		// and that:
		// is_valid_public_key(e, N) == true
		// Otherwise the function will return boost::none
		static boost::optional<boost::multiprecision::cpp_int> encrypt(
			const boost::multiprecision::cpp_int& original_message,
			const boost::multiprecision::cpp_int& e,
			const boost::multiprecision::cpp_int& N)
		{
			if (!rsa::is_valid_public_key(e, N) || original_message >= N || original_message < 0)
				return boost::none;
			return static_cast<boost::multiprecision::cpp_int>(boost::multiprecision::powm(original_message, e, N));
		}

		// You should check that:
		// 0 <= "encrypted_message" < this->N
		// Otherwise the function will return boost::none
		boost::optional<boost::multiprecision::cpp_int> decrypt(const boost::multiprecision::cpp_int& encrypted_message)
		{
			if (encrypted_message >= this->N || encrypted_message < 0)
				return boost::none;
			return static_cast<boost::multiprecision::cpp_int>(boost::multiprecision::powm(encrypted_message, this->d, this->N));
		}

		// RSA digital signature.
		// message_hash must be a cryptographic hash of a message
		// and not the message itself.
		// Otherwise the digital signature won't be secure.
		// 
		// You should check that:
		// 0 <= "message_hash" < this->N
		// Otherwise the function will return boost::none
		boost::optional<boost::multiprecision::cpp_int> sign(const boost::multiprecision::cpp_int& message_hash)
		{
			// It's the same algorithm. Isn't that convenient!
			return this->decrypt(message_hash);
		}

		// Verify an RSA digital signature.
		static bool is_valid_signature(
			const boost::multiprecision::cpp_int& message_hash,
			const boost::multiprecision::cpp_int& signature_of_hash,
			const boost::multiprecision::cpp_int& e,
			const boost::multiprecision::cpp_int& N)
		{
			// It's the same algorithm. Isn't that convenient!
			const boost::optional<boost::multiprecision::cpp_int> result = rsa::encrypt(signature_of_hash, e, N);
			if (result == boost::none)
				return false;
			// If the signature matches then it's legit.
			return result.get() == message_hash;
		}

		// Recommended to check the validity of public keys taken
		// from an untrusted source.
		// We wouldn't want to store an invalid public key
		// in the database of known public keys.
		// That would cause functions such as rsa::encrypt
		// to return boost::none
		static bool is_valid_public_key(
			const boost::multiprecision::cpp_int& e,
			const boost::multiprecision::cpp_int& N)
		{
			if (e < 2 || N < (2*3))
				return false;
			return true;
		}
	};
}
