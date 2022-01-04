#pragma once

#include "random_engine.hpp"
#include <boost/multiprecision/cpp_int.hpp>

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

		static boost::multiprecision::cpp_int findd(const boost::multiprecision::cpp_int& PhiN, const boost::multiprecision::cpp_int& e);

	public:
		rsa(const rsa&) = default;
		rsa(rsa&&) = default;
		rsa& operator=(const rsa&) = default;
		rsa& operator=(rsa&&) = default;

		// Constructor for generating RSA public-private key pair using the given random engine.
		//
		// When "num_bytes_in_prime_number" == 2048 that's 4096-bit RSA
		//
		rsa(random_engine& rand, const int num_bytes_in_prime_number = 2048);

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
	};
}
