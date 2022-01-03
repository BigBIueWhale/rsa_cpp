#pragma once

#include "random_engine.hpp"

namespace cryptb
{
	class prime
	{
	public:
		// Generates regular-old prime number. Not a "safe prime", but a cryptographically secure prime.
		// RSA doesn't need safe primes anyways.
		static boost::multiprecision::cpp_int gen_random(const int num_bytes, random_engine& engine);
	};
};
