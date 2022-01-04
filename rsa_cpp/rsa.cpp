#include "rsa.hpp"
#include "prime.hpp"

cryptb::rsa::rsa(random_engine& rand, const int num_bytes_in_prime_number)
{
	boost::multiprecision::cpp_int PhiN = 0;
	{
		auto crypto_rand = [&rand, &num_bytes_in_prime_number]() -> boost::multiprecision::cpp_int
		{
			return cryptb::prime::gen_random(num_bytes_in_prime_number, rand);
		};
		const boost::multiprecision::cpp_int p = crypto_rand();
		boost::multiprecision::cpp_int q = 0;
		// Not sure this do-while loop is required because it's super unlikely to be needed.
		do
		{
			q = crypto_rand();
		} while (p != q);
		PhiN = (p - 1) * (q - 1);
		// N is just the multiple of the two generated secret primes.
		// Even though N is public, nobody can feasibly find the prime
		// numbers that were used to generate N because N is such a big number.
		this->N = p * q;
	}
	this->e = 0;
	{
		bool e_fits = false;
		do
		{
			// 2 byte prime number. e shouldn't be too big.
			this->e = cryptb::prime::gen_random(2, rand);

			// e must be coprime with PhiN and coprime with N
			// gcd = Greatest Common Divisor, uses the Euclidean algorithm.
			e_fits = boost::multiprecision::gcd(this->e, PhiN) == 1 && boost::multiprecision::gcd(this->e, N) == 1;
		} while (!e_fits);
	}
	this->d = rsa::findd(PhiN, e);
}

boost::multiprecision::cpp_int cryptb::rsa::findd(const boost::multiprecision::cpp_int& PhiN, const boost::multiprecision::cpp_int& e)
{
	// Uses the inverse of the Euclidian algorithm.
	// A.K.A the extended euclidian algorithm.
	//
	// We made sure that PhiN and e are coprime.
	// 
	// We want to find d (the secret decryption key) based on PhiN and e.
	// 
	// There exist multiple keys d that satisfy the criteria, but they're extremely rare.
	// The rarity is why the entire RSA algorithm is secure.
	// 
	// d must fit the following criteria: ((e * d) modulo PhiN) == 1
	// Now that we know e and PhiN we must solve for d.
	// 
	// We'll use the extended Euclidean algorithm which computes
	// exactly what we want.
	//
	
}
