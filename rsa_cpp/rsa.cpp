#include "rsa.hpp"
#include "prime.hpp"
#include <vector>
#include <cstddef>
#include <utility>

cryptb::rsa::rsa(random_engine& rand, const int num_bytes_in_prime_number)
{
	if (num_bytes_in_prime_number < 2)
		throw std::invalid_argument("Error in function \"cryptb::rsa::rsa\"."
			" The argument \"num_bytes_in_prime_number\" must be at least 2 bytes because"
			" the specified e is always 65537 and e must be smaller than PhiN."
			" Therefore PhiN must be at least 65538 and for that to occur the prime"
			" numbers must be at least 256 which is already more than one byte."
			" Therefore specifying \"num_bytes_in_prime_number\" == 1 would cause"
			" an infinite loop.");
	// 65537 is the largest known Fermat prime
	// It's pretty much the standard when choosing e in RSA
	this->e = 65537;
	boost::multiprecision::cpp_int PhiN = 0;
	// The probability that this do-while loop will run more
	// than once is small (not that small).
	// N must be coprime with 65537 and also PhiN must be coprime with 65537
	// But if they're not coprime, which is unlikely but does happen,
	// we'll just generate another p and q until e is coprime with both PhiN and with N.
	// e also must be smaller than PhiN
	bool is_e_compatible = false;
	do
	{
		auto crypto_rand = [&rand, &num_bytes_in_prime_number]() -> boost::multiprecision::cpp_int
		{
			return cryptb::prime::gen_random(num_bytes_in_prime_number, rand);
		};
		boost::multiprecision::cpp_int p = crypto_rand();
		boost::multiprecision::cpp_int q = 0;
		// Not sure this do-while loop is required because it's super unlikely to be needed.
		do
		{
			q = crypto_rand();
		} while (p == q);
		// N is just the multiple of the two generated secret primes.
		// Even though N is public, nobody can feasibly find the prime
		// numbers that were used to generate N because N is such a big number.
		this->N = p * q;
		PhiN = (std::move(p) - 1) * (std::move(q) - 1);
		// e must be coprime with PhiN and coprime with N and also smaller than PhiN
		// gcd = Greatest Common Divisor, uses the Euclidean algorithm.
		is_e_compatible =
			boost::multiprecision::gcd(this->e, N) == 1
			&& boost::multiprecision::gcd(this->e, PhiN) == 1
			&& this->e < PhiN;
	} while (!is_e_compatible);
	this->d = rsa::findd(PhiN, e);
	if (this->d <= 0)
	{
		throw std::logic_error("Error in function \"cryptb::rsa::rsa\"."
			" Failed to generate valid RSA public-private key pairs because of an internal logic error."
			" d is negative or 0."
			" I recommend to immediately stop using this library because this should never happen."
			" It should be impossible to reach this exception.");
	}
	// Test that encryption, decryption and digital signature work with the number a number "num"
	auto test_num = [this](const boost::multiprecision::cpp_int& num) -> void
	{
		bool passed_test = false;
		boost::optional<boost::multiprecision::cpp_int> encrypted_message = rsa::encrypt(num, this->e, this->N);
		if (encrypted_message != boost::none)
		{
			boost::optional<boost::multiprecision::cpp_int> decrypted_message = this->decrypt(encrypted_message.get());
			if (decrypted_message != boost::none)
			{
				if (decrypted_message.get() == num)
				{
					boost::optional<boost::multiprecision::cpp_int> signature = this->sign(num);
					if (signature != boost::none)
					{
						if (this->is_valid_signature(num, signature.get(), this->e, this->N))
						{
							passed_test = true;
						}
					}
				}
			}
		}
		if (!passed_test)
		{
			throw std::logic_error("Error in function \"cryptb::rsa::rsa\"."
				" Failed to generate valid RSA public-private key pairs because of an internal logic error."
				" A basic test of encryption and decryption using the generated keys, failed."
				" I recommend to immediately stop using this library because this should never happen."
				" It should be impossible to reach this exception.");
		}
	};
	test_num(5);
	test_num(this->N - 1);
}

boost::multiprecision::cpp_int cryptb::rsa::findd(const boost::multiprecision::cpp_int& PhiN, const boost::multiprecision::cpp_int& e)
{
	if (PhiN < 2 || e < 2)
	{
		throw std::invalid_argument("Error in function \"cryptb::rsa::findd\"."
			" Can\'t use such small values for PhiN or e.");
	}
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
	// Now that we know e and PhiN we must solve for d. That's what this function does.
	// 
	// We'll use the extended Euclidean algorithm which computes
	// exactly what we want.
	//
	struct euclid_step
	{
		boost::multiprecision::cpp_int a = 0, b = 0, quotient = 0;
	};
	// Simulating the recursive approach with a std::vector
	// that stores the results along the way.
	// After filling the vector we'll then do another loop
	// that goes through the steps backwards, and deletes element
	// from the vector along the way. Just like in the recursive approach.
	std::vector<euclid_step> steps_of_euclid;
	const bool PhiN_greater_than_e = PhiN > e;
	boost::multiprecision::cpp_int a = PhiN;
	boost::multiprecision::cpp_int b = e;
	boost::multiprecision::cpp_int d = 0;
	while (true)
	{
		// a and b will be positive so no difference between modulo and remainder.
		boost::multiprecision::cpp_int remainder = a % b;
		if (remainder == 0)
			break;
		euclid_step current_step;
		// Basically, it's just by order of a pen and pencil calculation from left to right
		current_step.a = std::move(a);
		current_step.b = std::move(b);
		current_step.quotient = current_step.a / current_step.b;
		steps_of_euclid.push_back(current_step);
		a = current_step.b;
		b = std::move(remainder);
	}
	if (!steps_of_euclid.empty())
	{
		euclid_step first_step = std::move(steps_of_euclid.back());
		// Pairs of numbers and their multiples
		std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int> valueA{ std::move(first_step.a), 1 };
		std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int> valueB{ std::move(first_step.b), -std::move(first_step.quotient) };
		steps_of_euclid.pop_back();
		for (bool BSmaller = true; !steps_of_euclid.empty(); steps_of_euclid.pop_back())
		{
			euclid_step current_step = std::move(steps_of_euclid.back());
			if (BSmaller)
			{
				BSmaller = false;
				valueA.second = std::move(valueA.second) + valueB.second * (-std::move(current_step.quotient));
				valueB.first = std::move(current_step.a);
			}
			else
			{
				BSmaller = true;
				valueB.second = std::move(valueB.second) + valueA.second * (-std::move(current_step.quotient));
				valueA.first = std::move(current_step.a);
			}
		}
		// We could use d >= PhiN but that would be continuously slow so we
		// might as well use the reduced version: d modulo PhiN because it's the same.
		if (valueA.first > valueB.first)
		{
			d = std::move(valueB.second) % PhiN;
		}
		else
		{
			d = std::move(valueA.second) % PhiN;
		}
		// We could use a negative d but that would be confusing and slow
		// so we'll use the equivalent positive d.
		//
		// powm functions that take powm(base, exponent, modulo)
		// tend to have problems with negative exponents.
		// 
		// For example in Python3.7:
		//	pow(2, -3, 5) throws an exception
		// But in Python3.8
		//	pow(2, -3, 5) == 2
		// And yet:
		//	pow(2, -3, 8) throws an exception even in Python3.8
		//
		if (d < 0)
		{
			// Make d positive
			d += PhiN;
		}
	}
	else
	{
		// You can't rely on this exception to always be thrown when
		// the arguments PhiN and d are not coprime.
		// In this case we just happen to certainly know that something is wrong.
		throw std::invalid_argument("Error in function \"cryptb::rsa::findd\"."
			" The given PhiN and e are definitely not coprime. That will produce a completely invalid RSA key pair.");
	}
	return d;
}
