#include "rsa.hpp"
#include "prime.hpp"

cryptb::rsa::rsa(random_engine& rand, const int num_bytes_in_prime_number = 2048)
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
	const boost::multiprecision::cpp_int PhiN = (p - 1) * (q - 1);

	// ... Rest of algorithm WIP
}
