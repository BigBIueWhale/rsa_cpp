#include <iostream>
#include "rsa.hpp"
#include <random>
int main()
{
	std::random_device rd;
	cryptb::random_engine engine(static_cast<boost::multiprecision::uint128_t>(rd.operator()()));
	cryptb::rsa whatever{ engine };
	return 0;
}
