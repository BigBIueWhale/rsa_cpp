#include <iostream>
#include "rsa.hpp"
#include <random>
int main()
{
	std::random_device rd;
	cryptb::random_engine engine(static_cast<boost::multiprecision::uint128_t>(rd.operator()()));
	cryptb::rsa whatever{ engine, 20 };
	std::cout << "e: " << whatever.get_e() << " d: " << whatever.get_d() << " N: " << whatever.get_N();
	return 0;
}
