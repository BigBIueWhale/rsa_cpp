#include <iostream>
#include "rsa.hpp"
#include <random>
#include <chrono>
int main()
{
	const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

	std::random_device rd;
	cryptb::random_engine engine(static_cast<boost::multiprecision::uint128_t>(rd.operator()()));
	cryptb::rsa whatever{engine};
	std::cout << "e: " << whatever.get_e() << std::endl
			  << " d: " << whatever.get_d() << std::endl
			  << " N: " << whatever.get_N() << std::endl;

	const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const std::chrono::steady_clock::duration duration = end - start;
	const long double seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() / 1e9L;
	std::cout << "Time took: " << seconds << std::endl;
	return 0;
}
