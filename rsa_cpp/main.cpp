#include <iostream>
#include "rsa.hpp"
#include <chrono>

int main()
{
	const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
	// Seed with a truly random numbers (the default constructor does it).
	cryptb::random_engine engine;
	for (int i = 0; i < 10000; ++i)
	{
		cryptb::rsa whatever{ engine, 2 };
		if (i % 1000 == 0)
		{
			std::cout << "e: " << whatever.get_e() << std::endl << " d: " << whatever.get_d() << std::endl << " N: " << whatever.get_N() << std::endl;
		}
	}
	const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const std::chrono::steady_clock::duration duration = end - start;
	const long double seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() / 1e9L;
	std::cout << "Time took: " << seconds << std::endl;
	return 0;
}
