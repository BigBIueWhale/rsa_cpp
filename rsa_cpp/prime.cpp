#include "prime.hpp"

// Miller-Rabin prime test algorithm.
#include <boost/multiprecision/miller_rabin.hpp>
#include <random>

boost::multiprecision::cpp_int cryptb::prime::gen_random(const int num_bytes, random_engine& engine)
{
	if (num_bytes <= 0)
		throw std::invalid_argument("Error in function \"cryptb::prime::gen_random\"."
			" The argument: \"num_bytes\" <= 0. There is no prime number with that number of bytes.");
	boost::multiprecision::cpp_int candidate;
	const auto seed = engine.operator()(sizeof(std::mt19937_64::result_type));
	std::mt19937_64 miller_rabin_engine(static_cast<std::mt19937_64::result_type>(seed));
	do
	{
		candidate = engine.operator()(num_bytes);
		// 64 Should be enough. The higher the number of trials, the lower the probability is for a false positive.
		// Note: making this number lower will significantly improve performance.
	} while (boost::multiprecision::miller_rabin_test(candidate, 64, miller_rabin_engine) == false);
	return candidate;
}
