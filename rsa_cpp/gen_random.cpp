#include "gen_random.hpp"
#include "sha512.hpp"
#include <stdexcept>
#include <algorithm>

std::array<std::uint8_t, 64> cryptb::random_engine::gen_512_bit_random_number()
{
	const cryptb::sha512::digest_t sample1 = this->m_state.digest();
	this->m_state.update(sample1.data(), sample1.size());
	const cryptb::sha512::digest_t sample2 = this->m_state.digest();
	this->m_state.update(sample2.data(), sample2.size());
	std::array<std::uint8_t, 64> result{ {0} };
	for (int index = 0; index < result.size(); ++index)
	{
		// Fork the chain so that users of this function won't be able
		// to guess the internal state of the random_engine object
		// from the return value alone.
		result[index] = sample1[index] ^ sample2[index];
	}
	return result;
}

boost::multiprecision::cpp_int cryptb::random_engine::operator()(int num_bytes)
{
	if (num_bytes < 0)
	{
		throw std::invalid_argument("Error in function \"random_engine::operator()\"."
			" Invalid argument: \"num_bytes\" musn\'t be negative.");
	}
	std::vector<std::uint8_t> rand_num_as_bytes;
	rand_num_as_bytes.reserve(num_bytes);
	while (true)
	{
		const int num_bytes_missing = num_bytes - static_cast<int>(rand_num_as_bytes.size());
		if (num_bytes_missing == 0)
			break;
		std::array<std::uint8_t, 64> rand_num = this->gen_512_bit_random_number();
		const int num_bytes_to_push = std::min<int>(num_bytes_missing, static_cast<int>(rand_num.size()));
		rand_num_as_bytes.insert(rand_num_as_bytes.cend(), rand_num.cbegin(), rand_num.cbegin() + num_bytes_to_push);
	}
	boost::multiprecision::cpp_int integer_from_bytes;
	boost::multiprecision::import_bits(integer_from_bytes, rand_num_as_bytes.begin(), rand_num_as_bytes.end(), 8);
	return integer_from_bytes;
}
