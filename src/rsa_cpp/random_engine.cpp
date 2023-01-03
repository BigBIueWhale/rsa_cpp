#include "random_engine.hpp"
#include "sha512.hpp"
#include <stdexcept>
#include <algorithm>
#include <type_traits>
#include <cstring>

// For true random number generation (gen_truly_random_bytes)
#include <random>
#include <chrono>

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
	// The "msv_first == true" means that if rand_num_as_bytes
	// is: { 0x0f, 0xf0, 0x12, 0x30 }
	// then it'll turn into: 0xff01230
	// The alternative ("msv_first == true") would make the
	// outputted boost::multiprecision::cpp_int be: 0x3012f00f
	// But it doesn't matter that much. As long as it's random.
	boost::multiprecision::import_bits(integer_from_bytes, rand_num_as_bytes.begin(), rand_num_as_bytes.end(), 8, true);
	return integer_from_bytes;
}
static constexpr int ceil_division(const int dividend, const int divisor)
{
	//static_assert(dividend >= 0 && divisor > 0, "Will cause unexpected result")
	const int result = dividend / divisor;
	const int backwards = divisor * result;
	if (backwards < result)
		return result + 1;
	else
		return result;
}
std::array<std::uint8_t, cryptb::random_engine::optimal_seed_size_bytes> cryptb::random_engine::gen_truly_random_bytes()
{
	std::random_device hopefully_random;
	constexpr int num_bytes_in_each_random_number = sizeof(std::random_device::result_type);

	static_assert(random_engine::optimal_seed_size_bytes > 0, "Somebody broke cryptb library\'s constants.");
	static_assert(num_bytes_in_each_random_number > 0, "Somebody broke the standard library\'s constants.");
	static_assert(std::numeric_limits<std::random_device::result_type>::min() == std::random_device::min()
		&& std::numeric_limits<std::random_device::result_type>::max() == std::random_device::max(),
		"Assuming that the possible random range returned by std::random_device is the entire returned integer\'s range.");

	constexpr int required_random_numbers = ceil_division(random_engine::optimal_seed_size_bytes, num_bytes_in_each_random_number);
	std::array<std::random_device::result_type, required_random_numbers> rand_arr = { { 0 } };
	// Fill the array with truly random numbers
	for (std::random_device::result_type& elem : rand_arr)
	{
		elem = hopefully_random.operator()();
	}
	std::array<std::uint8_t, cryptb::random_engine::optimal_seed_size_bytes> result{ {0} };
	static_assert(std::is_trivially_copyable<decltype(rand_arr)::value_type>::value
		&& std::is_trivially_copyable<decltype(result)::value_type>::value,
		"I need this for the memcpy to be safe");
	std::memcpy(result.data(), rand_arr.data(), result.size());
	// Use time for extra randomness
	const std::chrono::high_resolution_clock::time_point t = std::chrono::high_resolution_clock::now();
	const auto nanoseconds_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
	static_assert(std::is_trivially_copyable<decltype(result)::value_type>::value
		&& std::is_trivially_copyable<decltype(nanoseconds_since_epoch)>::value,
		"I need this for the memcpy to be safe");
	static_assert(sizeof(nanoseconds_since_epoch) < result.size(),
		"I need this for the memcpy not to cause a stack buffer overflow");
	std::memcpy(result.data(), &nanoseconds_since_epoch, sizeof(nanoseconds_since_epoch));
	return result;
}
