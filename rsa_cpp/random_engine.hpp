#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <limits>
#include <algorithm>
#include <vector>
#include "sha512.hpp"

namespace cryptb
{
	class random_engine
	{
		sha512 m_state;
	public:
		// m_state has the following values:
		//
		// m_hash_values: 64 bytes == 2 ^ 512 valid combinations
		// m_message_block: 128 bytes == 2 ^ 1024 valid combinations
		// m_num_bytes_filled == 128 valid combinations
		// m_bits_counter == 2 ^ 128 valid combinations
		// 
		// Altogether that's: log2(2**(1024+512+128)*128) bits required
		// to achieve a similar number of combinations.
		// 
		// 1671 bits. A close enough number is 208 bytes.
		//
		static constexpr int optimal_seed_size_bytes = 208;
		// Generates a truly random number
		random_engine()
			: random_engine(random_engine::gen_truly_random_bytes()) {}
		random_engine(const random_engine&) = default;
		random_engine(random_engine&&) = default;
		random_engine& operator=(const random_engine&) = default;
		random_engine& operator=(random_engine&&) = default;
		// Supports using a specific size (optimal size) std::array as a seed
		random_engine(const std::array<std::uint8_t, random_engine::optimal_seed_size_bytes>& seed_bytes) :
			m_state(seed_bytes.data(), seed_bytes.size()) {}

		// Supports using any boost::multiprecision::cpp_int type as a seed.
		// For example:
		//
		//	boost::multiprecision::cpp_int
		// Or:
		//	boost::multiprecision::something_bits
		//
		template <unsigned MinBits, unsigned MaxBits, boost::multiprecision::cpp_integer_type SignType, boost::multiprecision::cpp_int_check_type Checked, class Allocator>
		random_engine(const boost::multiprecision::number<boost::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, Checked, Allocator>>& seed)
		{
			// Helper class that can be used with std::back_inserter_iterator.
			// This is to avoid using a std::vector with dynamic memory allocation.
			class back_inserter_t_for_sha512
			{
				sha512& m_obj;
			public:
				using value_type = std::uint8_t;
				back_inserter_t_for_sha512(sha512& obj) : m_obj(obj) {}
				void push_back(const std::uint8_t& elem)
				{
					this->m_obj.update(&elem, 1);
				}
			};
			back_inserter_t_for_sha512 dummy_back_inserter{ this->m_state };
			// The "msv_first == true" means that if the received number is 0xff01230
			// then it'll be layed-out in the byte array as:
			// { 0x0f, 0xf0, 0x12, 0x30 }
			// 
			// The alternative ("msv_first == false") would make the byte array look like:
			// { 0x30, 0x12, 0xf0, 0x0f }
			//
			// But it doesn't matter that much. As long as it's random.
			boost::multiprecision::export_bits(seed, std::back_inserter(dummy_back_inserter), 8, true);
		}

		// iter_T could be for example:
		//	std::vector<std::uint8_t>::const_iterator
		//
		template <typename iter_T>
		random_engine(const iter_T& begin, const iter_T& end)
		{
			using value_type = decltype(*begin);
			static_assert(std::is_integral<value_type>::value, "Must be iterator with an integer value type");
			static_assert(sizeof(value_type) == 8, "Must be iterator with an integer value type of size 8 bytes");
			std::for_each(begin, end,
				[&state = this->m_state](const value_type& val) -> void
				{
					const std::uint8_t cpy{ val };
					state.update(&cpy, 1);
				}
			);
		}

		// Get n random number with n number of bytes.
		boost::multiprecision::cpp_int operator()(int num_bytes);
		// Pseudo random number
		std::array<std::uint8_t, 64> gen_512_bit_random_number();
		// Truly random number
		std::array<std::uint8_t, random_engine::optimal_seed_size_bytes> gen_truly_random_bytes();
	};
}
