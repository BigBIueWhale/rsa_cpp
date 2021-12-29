#include <limits>
#include <cstddef>
#include <algorithm>
#include <boost/endian/conversion.hpp>
#include <stdexcept>
#include "sha512.hpp"

std::array<std::uint8_t, sha512::return_hash_size_in_bytes> sha512::calculate_sha512_hash(const std::uint8_t* const message, const std::size_t len)
{
	constexpr int size_of_each_message_block_in_bits{ return_hash_size_in_bits * 2 };

	constexpr int size_of_each_message_block_in_bytes{ size_of_each_message_block_in_bits / 8 };

	// The size of the message in bits is put at the end of the final message_block.
	// There are 128 bits reserved there, so according to the standards regarding
	// SHA512, the largest message that SHA512 supports is of size 2^128-1 bits
	// which I assume to never receive as part of this function.
	std::array<std::uint64_t, 8> current_hash_values{ {
		0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
	} };
	{
		std::array<std::uint64_t, size_of_each_message_block_in_bits / 64> current_block;

		{
			bool terminating_bit_got_pushed_to_the_next_block = false;
			int index_of_terminating_1_in_64bit_arr = 0;

			std::size_t index_in_message = 0;

			for (; ; index_in_message += size_of_each_message_block_in_bytes)
			{
				const std::size_t bytes_remaining = len - index_in_message;
				if (bytes_remaining >= size_of_each_message_block_in_bytes)
				{
					// Loading as big-endian
					sha512::copy_arr_bytes_into_arr_64_bits(&message[index_in_message], size_of_each_message_block_in_bytes, current_block.data());
					sha512::SHA512_compress_message_block(current_block, current_hash_values);
				}
				if (bytes_remaining == size_of_each_message_block_in_bytes)
				{
					// Didn't put in the last 1 bit
					terminating_bit_got_pushed_to_the_next_block = true;
					break;
				}
				// If it's not exactly 128 bits then there's room for the 1 terminating bit
				// in the current block.
				else if (bytes_remaining < size_of_each_message_block_in_bytes)
				{
					const int index_of_terminating_1_in_current_block = bytes_remaining / 8;
					std::fill(current_block.begin() + index_of_terminating_1_in_current_block, current_block.end(), 0);
					// Loading as big-endian
					sha512::copy_arr_bytes_into_arr_64_bits(&message[index_in_message], bytes_remaining, current_block.data());
					const int index_byte_in_64_bits = bytes_remaining % 8;
					// Set the 1 terminating bit
					current_block[index_of_terminating_1_in_current_block] |= static_cast<std::uint64_t>(1) << (63 - (index_byte_in_64_bits * 8));
					index_of_terminating_1_in_64bit_arr = index_of_terminating_1_in_current_block;
					terminating_bit_got_pushed_to_the_next_block = false;
					break;
				}
			}

			if (terminating_bit_got_pushed_to_the_next_block)
			{
				std::fill(current_block.begin(), current_block.end(), 0);
				current_block[0] = static_cast<std::uint64_t>(1) << 63;
			}
			// If the terminating 1 takes up one of the last two 64-bit elements in current_block,
			// then the length is pushed to the next block. That's because there are 128 bits
			// reserved for the length of the message in bits.
			else if (index_of_terminating_1_in_64bit_arr >= static_cast<int>(current_block.size()) - 2)
			{
				sha512::SHA512_compress_message_block(current_block, current_hash_values);
				std::fill(current_block.begin(), current_block.end(), 0);
			}
		}
		// The "std::uint64_t"s exist inside of "current_block" in the machine native form.
		// That's why endianness is irrelevant here.
		// boost::endian::conditional_reverse(len, boost::endian::order::native, boost::endian::order::big);
		static_assert(std::is_unsigned<decltype(len)>::value,
			"I need the \"len\" variable to be unsigned because left-shifting a signed integer is undefined behaviour.");
		constexpr int num_bits_in_len = std::numeric_limits<decltype(len)>::digits;
		static_assert(num_bits_in_len <= 64, "Too many bits in std::size_t. We now need to change the code to account for that.");
		current_block[current_block.size() - 1] = static_cast<std::uint64_t>(static_cast<std::uint64_t>(len) << 3 /*times 8, from bytes to bits*/);
		current_block[current_block.size() - 2] = static_cast<std::uint64_t>(static_cast<std::uint64_t>(len) >> (64 - 3) /*The overflow bits from earlier*/);
		sha512::SHA512_compress_message_block(current_block, current_hash_values);
	}
	// Finally, now that we have the hash values inside of
	// "current_hash_values" as 64 bits big endian.
	// It's big endian because we originally loaded the
	// bytes into the message blocks as big endian.
	// we'll convert the hash to bytes to avoid
	// confusion over endianness.

	std::array<std::uint8_t, return_hash_size_in_bytes> final_hash;

	for (int index = 0; index < static_cast<int>(current_hash_values.size()); ++index)
	{
		boost::endian::store_big_u64(final_hash.data() + index * 8, current_hash_values[index]);
	}
	return final_hash;
}
 void sha512::copy_arr_bytes_into_arr_64_bits(const std::uint8_t* const bytes, const std::size_t num_bytes, std::uint64_t* const arr64)
{
	// Loading the bytes into the std::uint64 as big endian because
		// that's the convention when dealing with SHA512
	auto& load_big_or_little = boost::endian::load_big_u64;
	if (num_bytes > 0)
	{
		std::array<std::uint8_t, 8> emergency_buffer;
		std::size_t index_byte = 0;
		std::size_t index_arr = 0;
		for (; ; index_byte += 8, ++index_arr)
		{
			const std::size_t bytes_remaining = num_bytes - index_byte;
			if (bytes_remaining >= 8)
			{
				arr64[index_arr] = load_big_or_little(&bytes[index_byte]);
			}
			if (bytes_remaining < 8)
			{
				std::fill(emergency_buffer.begin(), emergency_buffer.end(), 0);
				std::copy_n(&bytes[index_byte], bytes_remaining, emergency_buffer.begin());
				arr64[index_arr] = load_big_or_little(emergency_buffer.data());
			}
			if (bytes_remaining <= 8)
			{
				break;
			}
		}
	}
}
 void sha512::SHA512_compress_message_block(const std::array<std::uint64_t, 16>& message_block, std::array<std::uint64_t, 8>& parameter_hash_values)
 {
	 std::array<std::uint64_t, 80> message_schedule;

	 std::copy(message_block.begin(), message_block.end(), message_schedule.begin());
	 for (int word_index = 16; word_index < 80; ++word_index)
	 {
		 message_schedule[word_index] =
			 sha512::lowercase_sigma1(message_schedule[word_index - 2])
			 + message_schedule[word_index - 7]
			 + sha512::lowercase_sigma0(message_schedule[word_index - 15])
			 + message_schedule[word_index - 16];
	 }

	 constexpr std::uint64_t constants[80]{
		 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
		 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
		 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
		 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
		 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
		 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
		 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
		 0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
		 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
		 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
		 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
		 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
		 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
		 0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
		 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
	 };
	 std::uint64_t a = parameter_hash_values[0];
	 std::uint64_t b = parameter_hash_values[1];
	 std::uint64_t c = parameter_hash_values[2];
	 std::uint64_t d = parameter_hash_values[3];
	 std::uint64_t e = parameter_hash_values[4];
	 std::uint64_t f = parameter_hash_values[5];
	 std::uint64_t g = parameter_hash_values[6];
	 std::uint64_t h = parameter_hash_values[7];
	 for (int word_index = 0; word_index < 80; ++word_index)
	 {
		 const std::uint64_t T1 = sha512::uppercase_sigma1(e) + sha512::choice(e, f, g) + h + constants[word_index] + message_schedule[word_index];
		 const std::uint64_t T2 = sha512::uppercase_sigma0(a) + sha512::majority(a, b, c);
		 h = g;
		 g = f;
		 f = e;
		 e = d + T1;
		 d = c;
		 c = b;
		 b = a;
		 a = T1 + T2;
	 }
	 parameter_hash_values[0] += a;
	 parameter_hash_values[1] += b;
	 parameter_hash_values[2] += c;
	 parameter_hash_values[3] += d;
	 parameter_hash_values[4] += e;
	 parameter_hash_values[5] += f;
	 parameter_hash_values[6] += g;
	 parameter_hash_values[7] += h;
 }