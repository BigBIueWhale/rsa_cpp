#include "sha512.hpp"
#include <limits>
#include <algorithm>
#include <stdexcept>
#include <boost/endian/conversion.hpp>

// The size of the message in bits is put at the end of the final message_block.
// There are 128 bits reserved there, so according to the standards regarding
// SHA512, the largest message that SHA512 supports is of size 2^128-1 bits
// which I assume to never receive as part of this function.

void cryptb::sha512::update(const std::uint8_t* const data, const std::size_t len)
{
	if (data == nullptr)
	{
		throw std::invalid_argument("Error in function \"sha512::update\""
			" \"data\" can\'t be nullptr");
	}
	if (len <= 0)
	{
		throw std::invalid_argument("Error in function \"sha512::update\"."
			" \"len\" can\'t be 0");
	}
	if (this->m_num_bytes_filled < 0 || this->m_num_bytes_filled > sha512::message_block_size_bytes)
	{
		throw std::logic_error("Error in function \"sha512::update\"."
			" \"this->m_num_bytes_filled\" is out of range.");
	}
	for (std::size_t index_in_data = 0; index_in_data < len; )
	{
		// Compress if needed
		{
			const int num_bytes_unfilled_in_message_block = sha512::message_block_size_bytes - this->m_num_bytes_filled;
			if (num_bytes_unfilled_in_message_block == 0)
			{
				sha512::compress(this->m_message_block, m_hash_values);
				this->m_num_bytes_filled = 0;
			}
		}
		const int num_bytes_unfilled_in_message_block = sha512::message_block_size_bytes - this->m_num_bytes_filled;
		const std::size_t num_bytes_remaining_in_data = len - index_in_data;
		const int bytes_to_copy = static_cast<int>(std::min<std::size_t>(num_bytes_remaining_in_data, static_cast<std::size_t>(num_bytes_unfilled_in_message_block)));
		sha512::copy_arr_bytes_into_message_block(&data[index_in_data], bytes_to_copy, this->m_message_block, this->m_num_bytes_filled);
		this->m_num_bytes_filled += bytes_to_copy;
		index_in_data += bytes_to_copy;
	}
	// Times 8 to convert from bytes to bits
	this->m_bits_counter += static_cast<decltype(this->m_bits_counter)>(len) << 3;
}

void cryptb::sha512::zero_bytes(message_block_t& messsage_block, int index_byte_to_start_zeroing)
{
	if (index_byte_to_start_zeroing < 0 || index_byte_to_start_zeroing >= sha512::message_block_size_bytes)
	{
		throw std::invalid_argument("Error in function \"sha512::zero_bytes\"."
			" \"index_byte_to_start_zeroing\" is out of range.");
	}
	const int index_uint64 = index_byte_to_start_zeroing / 8;
	// One of the elements of message_block is tricky because part of it is already used
	// so we only need to clear the end of it in big endian byte order, meaning there's
	// one uint64 where zeroing the memory is not good and therefore we need to use
	// bit manipulation to zero only the least significant part of the uint64_t.
	// I'll call that element in message_block: "junction_uint64"
	{
		auto clear_n_least_significant_bits = [](const std::uint64_t& num, const int num_bits_to_clear) -> std::uint64_t
		{
			// Don't bit shift by 64 bits or more, that would be undefined behavior in C++
			if (num_bits_to_clear >= 64)
				return 0;
			else
				return static_cast<std::uint64_t>(num >> num_bits_to_clear) << num_bits_to_clear;
		};
		const int num_bytes_used_in_junction_uint64 = index_byte_to_start_zeroing % 8;
		const int num_bits_unused_in_junction_uint64 = 64 - (num_bytes_used_in_junction_uint64 * 8);
		messsage_block[index_uint64] = clear_n_least_significant_bits(messsage_block[index_uint64], num_bits_unused_in_junction_uint64);
	}
	std::fill(messsage_block.begin() + index_uint64 + 1, messsage_block.end(), 0);
}

// Creates a copy of "this->m_hash_values" and of "this->m_message_block"
// before computing the digest because there are some final steps that are
// required to get the digest and this function is not allowed to affect
// the internal state of the sha512 class. Therefore the changes that
// need to be made to the message_block and to the hash_values are done
// on the copies of those variables.
cryptb::sha512::digest_t cryptb::sha512::digest() const
{
	std::array<std::uint64_t, 8> final_hash = this->m_hash_values;
	{
		sha512::message_block_t message_block = this->m_message_block;
		int num_bytes_filled = this->m_num_bytes_filled;
		if (num_bytes_filled < 0 || num_bytes_filled > sha512::message_block_size_bytes)
		{
			throw std::logic_error("Error in function \"sha512::digest\"."
				" \"this->m_num_bytes_filled\" contains a value out of range.");
		}
		const bool is_completely_full = num_bytes_filled == sha512::message_block_size_bytes;
		if (!is_completely_full)
		{
			// Zero the unfilled bytes
			sha512::zero_bytes(message_block, num_bytes_filled);
		}
		// Advance to next block if terminating 1 bit doesn't fit
		else
		{
			sha512::compress(message_block, final_hash);
			num_bytes_filled = 0;
			std::fill(message_block.begin(), message_block.end(), 0);
		}
		// Set the 1 terminating bit.
		// Only one of the following bytes in a uint64_t
		// will be able to contain the 1 terminating byte:
		// 1000000010000000100000001000000010000000100000001000000010000000
		// The convention we're using for SHA512 revolves around 8-bit bytes, not bits.
		{
			const int index_byte_of_1_bit = num_bytes_filled;
			const int index_uint64_of_1_bit = index_byte_of_1_bit / 8;
			// Where index 0 is the most significant
			// in big-endian style.
			const int index_byte_in_uint64 = index_byte_of_1_bit % 8;
			message_block[index_uint64_of_1_bit] |= (static_cast<std::uint64_t>(1) << (63 - (index_byte_in_uint64 * 8)));
			++num_bytes_filled;
		}
		const int unused_len_bytes = sha512::message_block_size_bytes - num_bytes_filled;
		// The 128 bits of length that are inputted at the end of the last message block
		// as per the SHA512 algorithm. In big endian.
		{
			// Advance to next block if length doesn't fit
			{
				const bool length_fits = unused_len_bytes >= 128 / 8;
				if (!length_fits)
				{
					sha512::compress(message_block, final_hash);
					std::fill(message_block.begin(), message_block.end(), 0);
					num_bytes_filled = 0;
				}
			}
			// Extract the less significant half
			message_block[message_block.size() - 1] = static_cast<std::uint64_t>(this->m_bits_counter);
			// Extract the more significant half, big endian style.
			message_block[message_block.size() - 2] = static_cast<std::uint64_t>(this->m_bits_counter >> 64);
		}
		// Now that the length and the 1 terminating bit are both in message_block
		// let's finally calculate the final hash
		sha512::compress(message_block, final_hash);
	}

	// Finally, now we have the hash values inside of
	// "final_hash" as 64 bits big endian.
	// It's big endian because we originally loaded the
	// bytes into the message blocks as big endian.
	// We'll convert the hash to bytes to avoid
	// confusion over endianness.

	sha512::digest_t hash_user_friendly{ { 0 } };
	for (int index = 0; index < static_cast<int>(final_hash.size()); ++index)
	{
		boost::endian::store_big_u64(hash_user_friendly.data() + index * 8LL, final_hash[index]);
	}
	return hash_user_friendly;
}

// Loading the bytes into the std::uint64 as big endian because
// that's the convention when dealing with SHA512
//
// For example
// When calling the function "copy_arr_bytes_into_message_block" with
// the parameters:
//		bytes == { 0x01, 0x02, 0x03 },
//		num_bytes == 2,
//		message_block == { 1, 2, 3, 4, 5, 6, 7, 0xffffffffffffffff, 99, 99, 99, 99, 99, 99, 99, 99 },
//		num_bytes_already_used_in_message_block == 56
// Then message_block will become:
//		 message_block = { 1, 2, 3, 4, 5, 6, 7, 0x0102ffffffffffff, 99, 99, 99, 99, 99, 99, 99, 99 },
//
void cryptb::sha512::copy_arr_bytes_into_message_block(const std::uint8_t* const bytes, const int num_bytes, message_block_t& messsage_block, const int num_bytes_already_used_in_message_block)
{
	const bool bytes_taken_valid_range = num_bytes_already_used_in_message_block >= 0 && num_bytes_already_used_in_message_block < sha512::message_block_size_bytes;
	if (!bytes_taken_valid_range)
	{
		throw std::invalid_argument("Error in function \"sha512::copy_arr_bytes_into_arr_64_bits\"."
			" \"num_bytes_already_used_in_message_block\" is out of range [0, 128)");
	}
	if (num_bytes <= 0)
	{
		throw std::invalid_argument("Error in function \"sha512::copy_arr_bytes_into_arr_64_bits\"."
			" num_bytes can\'t be zero.");
	}
	if (bytes == nullptr)
	{
		throw std::invalid_argument("Error in function \"sha512::copy_arr_bytes_into_arr_64_bits\"."
			" neither \"bytes\" nor \"arr64\" are allowed to be nullptr.");
	}
	{
		const int num_bytes_left_in_message_block = sha512::message_block_size_bytes - num_bytes_already_used_in_message_block;
		if (num_bytes > num_bytes_left_in_message_block)
		{
			throw std::invalid_argument("Error in function \"sha512::copy_arr_bytes_into_arr_64_bits\"."
				" There isn\'t enough room in the message block to copy the requested number of bytes.");
		}
	}

	// The copying is very simple. Use boost::endian::load_big_u64 each time to copy
	// 8 bytes at a time into the "arr64".
	//
	// The issue we encounter is that the first and the last index of the arr64 array
	// may contain data that we're not allowed to overwrite.
	// The parameter: "num_bytes_already_taken" is responsible for determining that.
	// 
	// Therefore, for efficiency we'll still use boost::endian::load_big_u64 and only for
	// the beginning and end indexes in the relevant range inside of "arr64" we'll
	// implement specialized bitwise operations that don't override the existing data.
	//

	// Lambda function "fill_byte_in_index":
	// Index byte where 0 is the most significant byte and 7 is the least significant byte.
	// In big-endian style.
	//
	// Example:
	// Calling with:
	// num == 0x123456789abcdef0, byte == 0x01, index_byte == 1
	// 
	// sets num = 0x120156789abcdef0
	//
	auto fill_byte_in_index = [](std::uint64_t& num, const std::uint8_t& byte, const int& index_byte)
	{
		// The "index_byte" must be in the range [0, 7] otherwise it causes
		// undefined behavior.
		if (index_byte < 0 || index_byte > 7)
		{
			throw std::invalid_argument("Error in lambda function \"fill_byte_in_index\"."
				" The requested byte index in the uint64 is outside of the range [0, 7]");
		}
		const int amount_shift_left = ((7 - index_byte) * 8);
		// Clear the target byte
		num &= ~(static_cast<std::uint64_t>(0xff) << amount_shift_left);
		// Set the target byte (target byte must already by zeroed, that's why we cleared it just above).
		num |= static_cast<std::uint64_t>(byte) << amount_shift_left;
	};

	int index_in_arr64 = num_bytes_already_used_in_message_block / 8;
	int num_bytes_already_taken_in_first_uint64 = num_bytes_already_used_in_message_block % 8;
	int index_byte = 0;

	// Do the first index
	{
		const int unused_bytes_in_first_uint64 = 8 - num_bytes_already_taken_in_first_uint64;
		const int num_bytes_to_fill_in_in_first_uint64 = std::min<int>(num_bytes, unused_bytes_in_first_uint64);
		if (num_bytes_to_fill_in_in_first_uint64 > 0)
		{
			for (index_byte = 0; index_byte < num_bytes_to_fill_in_in_first_uint64; ++index_byte)
			{
				fill_byte_in_index(messsage_block[index_in_arr64], bytes[index_byte], num_bytes_already_taken_in_first_uint64 + index_byte);
			}
			++index_in_arr64;
		}
	}
	// Copy normally
	if (index_byte < num_bytes)
	{
		for (; ; index_byte += 8, ++index_in_arr64)
		{
			const int bytes_remaining = num_bytes - index_byte;
			if (bytes_remaining >= 8)
			{
				messsage_block[index_in_arr64] = boost::endian::load_big_u64(&bytes[index_byte]);
			}
			// Do the last index in the arr64
			if (bytes_remaining < 8)
			{
				for (int bytes_counter = 0; bytes_counter < bytes_remaining; ++bytes_counter)
				{
					fill_byte_in_index(messsage_block[index_in_arr64], bytes[index_byte + bytes_counter], bytes_counter);
				}
			}
			if (bytes_remaining <= 8)
			{
				break;
			}
		}
	}
}
void cryptb::sha512::compress(const message_block_t & message_block, std::array<std::uint64_t, 8>&hash_values)
{
	std::array<std::uint64_t, 80> message_schedule{ {0} };

	std::copy(message_block.begin(), message_block.end(), message_schedule.begin());
	for (int word_index = 16; word_index < 80; ++word_index)
	{
		message_schedule[word_index] =
			sha512::lowercase_sigma1(message_schedule[word_index - 2LL])
			+ message_schedule[word_index - 7LL]
			+ sha512::lowercase_sigma0(message_schedule[word_index - 15LL])
			+ message_schedule[word_index - 16LL];
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
	std::uint64_t a = hash_values[0];
	std::uint64_t b = hash_values[1];
	std::uint64_t c = hash_values[2];
	std::uint64_t d = hash_values[3];
	std::uint64_t e = hash_values[4];
	std::uint64_t f = hash_values[5];
	std::uint64_t g = hash_values[6];
	std::uint64_t h = hash_values[7];
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
	hash_values[0] += a;
	hash_values[1] += b;
	hash_values[2] += c;
	hash_values[3] += d;
	hash_values[4] += e;
	hash_values[5] += f;
	hash_values[6] += g;
	hash_values[7] += h;
}