#include <type_traits>
#include <limits>
#include <cstdint>
#include <cstddef>
#include <limits>
#include <array>
#include <algorithm>
#include <boost/endian/conversion.hpp>
#include <stdexcept>

class sha512
{
	static constexpr int return_hash_size_in_bits{ 512 };
	static constexpr int return_hash_size_in_bytes{ return_hash_size_in_bits / 8 };
public:
	static std::array<std::uint8_t, return_hash_size_in_bytes> calculate_sha512_hash(const std::uint8_t* const message, const std::size_t len);
private:
	template <typename x_T, int amount>
	static x_T rotater(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Rotates unsigned integer by a specific number of bits");
		static_assert(std::numeric_limits<x_T>::digits > amount, "Amount to shift needs to be smaller than number of bits in unsigned integer."
			"Otherwise it\'s undefined behavior.");
		return (x >> amount) | (x << (64 - amount));
	}

	template <typename x_T>
	static x_T lowercase_sigma0(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Must be unsigned integer");
		return sha512::rotater<x_T, 1>(x) ^ sha512::rotater<x_T, 8>(x) ^ (x >> 7);
	}

	template <typename x_T>
	static x_T lowercase_sigma1(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Must be unsigned integer");
		return sha512::rotater<x_T, 19>(x) ^ sha512::rotater<x_T, 61>(x) ^ (x >> 6);
	}

	template <typename x_T>
	static x_T uppercase_sigma0(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Must be unsigned integer");
		return sha512::rotater<x_T, 28>(x) ^ sha512::rotater<x_T, 34>(x) ^ sha512::rotater<x_T, 39>(x);
	}

	template <typename x_T>
	static x_T uppercase_sigma1(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Must be unsigned integer");
		return sha512::rotater<x_T, 14>(x) ^ sha512::rotater<x_T, 18>(x) ^ sha512::rotater<x_T, 41>(x);
	}

	template <typename xyz_T>
	static xyz_T choice(const xyz_T& x, const xyz_T& y, const xyz_T& z)
	{
		static_assert(std::is_unsigned<xyz_T>::value, "Must be unsigned integer");
		return (x & y) ^ ((~x) & z);
	}

	template <typename xyz_T>
	static xyz_T majority(const xyz_T& x, const xyz_T& y, const xyz_T& z)
	{
		static_assert(std::is_unsigned<xyz_T>::value, "Must be unsigned integer");
		return (x & y) ^ (x & z) ^ (y & z);
	}

	static void copy_arr_bytes_into_arr_64_bits(const std::uint8_t* const bytes, const std::size_t num_bytes, std::uint64_t* const arr64);
	static void SHA512_compress_message_block(const std::array<std::uint64_t, 16>& message_block, std::array<std::uint64_t, 8>& parameter_hash_values);
};
