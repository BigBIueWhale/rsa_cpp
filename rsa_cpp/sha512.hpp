#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <array>

class sha512
{
	// The hash size in bits
	static constexpr int hash_digest_size_in_bits{ 512 };
	// The hash size in bytes
	static constexpr int hash_digest_size_in_bytes{ hash_digest_size_in_bits / 8 };

	// The size of each message block in bits
	static constexpr int message_block_size_bits{ sha512::hash_digest_size_in_bits * 2 };

	// The size of each message block in bytes
	static constexpr int message_block_size_bytes{ message_block_size_bits / 8 };

	// Current hash values, of the concatenation of all of the message
	// blocks that we went through until now not including the current message block.
	std::array<std::uint64_t, 8> m_hash_values{ {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL } };

	// The partial message block that hasn't yet been accounted for in
	// the summation m_hash_values.
	// The assumption is that m_message_block will be "emptied" when full
	// The variable "m_num_bytes_filled" keeps track of how full m_message_block is.
	std::array<std::uint64_t, message_block_size_bits / 64> m_message_block;

	// 1024 bits fills the entire 16 * 64bit message block
	static constexpr int completely_full_message_block = 1024;

	// The message block contains 64-bit integers but we're measuring the fullness level in
	// bytes. The message block is filled in big endian order inside of each 64-bit integer.
	// Meaning if "m_num_bytes_filled" then the 3 most significant bytes are set
	// in the first element of "current_message_block".
	int m_num_bytes_filled = 0;

public:
	sha512() = default;
	sha512(const sha512&) = default;
	sha512(sha512&&) = default;
	sha512& operator=(const sha512&) = default;
	sha512& operator=(sha512&&) = default;

	sha512(const std::uint8_t* const data, const std::size_t len) { this->update(data, len); }

	// Appends another part of the message to be concatenated.
	// Even though that sounds expensive, the memory usage is constant.
	void update(const std::uint8_t* const data, const std::size_t len);

	using digest_t = std::array<std::uint8_t, hash_digest_size_in_bytes>;

	// At any point you can ask for the hash of the concatenated data so far
	digest_t digest() const;

	~sha512() = default;
private:
	template <typename x_T, int amount>
	static x_T rotater(const x_T& x)
	{
		static_assert(std::is_unsigned<x_T>::value, "Rotates unsigned integer by a specific number of bits");
		static_assert(std::numeric_limits<x_T>::digits > amount, "Amount to shift needs to be smaller than number of bits in unsigned integer."
			" Otherwise it\'s undefined behavior.");
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

	// Helper function to copy elements from an array of bytes
	// into an array of 64 bit unsigned integers in big-endian byte loading.
	// That means that the first byte copies into the most significant
	// byte of the first element of the 64 bit integer array etc.
	//
	// All of the bytes in the 64-bit integer array that aren't direct
	// targets to be overridden, are unaffected by this function's operation.
	static void copy_arr_bytes_into_arr_64_bits(
		// Source array of bytes
		const std::uint8_t* const bytes,
		// Length of "bytes" array
		const std::size_t num_bytes,
		// Destination 64 bit array
		std::uint64_t* const arr64,
		// How many bytes are already used inside of the first element of arr64?
		// The first used byte is the most significant one, in big-endian style.
		const int num_bytes_already_taken);

	// Consumes m_message_block and alters m_hash_values accordingly.
	// Assumes that m_num_bytes_filled == completely_full_message_block
	// Sets m_num_bytes_filled to 0
	void compress();
};
