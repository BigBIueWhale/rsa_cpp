#include "sha512.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>

int main()
{
	constexpr const std::uint8_t message[] = "Hello World!";
	const std::array<std::uint8_t, 512 / 8> hash_bytes = sha512::calculate_hash(message, sizeof(message) - 1);
	for (const std::uint8_t& byte_elem : hash_bytes)
	{
		std::ostringstream num_as_str;
		num_as_str << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte_elem);
		std::cout << num_as_str.str() << " ";
	}
	return 0;
}
