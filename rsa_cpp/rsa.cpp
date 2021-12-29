#include "sha512.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>

int main()
{
	constexpr const std::uint8_t message[] = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway. Because bees don’t care what humans think is impossible.” SEQ. 75 - “INTRO TO BARRY” INT. BENSON HOUSE - DAY ANGLE ON: Sneakers on the ground. Camera PANS UP to reveal BARRY BENSON’S BEDROOM ANGLE ON: Barry’s hand flipping through different sweaters in his closet. BARRY Yellow black, yellow black, yellow black, yellow black, yellow black, yellow black...oohh, black and yellow... ANGLE ON: Barry wearing the sweater he picked, looking in the mirror. BARRY (CONT’D) Yeah, let’s shake it up a little. He picks the black and yellow one. He then goes to the sink, takes the top off a CONTAINER OF HONEY, and puts some honey into his hair. He squirts some in his mouth and gargles. Then he takes the lid off the bottle, and rolls some on like deodorant. CUT TO: INT. BENSON HOUSE KITCHEN - CONTINUOUS Barry’s mother, JANET BENSON, yells up at Barry. JANET BENSON Barry, breakfast is ready ";
	const std::array<std::uint8_t, 512 / 8> hash_bytes = sha512::calculate_sha512_hash(message, sizeof(message) - 1);
	for (const std::uint8_t& byte_elem : hash_bytes)
	{
		std::ostringstream num_as_str;
		num_as_str << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte_elem);
		std::cout << num_as_str.str() << " ";
	}
	return 0;
}
