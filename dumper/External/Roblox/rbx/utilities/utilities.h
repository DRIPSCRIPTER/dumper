#pragma once

#include <string>
#include <utility>

using vector_addresses_t = std::pair<uintptr_t, uintptr_t>;

namespace rbx::utilities {
	std::string rbx_string(uintptr_t address);
	vector_addresses_t get_vector_addresses(uintptr_t address);
	uintptr_t select_vector_element(vector_addresses_t vector_addresses, size_t index = 0, size_t step = 0x8);
	size_t get_vector_size(vector_addresses_t vector_addresses, size_t step = 0x8);
}