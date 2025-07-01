#include "../rbx.h"
#include <TlHelp32.h>
#include <regex>
#include <cmath>
#include "utilities.h"

#pragma comment(lib, "Advapi32.lib")  // Link Windows Registry functions
#include <windows.h>

#define ROBLOX_REGISTRY_PATH "SOFTWARE\\ROBLOX Corporation\\Environments\\roblox-player"
#define ROBLOX_REGISTRY_ERROR "RobloxRegistryPathError"
#define ROBLOX_VERSION_ERROR "RobloxVersionError"

namespace rbx::utilities {

	std::string rbx_string(uintptr_t address) {
		bool is_long_string = process->read_longlong(address + 0x18) > 0xF;
		if (is_long_string)
			address = process->read_longlong(address);

		return process->read_string(address);
	}

	vector_addresses_t get_vector_addresses(uintptr_t address) {
		uintptr_t begin_address = process->read_longlong(address);
		uintptr_t end_address = process->read_longlong(address + 0x8);

		return std::make_pair(begin_address, end_address);
	}

	uintptr_t select_vector_element(vector_addresses_t vector_addresses, size_t index, size_t step) {
		auto [begin_address, end_address] = vector_addresses;
		uintptr_t element_address = process->read_longlong(std::clamp(
			begin_address + index * step,
			begin_address, end_address));

		return element_address;
	}

	size_t get_vector_size(vector_addresses_t vector_addresses, size_t step) {
		auto [begin_address, end_address] = vector_addresses;
		return (end_address - begin_address) / step;
	}
}