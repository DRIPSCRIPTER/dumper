#pragma once

#include "../offsets.h"
#include <cstdint>
#include <string>

namespace rbx::classes {
	using namespace offsets;

	class Attribute {
	public:
		Attribute(uintptr_t address = 0);

		uintptr_t address;

		std::string name();
		std::string ttype_value();
	
		uintptr_t value();
	};
}