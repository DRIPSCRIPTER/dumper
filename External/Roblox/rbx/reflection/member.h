#pragma once

#include <cstdint>
#include <string>

namespace rbx::classes {
	class MemberDescriptor {
	public:
		MemberDescriptor(uintptr_t address = 0);

		uintptr_t address;

		std::string name();
	};
}