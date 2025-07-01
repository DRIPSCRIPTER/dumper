#pragma once

#include "member.h"

namespace rbx::classes {
	class BoundFuncDescriptor : public MemberDescriptor {
	public:
		BoundFuncDescriptor(uintptr_t address = 0);
	};
}