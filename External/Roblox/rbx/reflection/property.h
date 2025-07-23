#pragma once

#include "member.h"

namespace rbx::classes {
	class PropertyDescriptor : public MemberDescriptor {
	public:
		PropertyDescriptor(uintptr_t address = 0);

		bool is_scriptable();
		bool is_public();
		bool set_scriptable(bool value);
	};
}