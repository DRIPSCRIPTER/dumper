#pragma once

#include "member.h"
#include "property.h"
#include "function.h"
#include <vector>

namespace rbx::classes {
	class ClassDescriptor : public MemberDescriptor {
	public:
		ClassDescriptor(uintptr_t address = 0);

		std::vector<PropertyDescriptor> get_properties();
		std::vector<BoundFuncDescriptor> get_methods();
		PropertyDescriptor get_property(std::string name);
		BoundFuncDescriptor get_method(std::string name);
	};
}