#pragma once

#include "../reflection/class.h"
#include "attribute.h"
#include <cstdint>
#include <string>
#include <vector>
#include "../utilities/utilities.h"

namespace rbx::classes {
	class Instance {
	private:
		bool children_check(Instance children, bool is_safe);
	public:
		Instance(uintptr_t address = 0);

		uintptr_t address;

		Instance self();
		Instance set_self(uintptr_t value);
		ClassDescriptor class_descriptor();
		std::string class_name();
		std::vector<Attribute> get_attributes();
		Attribute get_attribute(std::string name);
		Instance parent();
		std::string name();
		size_t get_children_count(vector_addresses_t vector_addresses);
		Instance select_children(vector_addresses_t vector_addresses, size_t index = 0);
		std::vector<Instance> get_children(bool safe = true);
		Instance find_descendant_by_name(const std::string& target_name);
		Instance find_descendant_by_class(const std::string& target_name);
		Instance find_first_child(std::string name, bool safe = true);
		Instance find_first_class(std::string class_name, bool safe = true);
		Instance wait_for_child(std::string name, size_t timeout = 5, bool safe = true);
		Instance traverse_child(std::vector<std::string> names, bool safe = true);
		Instance operator[](size_t index);
	};
}