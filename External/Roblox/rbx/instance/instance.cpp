#include "../rbx.h"
#include <thread>
#include <chrono>
#include "instance.h"
#include "Memory.h"

namespace rbx::classes {
	using namespace offsets;
	using namespace utilities;

	Instance::Instance(uintptr_t address) : address(address) {}

	Instance Instance::self() {
		uintptr_t self_address = process->read_longlong(
			address + INSTANCE_SELF
		);

		return Instance(self_address);
	}

	Instance Instance::set_self(uintptr_t value) {
		Instance old_self = self();

		process->write_longlong(
			address + INSTANCE_SELF, &value
		);

		return old_self;
	}

	ClassDescriptor Instance::class_descriptor() {
		uintptr_t class_descriptor_address = process->read_longlong(
			address + INSTANCE_CLASSDESCRIPTOR
		);

		return ClassDescriptor(class_descriptor_address);
	}

	std::string Instance::class_name() {
		return class_descriptor().name();
	}

	std::vector<Attribute> Instance::get_attributes() {
		std::vector<Attribute> attributes;

		uintptr_t ondemandinstance_address = process->read_longlong(address + INSTANCE_ONDEMANDINSTANCE);
		uint32_t attributes_count = process->read_long(ondemandinstance_address + ONDEMANDINSTANCE_ATTRIBUTESCOUNT);
		uintptr_t attributes_address = process->read_longlong(ondemandinstance_address + ONDEMANDINSTANCE_ATTRIBUTES);
		
		for (uint32_t i = 0; i != attributes_count; ++i) {
			uintptr_t attribute_address = attributes_address + i * 0x70;
			Attribute attribute(attribute_address);

			attributes.push_back(attribute);
		}

		return attributes;
	}

	Attribute Instance::get_attribute(std::string name) {
		for (Attribute attribute : get_attributes()) {
			if (attribute.name() == name)
				return attribute;
		}

		return Attribute(0);
	}

	Instance Instance::parent() {
		uintptr_t parent_address = process->read_longlong(
			address + INSTANCE_PARENT
		);

		return Instance(parent_address);
	}

	std::string Instance::name() {
		uintptr_t name_address = process->read_longlong(
			address + INSTANCE_NAME
		);

		return rbx_string(name_address);
	}

	bool Instance::children_check(Instance children, bool is_safe) {
		return (is_safe && class_name() == "DataModel" && children.class_name() == "MarketplaceService"); // next time make it class_name()
	}

	size_t Instance::get_children_count(vector_addresses_t vector_addresses) {
		return get_vector_size(vector_addresses, 0x10);
	}

	Instance Instance::select_children(vector_addresses_t vector_addresses, size_t index) {
		uintptr_t element_address = select_vector_element(vector_addresses, index, 0x10);
		return Instance(element_address);
	}
	
	std::vector<Instance> Instance::get_children(bool safe) {
		std::vector<Instance> child_list;

		uintptr_t vector_address = process->read_longlong(address + INSTANCE_CHILDREN);
		vector_addresses_t vector_addresses = get_vector_addresses(vector_address);
		size_t vector_size = get_children_count(vector_addresses);
		
		bool skip = false;
		for (size_t i = 0; i != vector_size; ++i) {
			if (skip) {
				skip = false;
				continue;
			}

			Instance children = select_children(vector_addresses, i);
			child_list.push_back(children);

			if (children_check(children, safe))
				skip = true;
		}

		return child_list;
	}

	Instance Instance::find_descendant_by_name(const std::string& target_name) {
		if (this->name() == target_name)
			return *this;

		auto children = this->get_children();
		for (size_t i = 0; i < children.size(); ++i) {
			Instance& child = children[i];
			Instance result = child.find_descendant_by_name(target_name);
			if ((uintptr_t)result.address > 0x1000)
				return result;
		}

		return Instance(0);
	}

	Instance Instance::find_descendant_by_class(const std::string& target_classname) {
		if (this->class_name() == target_classname)
			return *this;

		auto children = this->get_children();
		for (size_t i = 0; i < children.size(); ++i) {
			Instance& child = children[i];
			Instance result = child.find_descendant_by_class(target_classname);
			if ((uintptr_t)result.address > 0x1000)
				return result;
		}

		return Instance(0);
	}

	Instance Instance::find_first_child(std::string name, bool safe) {
		uintptr_t vector_address = process->read_longlong(address + INSTANCE_CHILDREN);
		vector_addresses_t vector_addresses = get_vector_addresses(vector_address);
		size_t vector_size = get_children_count(vector_addresses);

		bool skip = false;
		for (size_t i = 0; i != vector_size; ++i) {
			if (skip) {
				skip = false;
				continue;
			}

			Instance children = select_children(vector_addresses, i);
			if (children.name() == name)
				return children;

			if (children_check(children, safe))
				skip = true;
		}

		return Instance(0);
	}

	Instance Instance::find_first_class(std::string class_name, bool safe) {
		uintptr_t vector_address = process->read_longlong(address + INSTANCE_CHILDREN);
		vector_addresses_t vector_addresses = get_vector_addresses(vector_address);
		size_t vector_size = get_children_count(vector_addresses);

		bool skip = false;
		for (size_t i = 0; i != vector_size; ++i) {
			if (skip) {
				skip = false;
				continue;
			}

			Instance children = select_children(vector_addresses, i);
			if (children.class_name() == class_name)
				return children;

			if (children_check(children, safe))
				skip = true;
		}

		return Instance(0);
	}

	Instance Instance::wait_for_child(std::string name, size_t timeout, bool safe) {
		for (size_t i = 0; i != timeout; ++i) {
			Instance found = find_first_child(name);
			if (found.address > 0x1000)
				return found;

			std::this_thread::sleep_for(
				std::chrono::seconds(1)
			);
		}

		return Instance(0);
	}

	Instance Instance::traverse_child(std::vector<std::string> names, bool safe) {
		Instance found = *this;
		std::string last_name = names.back();

		for (auto name : names) {
			found = found.find_first_child(name, safe);

			if (found.address < 0x1000)
				break;

			if (found.name() == last_name)
				return found;
		}
		
		return Instance(0);
	}

	Instance Instance::operator[](size_t index) {
		uintptr_t vector_address = process->read_longlong(address + INSTANCE_CHILDREN);
		vector_addresses_t vector_addresses = get_vector_addresses(vector_address);

		return select_children(vector_addresses, index);
	}
};