#include "../rbx.h"
#include "class.h"

namespace rbx::classes {
	using namespace utilities;
	using namespace offsets;

	ClassDescriptor::ClassDescriptor(uintptr_t address) : MemberDescriptor(address) {}

	std::vector<PropertyDescriptor> ClassDescriptor::get_properties() {
		std::vector<PropertyDescriptor> properties;

		vector_addresses_t vector_addresses = get_vector_addresses(
			address + CLASSDESCRIPTOR_PROPERTIES
		);

		size_t vector_size = get_vector_size(vector_addresses);

		for (size_t i = 0; i != vector_size; ++i) {
			uintptr_t property_address = select_vector_element(vector_addresses, i);

			PropertyDescriptor property(property_address);
			properties.push_back(property);
		}

		return properties;
	};

	std::vector<BoundFuncDescriptor> ClassDescriptor::get_methods() {
		std::vector<BoundFuncDescriptor> methods;

		vector_addresses_t vector_addresses = get_vector_addresses(
			address + CLASSDESCRIPTOR_METHODS
		);

		size_t vector_size = get_vector_size(vector_addresses);

		for (size_t i = 0; i != vector_size; ++i) {
			uintptr_t method_address = select_vector_element(vector_addresses, i);

			BoundFuncDescriptor method(method_address);
			methods.push_back(method);
		}

		return methods;
	};

	PropertyDescriptor ClassDescriptor::get_property(std::string name) {
		vector_addresses_t vector_addresses = get_vector_addresses(
			address + CLASSDESCRIPTOR_PROPERTIES
		);

		size_t vector_size = get_vector_size(vector_addresses);

		for (size_t i = 0; i != vector_size; ++i) {
			uintptr_t property_address = select_vector_element(vector_addresses, i);

			PropertyDescriptor property(property_address);
			if (property.name() == name)
				return property;
		}

		return PropertyDescriptor(0);
	}

	BoundFuncDescriptor ClassDescriptor::get_method(std::string name) {
		vector_addresses_t vector_addresses = get_vector_addresses(
			address + CLASSDESCRIPTOR_METHODS
		);

		size_t vector_size = get_vector_size(vector_addresses);

		for (size_t i = 0; i != vector_size; ++i) {
			uintptr_t method_address = select_vector_element(vector_addresses, i);

			BoundFuncDescriptor method(method_address);
			if (method.name() == name)
				return method;
		}

		return BoundFuncDescriptor(0);
	}
}