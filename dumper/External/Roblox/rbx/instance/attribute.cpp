#include "../rbx.h"
#include "../utilities/utilities.h"
#include "attribute.h"
#include "Memory.h"

namespace rbx::classes {
	using namespace utilities;

	Attribute::Attribute(uintptr_t address) : address(address) {};

	std::string Attribute::name() {
		return rbx_string(address);
	}

	std::string Attribute::ttype_value() {
		uintptr_t ttype_address = process->read_longlong(address + ATTRIBUTE_TTYPE);
		uintptr_t name_address = process->read_longlong(ttype_address + ATTRIBUTE_NAME);

		return rbx_string(name_address);
	}

	uintptr_t Attribute::value() {
		return address + ATTRIBUTE_VALUE;
	}
}