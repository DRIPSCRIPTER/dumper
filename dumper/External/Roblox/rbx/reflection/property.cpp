#include "../rbx.h"
#include "property.h"

namespace rbx::classes {
	using namespace offsets;

	PropertyDescriptor::PropertyDescriptor(uintptr_t address) : MemberDescriptor(address) {}

	bool PropertyDescriptor::is_public() {
		uint32_t is_public_value = process->read_longlong(
			address + PROPERTYDESCRIPTOR_PUBLIC
		);

		return (is_public_value >> 6) & 1;
	}

	bool PropertyDescriptor::is_scriptable() {
		uint32_t is_scriptable_value = process->read_longlong(
			address + PROPERTYDESCRIPTOR_SCRIPTABLE
		);

		return (is_scriptable_value >> 5) & 1;
	}

	bool PropertyDescriptor::set_scriptable(bool value) {
		bool was_scriptable = is_scriptable();
		uint32_t is_scriptable_value = 0x3F ^ static_cast<uint32_t>(~value & 0xFF << 5);

		process->write_longlong(
			address + PROPERTYDESCRIPTOR_SCRIPTABLE,
			&is_scriptable_value
		);

		return was_scriptable;
	}
}