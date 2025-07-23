#include "../rbx.h"
#include "script_context.h"
#include "../utilities/utilities.h"

namespace rbx::classes {
	using namespace utilities;
	using namespace offsets;

	ScriptContext::ScriptContext(uintptr_t address) : Instance(address) {}

	bool ScriptContext::is_ingame() {
		uintptr_t vector_address = process->read_longlong(address + INSTANCE_CHILDREN);
		vector_addresses_t vector_addresses = get_vector_addresses(vector_address);
		size_t vector_size = get_children_count(vector_addresses);

		return vector_size > 1;
	}

	uint64_t ScriptContext::max_capabilities() {
		uintptr_t capabilities_address = process->read_longlong(address + SCRIPTCONTEXT_CAPABILITIES);
		uintptr_t max_capabilities_address = process->read_longlong(capabilities_address);
		uint64_t max_capabilities_b = process->read_longlong(max_capabilities_address + 0x10);

		return max_capabilities_b;
	}

	uint64_t ScriptContext::set_max_capabilities(uint64_t value) {
		uint64_t old_capabilities = max_capabilities();

		uintptr_t capabilities_address = process->read_longlong(address + SCRIPTCONTEXT_CAPABILITIES);
		uintptr_t max_capabilities_address = process->read_longlong(capabilities_address);

		process->write_longlong(max_capabilities_address + 0x10, &value);
		process->write_longlong(max_capabilities_address + 0x18, &value);

		return old_capabilities;
	}
}