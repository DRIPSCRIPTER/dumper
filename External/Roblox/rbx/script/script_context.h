#pragma once

#include "../instance/instance.h"

namespace rbx::classes {
	class ScriptContext : public Instance {
	public:
		ScriptContext(uintptr_t address = 0);
		bool is_ingame();
		uint64_t max_capabilities();
		uint64_t set_max_capabilities(uint64_t value);
	};
}