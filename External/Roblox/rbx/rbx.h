#pragma once

#include <map>
#include "../../Utils/Memory.h"
#include "instance/instance.h"
#include "script/script_context.h"
#include "offsets.h"

namespace rbx {
	inline uint64_t globalstate;
	namespace offsets {}
	namespace vmstate {
		inline uintptr_t get_vmstate_(uintptr_t address) {
			auto r1 = process->read_longlong(address + dump->dump_vmstate()); // VMState
			return process->read_longlong(r1); // VMState
		}
		inline void set_loadingstate(uintptr_t vmstate) {
			process->write_int(vmstate + 0x20, 0);
		}
		inline int get_loadingstate(uintptr_t address) {
			return process->read_int(address + 0x20);
		}
	}

	namespace objects {
		using namespace classes;

		inline std::map<uintptr_t, std::string> allocations;
	}
}