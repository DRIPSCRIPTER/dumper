#pragma once
#define WIN32_LEAN_AND_MEAN
#include "Memory.h"
#include <windows.h>
#include <stdint.h>

class TDumper {
public:
	auto dump_capabilities() -> uintptr_t {
		for (uintptr_t addr = 0x690; addr < 0x7FF; addr += 0x10) {
			auto ptr_0 = process->read_longlong(s + addr);
			if (!ptr_0) continue;

			auto ptr_10 = process->read_longlong(s + addr + 0x10);
			auto ptr_18 = process->read_longlong(s + addr + 0x18);

			if (ptr_10 == ptr_18) return addr;
		}
		return 0;
	}

	auto dump_getgc() -> uintptr_t {
		for (uintptr_t offset = 0x518; offset < 0x800; offset++) {
			auto ptr = process->read_longlong(s + offset);
			auto str = process->read_string(ptr + 0x18);
			if (str == "LuaGc") return offset;
		}
		return 0;
	}

	auto dump_instance_name() -> uintptr_t {
		for (uintptr_t offset = 0x70; offset < 0x100; offset++) {
			auto ptr = process->read_longlong(dm + offset);
			if (!process->is_valid_pointer(ptr)) continue;

			auto str = process->read_string(ptr);
			if (str == "LuaApp") return offset;
		}
		return 0;
	}

	auto dump_parent() -> uintptr_t {
		auto name_offset = dump_instance_name();
		for (uintptr_t offset = 0x50; offset < 0x100; offset++) {
			auto ptr = process->read_longlong(s + offset);
			if (!process->is_valid_pointer(ptr)) continue;

			auto ptr2 = process->read_longlong(ptr + name_offset);
			auto str = process->read_string(ptr2);
			if (str == "LuaApp") return offset;
		}
		return 0;
	}

	auto dump_instance_children() -> uintptr_t {
		auto name_offset = dump_instance_name();
		for (uintptr_t offset = 0x80; offset < 0x100; offset++) {
			auto ptr = process->read_longlong(dm + offset);
			if (!process->is_valid_pointer(ptr)) continue;

			auto ptr2 = process->read_longlong(ptr);
			if (!process->is_valid_pointer(ptr2)) continue;

			auto ptr3 = process->read_longlong(ptr2);
			if (!process->is_valid_pointer(ptr3)) continue;

			auto str = process->read_string(ptr3 + name_offset);
			if (str == "Workspace") return offset;
		}
		return 0;
	}

	auto dump_globalstate_corescripts() -> uintptr_t {
		for (uintptr_t offset = 0x3B0; offset < 0x500; offset++) { 
			auto ptr = process->read_longlong(s + offset); // scriptcontext + candidate_globalstate
			if (!process->is_valid_pointer(ptr)) continue;
			auto ptr2 = process->read_longlong(ptr + 0x8);
			if (!process->is_valid_pointer(ptr2)) continue;
			auto ptr3 = process->read_longlong(ptr2 + 0x8);
			if (!process->is_valid_pointer(ptr3)) continue;
			return offset;
		}
		return 0; // :(
	}

	auto dump_globalstate_gamescripts() -> uintptr_t {
		for (uintptr_t offset = 0x270; offset < 0x500; offset++) { // simple dumper may update soon
			auto ptr = process->read_longlong(s + offset);
			auto ptr_2 = process->read_longlong(ptr + 0x78);
			if (!process->is_valid_pointer(ptr_2)) continue;
			auto ptr_3 = process->read_longlong(ptr_2);
			if (!process->is_valid_pointer(ptr_3)) continue;
			auto ptr_4 = process->read_longlong(ptr_3 + 0x8);
			if (!process->is_valid_pointer(ptr_4)) continue;
			return offset;
		}
	}
	auto dump_vmstate() -> uint64_t {
		for (uintptr_t offset = 0x1B0; offset < 0x7FF; offset++) {
			auto ptr = process->read_longlong(ms + offset);
			auto ptr2 = process->read_longlong(ptr);
			if (process->is_valid_pointer(ptr2)) {
				auto p1 = process->read_longlong(ptr2);
				if (!process->is_valid_pointer(p1))
					continue;
				return offset;
			}
			else {
				continue;
			}
		}
		return 0;
	}

	auto get_instance_capabilities() -> uintptr_t {
		for (uintptr_t offset = 0x378; offset < 0x7FF; offset++) {
			int must_val = 33554433;
			auto cptr1 = process->read_longlong(cg + 0x18);
			int intval = process->read_int(cptr1 + offset);
			if (intval == must_val) {
				return offset;
			}
			else {
				continue;
			}
		}
	}

	auto set_modulescript(uintptr_t addy) {
		ms = addy;
	}

	auto set_scriptcontext(uintptr_t sc) -> void {
		s = sc;
	}

	auto set_datamodel(uintptr_t dam) -> void {
		dm = dam;
	}

	auto set_coregui(uintptr_t cg12) -> void {
		cg = cg12;
	}

private:
	uintptr_t s;
	uintptr_t dm;
	uintptr_t ms;
	uintptr_t cg;

	bool match_with_wildcards(const uint8_t* data, const std::vector<uint8_t>& pattern) {
		for (size_t i = 0; i < pattern.size(); ++i) {
			if (pattern[i] != 0x00 && data[i] != pattern[i])
				return false;
		}
		return true;
	}
};

inline auto dump = std::make_unique<TDumper>();
