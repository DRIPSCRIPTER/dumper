#pragma once
#define WIN32_LEAN_AND_MEAN
#include "Memory.h"
#include <windows.h>
#include <stdint.h>

class TDumper {
private:
public:
	auto dump_capabilities() -> uintptr_t { // fixed
		for (uintptr_t addr = 0x690; addr < 0x7FF; addr++) {
			auto ptr_0 = process->read_longlong(s + addr);
			if (!process->is_valid_pointer(ptr_0)) continue;

			auto ptr_10s = process->read_longlong(s + addr);
			if (!process->is_valid_pointer(ptr_10s)) continue;
			auto ptr_8s = process->read_longlong(ptr_10s + 0x8);
			if (!process->is_valid_pointer(ptr_8s)) continue;

			auto ptr_10 = process->read_int(ptr_8s + 0x10);
			auto ptr_18 = process->read_int(ptr_8s + 0x18);

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
		for (uintptr_t offset = 0x1; offset < 0x100; offset++) {
			auto ptr = process->read_longlong(dm + offset);
			if (!process->is_valid_pointer(ptr)) continue;

			auto str = process->read_string(ptr);
			if (str == "LuaApp") return offset;
		}
		return 0;
	}

	auto dump_parent() -> uintptr_t {
		auto name_offset = dump_instance_name();
		for (uintptr_t offset = 0x1; offset < 0x100; offset++) {
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
		for (uintptr_t offset = 0x1; offset < 0x100; offset++) {
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
		for (uintptr_t offset = 0x300; offset < 0x7FF; offset++) {
			int target = 33554433;
			auto cd = process->read_longlong(cg + 0x18);
			int val = process->read_int(cd + offset);
			if (val == target) {
				return offset;
			}
			else {
				continue;
			}
		}
	}

	auto dump_modulescript_bytecode() -> uintptr_t {
		for (uintptr_t offset = 0x1; offset < 0x7FF; offset++) {
			int target = 201; // size [can be changed base on the size of the module]
			auto ptr = process->read_longlong(ms + offset);
			auto iv = process->read_int(ptr + 0x20);
			if (iv == target) {
				modulescriptbytecode_address = ptr; // so we can get modulesize
				return offset;
			}
			else {
				continue;
			}
		}
	}

	auto dump_modulescript_size() -> uintptr_t {
		for (uintptr_t offset = 0x1; offset < 0x100; offset++) {
			int target = 201;
			auto guess = process->read_int(modulescriptbytecode_address + offset);
			if (guess == target) {
				return offset;
			}
			else {
				continue;
			}
		}
	}

	auto dump_modulescript_hash() -> uintptr_t {
		for (uintptr_t offset = 0x1; offset < 0x7FF; offset++) {
			int target = 1680946276;
			auto guess = process->read_longlong(ms + offset);
			auto guess2 = process->read_int(guess + 0x0);
			if (guess2 == target) {
				return offset;
			}
			else {
				continue;
			}
		}
	}

	// goons

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

	// the variables
	uintptr_t s;
	uintptr_t dm;
	uintptr_t ms;
	uintptr_t cg;

	// the addresses
	uintptr_t modulescriptbytecode_address;

	bool match_with_wildcards(const uint8_t* data, const std::vector<uint8_t>& pattern) {
		for (size_t i = 0; i < pattern.size(); ++i) {
			if (pattern[i] != 0x00 && data[i] != pattern[i])
				return false;
		}
		return true;
	}
};

inline auto dump = std::make_unique<TDumper>();
