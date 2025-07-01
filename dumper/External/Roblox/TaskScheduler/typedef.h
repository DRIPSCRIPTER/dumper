#pragma once
#include <cstdint>

struct Offsets {
	static constexpr std::uintptr_t JobName = 0x18;
	static constexpr std::uintptr_t JobStart = 0x1D0;
	static constexpr std::uintptr_t JobEnd = 0x1D8;
	static constexpr std::uintptr_t ScriptContextPoint = 0x1F8;
	static constexpr std::uintptr_t Parent = 0x50;
};

struct Addresses {
	static constexpr std::uintptr_t RawScheduler = 0x6829508;
};