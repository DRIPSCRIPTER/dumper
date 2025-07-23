#include "../rbx.h"
#include "function.h"

namespace rbx::classes {
	BoundFuncDescriptor::BoundFuncDescriptor(uintptr_t address) : MemberDescriptor(address) {}
}