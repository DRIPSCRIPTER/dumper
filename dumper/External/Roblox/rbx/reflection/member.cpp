#include "../rbx.h"
#include "member.h"

namespace rbx::classes {
	using namespace utilities;
	using namespace offsets;

	MemberDescriptor::MemberDescriptor(uintptr_t address) : address(address) {}

	std::string MemberDescriptor::name() {
		uintptr_t name_address = process->read_longlong(
			address + MEMBERDESCRIPTOR_NAME
		);

		return rbx_string(name_address);
	}
}