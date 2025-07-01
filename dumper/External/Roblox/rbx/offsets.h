#pragma once

#include <cstdint>
#include "Dumper.h"

namespace rbx::offsets {
	constexpr uint32_t INSTANCE_SELF = 0x8;
	constexpr uint32_t INSTANCE_CLASSDESCRIPTOR = 0x18;
	constexpr uint32_t INSTANCE_ONDEMANDINSTANCE = 0x30;
	inline uint32_t INSTANCE_NAME;
	inline uint32_t INSTANCE_PARENT;
	inline uint32_t INSTANCE_CHILDREN;

	constexpr uint32_t OBJECTVALUE_VALUEBASE = 0xD8;
	
	constexpr uint32_t MEMBERDESCRIPTOR_NAME = 0x8;

	constexpr uint32_t CLASSDESCRIPTOR_PROPERTIES = 0x28;
	constexpr uint32_t CLASSDESCRIPTOR_EVENTS = 0xD0;
	constexpr uint32_t CLASSDESCRIPTOR_METHODS = 0x178;
	
	constexpr uint32_t PROPERTYDESCRIPTOR_SCRIPTABLE = 0x40;
	constexpr uint32_t PROPERTYDESCRIPTOR_PUBLIC = 0x44;

	constexpr uint32_t ONDEMANDINSTANCE_ATTRIBUTESCOUNT = 0x120;
	constexpr uint32_t ONDEMANDINSTANCE_ATTRIBUTES = 0x130;

	constexpr uint32_t ATTRIBUTE_NAME = 0;
	constexpr uint32_t ATTRIBUTE_TTYPE = 0x20;
	constexpr uint32_t ATTRIBUTE_VALUE = 0x30;

	inline uint32_t MODULESCRIPT_VMSTATEMAP;

	inline uint32_t SCRIPTCONTEXT_CAPABILITIES;
	inline uint32_t SCRIPTCONTEXT_GCJOB;
	// doesnt changeee
	constexpr uint32_t LIVETHREADREF_THREAD = 0x8;
	constexpr uint32_t WEAKTHREADREF_PREVIOUS = 0x10;
	constexpr uint32_t WEAKTHREADREF_NEXT = 0x18;
	constexpr uint32_t WEAKTHREADREF_LIVETHREADREF = 0x20;
	constexpr uint32_t WEAKTHREADREF_NODE = 0x28;
	constexpr uint32_t WEAKTHREADREFNODE_FIRST = 0x8;

	constexpr uint32_t PERVMSTATE_LOADINGSTATE = 0x20;
	constexpr uint32_t PERVMSTATE_WEAKTHREADREFNODE = 0x28;
	constexpr uint32_t PERVMSTATE_GLOBALSTATE = 0x30;

	namespace luastae {
		constexpr uint32_t extra_space = 0x78; // doesnt change

	}
	inline void init() {
		INSTANCE_NAME = dump->dump_instance_name();
		INSTANCE_PARENT = dump->dump_parent();
		INSTANCE_CHILDREN = dump->dump_instance_children();
		SCRIPTCONTEXT_CAPABILITIES = dump->dump_capabilities();
		SCRIPTCONTEXT_GCJOB = dump->dump_getgc();
		MODULESCRIPT_VMSTATEMAP = dump->dump_vmstate();

	}
}