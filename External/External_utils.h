#pragma once
#include "Memory.h"
#include <format>
#include <sstream>
#pragma comment(lib, "User32.lib")
#include "Roblox/rbx/rbx.h"
#include "Roblox/rbx/instance/instance.h"
#include "Roblox/rbx/script/script_context.h"
#include "Roblox/TaskScheduler/task.h"
#include <Dumper.h>

using rbx::classes::Instance;
using rbx::classes::ScriptContext;

using namespace rbx::vmstate;
static void print_address(const std::string& name, uintptr_t offset) {
    if (name == "PID") {
        std::cout << name << ": " << offset << std::endl;
    }
    else {
        std::ostringstream oss;
        oss << "[*] " << name << ": 0x" << std::uppercase << std::hex << offset;  // Convert to uppercase hex
        std::cout << oss.str() << std::endl;
    }
}

static void setup_shits() {
    process->setup();
    process->patch_working_set();
    ScriptContext scriptcontext(TaskScheduler->GetScriptContextClient());
    dump->set_scriptcontext(scriptcontext.address);
    dump->set_datamodel(TaskScheduler->GetDataModelClient());
    dump->set_scriptcontext(TaskScheduler->GetScriptContextClient());
    rbx::offsets::init();
    Instance DataModel(TaskScheduler->GetDataModelClient());
    print_address("DataModel", TaskScheduler->GetDataModelClient());
    print_address("ScriptContext", TaskScheduler->GetScriptContextClient());
    print_address("CoreGui", DataModel.find_first_child("CoreGui").address);
    print_address("Modulescript", DataModel.find_first_child("CorePackages").find_first_child("Packages").find_first_child("Cryo").address);
    dump->set_modulescript(DataModel.find_first_child("CorePackages").find_first_child("Packages").find_first_child("Cryo").address);
    dump->set_coregui(DataModel.find_first_child("CoreGui").address);
}