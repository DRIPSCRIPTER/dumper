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

static uint64_t homepage_raper(Instance dt) {
    auto scriptsploit = dt.traverse_child({
        "CorePackages", "Packages", "_Index", "UIBlox", "UIBlox", "App", "Tile", "MenuTile", "MenuTile"
        });
    if (scriptsploit.class_name() == "Folder") {
        return scriptsploit.find_first_child("MenuTile").address;
    }
    else if (scriptsploit.class_name() == "ModuleScript") {
        return scriptsploit.address;
    }
}

static void setup_shits() {
    process->setup();
    std::cout << "[*] Process found!" << std::endl;
    // process->remove_bytes(true); // removes useless bytes [buggy]
    std::cout << "[x] Cleaned memory!" << std::endl;
    process->patch_working_set();
    std::cout << "[x] Bypass Set!" << std::endl;
    if (!process->allocate())
        std::cout << "[x] Failed to allocated destroy" << std::endl;
    std::cout << "[*] Allocated" << std::endl;
    ScriptContext scriptcontext(TaskScheduler->GetScriptContextClient());
    dump->set_scriptcontext(scriptcontext.address);
    dump->set_datamodel(TaskScheduler->GetDataModelClient());
    dump->set_scriptcontext(TaskScheduler->GetScriptContextClient());
    rbx::offsets::init();
    Instance DataModel(TaskScheduler->GetDataModelClient());
    print_address("DataModel", TaskScheduler->GetDataModelClient());
    print_address("ScriptContext", TaskScheduler->GetScriptContextClient());
    print_address("CoreGui", DataModel.find_first_child("CoreGui").address);
    print_address("Modulescript", homepage_raper(TaskScheduler->GetDataModelClient()));
    static uintptr_t Capabilities = 0xFFFFFFF00LL | 0x200000000000003FLL;
    if (scriptcontext.set_max_capabilities(Capabilities)) {
        std::cout << "[*] Capabilities Setted" << std::endl;
    }
    dump->set_modulescript(homepage_raper(TaskScheduler->GetDataModelClient()));
    dump->set_coregui(DataModel.find_first_child("CoreGui").address);
}