#include <windows.h>
#include <iostream>

#include "External_utils.h"

int main()
{
    setup_shits();

    std::cout << "                      " << std::endl;
    std::cout << "-                      -" << std::endl;
    std::cout << "START OF THE REAL DUMPER" << std::endl;
    std::cout << "-                      -" << std::endl;
    std::cout << "                      " << std::endl;

    print_address("capabilities", dump->dump_capabilities());
    print_address("getgc", dump->dump_getgc());
    print_address("instance_name", dump->dump_instance_name());
    print_address("instance_parent", dump->dump_parent());
    print_address("instance_children", dump->dump_instance_children());
    print_address("globalstate_corescripts", dump->dump_globalstate_corescripts());
    print_address("globalstate_gamescripts", dump->dump_globalstate_gamescripts());
    print_address("vmstate", dump->dump_vmstate());
    print_address("instance_capabilities", dump->get_instance_capabilities());
    print_address("modulescript_bytecode", dump->dump_modulescript_bytecode());
    print_address("modulescript_size", dump->dump_modulescript_size());
    print_address("moduelscript_hash", dump->dump_modulescript_hash());
    return 0;
}