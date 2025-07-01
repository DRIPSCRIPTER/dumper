#pragma once
#include <Windows.h>
#include <memory>  // Include this for std::make_unique
#include <string>

class TTaskScheduler
{
public:
    auto GetTaskSchedulerClient() -> uintptr_t;
    auto GetJobClient(std::string) -> uintptr_t;
    auto GetDataModelClient() -> uintptr_t;
    auto GetScriptContextClient() -> uintptr_t;
};

inline std::unique_ptr<TTaskScheduler> TaskScheduler = std::make_unique<TTaskScheduler>();