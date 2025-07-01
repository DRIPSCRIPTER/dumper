#include "task.h"
#include "Memory.h"
#include "typedef.h"

auto TTaskScheduler::GetTaskSchedulerClient() -> uintptr_t
{
    return process->read_on_module<uintptr_t>(Addresses::RawScheduler);
}

auto TTaskScheduler::GetJobClient(std::string JobName) -> uintptr_t
{
    uintptr_t Task = this->GetTaskSchedulerClient();
    uintptr_t Start = process->read<uintptr_t>(Task + Offsets::JobStart);
    uintptr_t End = process->read<uintptr_t>(Task + Offsets::JobEnd);

    if (!Start || !End || Start >= End) return 0;

    for (uintptr_t job = Start; job < End; job += 0x10) {
        uintptr_t Address = process->read<uintptr_t>(job);
        if (!Address || Address == -1) continue;

        uintptr_t pointer = process->read<uintptr_t>(Address + Offsets::JobName);
        std::string jobName = process->read_string_unknown(pointer);

        if (jobName == JobName) {
            return Address;
        }
    }

    return 0;
}

auto TTaskScheduler::GetDataModelClient() -> uintptr_t
{
    return process->read<uintptr_t>(this->GetScriptContextClient() + Offsets::Parent);
}

auto TTaskScheduler::GetScriptContextClient() -> uintptr_t
{
    return process->read<uintptr_t>(this->GetJobClient("WaitingHybridScriptsJob") + Offsets::ScriptContextPoint);
}