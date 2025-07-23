#pragma once
#include <Windows.h>
#include <thread>
#include <TlHelp32.h>
#include <psapi.h>
#include <string>
#include "ntdll.h"
#include <vector>
#include <algorithm>
#include <mutex>
#include <unordered_set>
#include <iostream> 

class TMemory {
private:
    DWORD process_id = NULL;
    HANDLE process_handle = NULL;
    const wchar_t* procName = L"RobloxPlayerBeta.exe";
    HWND rbx_window = NULL;
    DWORD rbx_thread_id = NULL;
    MODULEINFO hyperion_info = {};
    typedef NTSTATUS(NTAPI* pNtGetNextProcess)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    void* allocated_memory;
    typedef NTSTATUS(WINAPI* NtFreeVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType

        );
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    auto get_peb_address() -> std::uintptr_t {
        PROCESS_BASIC_INFORMATION pbi{};
        NtQueryInformationProcess(process_handle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
        return reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress);
    }

    auto get_teb_address() -> std::uintptr_t {
#ifdef _M_X64
        return __readgsqword(0x30);
#else
        return __readfsdword(0x18);
#endif
    }

    auto get_whitelisted_sections() -> std::unordered_set<std::uintptr_t> {
        std::unordered_set<std::uintptr_t> whitelist;
        HMODULE modules[1024];
        DWORD needed;
        EnumProcessModules(process_handle, modules, sizeof(modules), &needed);
        int count = needed / sizeof(HMODULE);

        for (int i = 0; i < count; i++) {
            MODULEINFO info{};
            GetModuleInformation(process_handle, modules[i], &info, sizeof(info));

            BYTE headers[0x1000];
            SIZE_T read = 0;
            NtReadVirtualMemory(process_handle, modules[i], headers, sizeof(headers), &read);

            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(headers);
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(headers + dos->e_lfanew);
            auto section = IMAGE_FIRST_SECTION(nt);

            for (int s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                whitelist.insert(reinterpret_cast<std::uintptr_t>(modules[i]) + section[s].VirtualAddress);
            }
        }

        return whitelist;
    }

    auto entropy(const std::vector<std::uint8_t>& data) -> double {
        double freq[256]{};
        for (auto b : data) freq[b]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                double p = freq[i] / data.size();
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }

    auto thread_clean(std::uintptr_t start, std::uintptr_t end, bool safe_mode, const std::unordered_set<std::uintptr_t>& whitelist, std::uintptr_t peb, std::uintptr_t teb) -> void {
        MEMORY_BASIC_INFORMATION mbi{};
        std::uintptr_t address = start;
        int region_counter = 0;

        while (address < end && VirtualQueryEx(process_handle, reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE) &&
                !(mbi.Protect & PAGE_GUARD) &&
                mbi.RegionSize >= 0x1000 &&
                std::abs((std::intptr_t)address - (std::intptr_t)peb) > 0x10000 &&
                std::abs((std::intptr_t)address - (std::intptr_t)teb) > 0x10000 &&
                whitelist.count((std::uintptr_t)mbi.AllocationBase) == 0) {
                if (safe_mode) {
                    if (mbi.RegionSize < 0x1000) {
                        address += mbi.RegionSize;
                        continue;
                    }

                    std::vector<std::uint8_t> buffer(mbi.RegionSize);
                    if (NtReadVirtualMemory(process_handle, reinterpret_cast<void*>(address), buffer.data(), mbi.RegionSize, nullptr)) {
                        if (entropy(buffer) < 1.0) {
                            virtual_free((PVOID)address);
                        }
                    }
                }
                else {
                    virtual_free(reinterpret_cast<void*>(address));
                }
                region_counter++;
                if (region_counter % 10 == 0) {
                    Sleep(10);
                }
            }
            if (address + mbi.RegionSize > end) {
                break;
            }

            address += mbi.RegionSize;
        }
    }

    auto remove_bytes_pass(bool safe_mode = true) -> void {
        const std::uintptr_t max_address = 0x7FFFFFFF0000;
        auto peb = get_peb_address();
        auto teb = get_teb_address();
        auto whitelist = get_whitelisted_sections();
        auto thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) thread_count = 4;

        std::vector<std::thread> threads;
        std::uintptr_t chunk = max_address / thread_count;

        for (int i = 0; i < thread_count; ++i) {
            std::uintptr_t start = chunk * i;
            std::uintptr_t end = (i == thread_count - 1) ? max_address : start + chunk;

            threads.emplace_back([this, safe_mode, start, end, whitelist, peb, teb]() {
                this->thread_clean(start, end, safe_mode, whitelist, peb, teb);
                });
        }

        for (auto& t : threads) {
            t.join();
        }
    }

    std::mutex table_mutex;

    auto scan_region(uint64_t val, uintptr_t start, uintptr_t end, std::vector<uintptr_t>& table) -> void {
        MEMORY_BASIC_INFORMATION mem_info;

        uintptr_t address = start;
        while (address < end) {
            if (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address), &mem_info, sizeof(mem_info)) == sizeof(mem_info)) {
                if (mem_info.State == MEM_COMMIT && (mem_info.Protect & PAGE_READWRITE)) {
                    std::vector<uint8_t> buffer(mem_info.RegionSize);
                    SIZE_T bytes_read;
                    if (NtReadVirtualMemory(process_handle, reinterpret_cast<LPCVOID>(address), buffer.data(), mem_info.RegionSize, &bytes_read)) {
                        for (SIZE_T i = 0; i < bytes_read - sizeof(uint64_t); ++i) {
                            uint64_t* value = reinterpret_cast<uint64_t*>(&buffer[i]);
                            if (*value == val) {
                                std::lock_guard<std::mutex> lock(table_mutex);
                                table.push_back(address + i);
                            }
                        }
                    }
                }
                address += mem_info.RegionSize;
            }
            else {
                address += 0x1000;
            }
        }
    }

    

    inline auto is_readable(DWORD protect) -> bool {
        return protect == PAGE_READONLY
            || protect == PAGE_READWRITE
            || protect == PAGE_EXECUTE_READ
            || protect == PAGE_EXECUTE_READWRITE;
    }
public:


    auto setup() -> void {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W Entry;
            Entry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnap, &Entry)) {
                do {
                    if (wcscmp(Entry.szExeFile, L"RobloxPlayerBeta.exe") == 0) {
                        process_id = Entry.th32ProcessID;
                        process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
                        rbx_window = FindWindowW(NULL, L"Roblox");

                        rbx_thread_id = GetWindowThreadProcessId(rbx_window, &process_id);
                        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                        NTDLL_INIT_FCNS(ntdll);
                        MODULEINFO moduleInfo = {};
                        HMODULE hModule = nullptr;
                        DWORD size;
                        if (EnumProcessModules(process_handle, &hModule, sizeof(hModule), &size)) {
                            if (GetModuleInformation(process_handle, hModule, &moduleInfo, sizeof(moduleInfo))) {
                                uintptr_t base = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
                                hyperion_info = moduleInfo;
                            }
                        }
                        break;
                    }
                } while (Process32NextW(hSnap, &Entry));
            }
            CloseHandle(hSnap);
        }
    }

    auto get_process_base() -> uintptr_t {
        uintptr_t base_address = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 mod_entry = { 0 };
            mod_entry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(snapshot, &mod_entry)) {
                base_address = reinterpret_cast<uintptr_t>(mod_entry.modBaseAddr);
            }

            CloseHandle(snapshot);
        }

        return base_address;
    }

    auto get_process_size() -> uintptr_t {
        uintptr_t module_size = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 mod_entry = { 0 };
            mod_entry.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(snapshot, &mod_entry)) {
                module_size = static_cast<uintptr_t>(mod_entry.modBaseSize);
            }
            CloseHandle(snapshot);
        }
        return module_size;
    }


    uintptr_t find_working_set() {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;

        while (VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT &&
                mbi.Protect == PAGE_READWRITE && mbi.RegionSize == 0x200000) {
                return reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            }
            address += mbi.RegionSize;
        }

        return 0;
    }

    // forced to add these shits
    template <typename T>
    void mem_read(DWORD64 address, T* buffer, SIZE_T size = 0) {
        if (size == 0)
            size = sizeof(buffer);

        NtReadVirtualMemory(
            process_handle,
            (LPCVOID)address,
            buffer,
            size,
            NULL
        );
    };

    template <typename T>
    void mem_write(DWORD64 address, T* buffer, SIZE_T size = 0) {
        if (size == 0)
            size = sizeof(buffer);

        NtWriteVirtualMemory(
            process_handle,
            (LPVOID)address,
            buffer,
            size,
            NULL
        );
    };

    template<typename T>
    auto read(uintptr_t address) -> T {
        T buff{};
        if (!process_handle) return 0;
        SIZE_T bytesRead;
        ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address), &buff, sizeof(T), &bytesRead);
        return buff;
    }

    bool read_bool(uintptr_t address) { return read<bool>(address); }
    int read_int(uintptr_t address) { return read<int>(address); }

    auto allocate(size_t size, DWORD protection = PAGE_EXECUTE_READWRITE) -> uintptr_t {
        if (!process_handle) return 0;

        return reinterpret_cast<uintptr_t>(
            VirtualAllocEx(process_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection)
            );
    }

    auto write_bytes(DWORD64 address, std::vector<char> value, SIZE_T byte_size = 0) -> void {
        if (byte_size < 1)
            byte_size = value.size();

        mem_write(
            address,
            value.data(),
            byte_size
        );
    }

    auto read_bytes(uintptr_t address, size_t size) -> std::vector<char> {
        std::vector<char> buffer(size, 0);
        mem_read(address, buffer.data(), size);

        return buffer;
    }

    template<typename T>
    auto read_on_module(uintptr_t address) -> T {
        T buff{};
        DWORD size;
        if (!process_handle) return 0;
        MODULEINFO moduleInfo = {};
        HMODULE hModule = nullptr;
        if (EnumProcessModules(process_handle, &hModule, sizeof(hModule), &size)) {
            if (GetModuleInformation(process_handle, hModule, &moduleInfo, sizeof(moduleInfo))) {
                uintptr_t base = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
                hyperion_info = moduleInfo;
                uintptr_t Address = base + address;
                NtReadVirtualMemory(process_handle, reinterpret_cast<LPCVOID>(Address), &buff, sizeof(T), nullptr);
            }
        }
        return buff;
    }

    auto get_module_info() -> MODULEINFO {
        return hyperion_info;
    }

    auto convert_addy(const void* Address, const void* Old, const void* New) -> void* {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Address) - reinterpret_cast<uintptr_t>(Old) + reinterpret_cast<uintptr_t>(New));
    }

    auto virtual_free(PVOID address) -> bool {
        static NtFreeVirtualMemory_t NtFreeVirtualMemory = nullptr;
        if (!NtFreeVirtualMemory) {
            NtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(
                GetProcAddress(GetModuleHandle("ntdll.dll"), "NtFreeVirtualMemory"));
        }

        if (!NtFreeVirtualMemory) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(process_handle, address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        PVOID addr = address;
        SIZE_T region_size = mbi.RegionSize;
        ULONG free_type = MEM_RELEASE;

        if (NtFreeVirtualMemory(process_handle, &addr, &region_size, free_type)) {
            return true;
        }
        else {
            return false;
        }
    }

    auto remove_bytes(bool safe_mode = true) -> void {
        std::thread([this, safe_mode]() {
            while (true) {
                remove_bytes_pass(safe_mode);
                Sleep(60000);
            }
            }).detach();

    }

    auto allocate() -> bool {
        PVOID Allocation = VirtualAllocEx(process_handle, nullptr, 0x1000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        allocated_memory = Allocation;
        return 1;
    }


    auto get_allocation() -> void* {
        return allocated_memory;
    }

    template<typename T>
    bool write_memory(uintptr_t address, T value) {
        if (!process_handle) return false;
        SIZE_T bytesWritten;
        return NtWriteVirtualMemory(process_handle, reinterpret_cast<PVOID>(address), &value, sizeof(T), &bytesWritten) == 0 && bytesWritten == sizeof(T);
    }

    auto rebase_value(uintptr_t address) -> uintptr_t{
        return address - get_process_base();
    }

    auto patcher_write_bytes(uintptr_t address, const std::vector<uint8_t>& value) -> void {
        if (!process_handle || address == 0 || value.empty()) return;

        NtWriteVirtualMemory(
            process_handle,
            reinterpret_cast<PVOID>(address),
            (PVOID)value.data(),  // Correctly pass the raw byte array
            value.size(),
            nullptr
        );
    }

    auto virtual_query(uintptr_t address) -> MEMORY_BASIC_INFORMATION {
        auto mbi = MEMORY_BASIC_INFORMATION{};
        VirtualQueryEx(
            process_handle, (PVOID)address,
            &mbi, sizeof(mbi)
        );

        return mbi;
    }

    bool write_bool(uintptr_t address, bool value) { return write_memory<bool>(address, value); }
    bool write_int(uintptr_t address, int value) { return write_memory<int>(address, value); }

    bool write_string(uintptr_t address, const char* value) {
        if (!process_handle) return false;
        SIZE_T bytesWritten;
        return NtWriteVirtualMemory(process_handle, reinterpret_cast<PVOID>(address), (PVOID)value, strlen(value) + 1, &bytesWritten) == 0 && bytesWritten == strlen(value) + 1;
    }

    auto read_string_unknown(uintptr_t address) -> std::string {
        std::string result;
        char character = 0;
        int offset = 0;
        result.reserve(204);
        while (offset < 200) {
            character = read<char>(address + offset);
            if (character == 0) break;
            offset += sizeof(character);
            result.push_back(character);
        }
        return result;
    }

    auto read_long(uintptr_t address) -> long {
        return read<long>(address);
    }

    auto read_longlong(uintptr_t address) -> long long {
        return read<long long>(address);
    }

    auto write_long(uintptr_t address, size_t* value) -> bool {
        return write_memory<long>(address, *value);
    }


    template <typename T>
    auto write_longlong(uintptr_t address, T value) -> bool {
        if constexpr (std::is_pointer_v<T>) {
            if (!value) return false;
            return write_memory<long long>(address, *value);
        }
        else {
            return write_memory<long long>(address, value);
        }
    }

    

    auto read_string(uintptr_t address) -> std::string {
        const auto length = read<int>(address + 0x10);
        if (length >= 16u) {
            const auto name = read<uintptr_t>(address);
            return read_string_unknown(name);
        }
        return read_string_unknown(address);
    }

    auto get_pid() -> DWORD { return process_id; }
    auto get_handle() -> HANDLE { return process_handle; }
    auto get_window() -> HWND { return rbx_window;  }
    auto get_thread() -> DWORD { return rbx_thread_id;  }

    auto parse_pattern(const std::string& pattern, std::string& mask) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        mask.clear();
        for (size_t i = 0; i < pattern.size();) {
            if (pattern[i] == '?') {
                bytes.push_back(0);
                mask.push_back('?');
                i += (i + 1 < pattern.size() && pattern[i + 1] == '?') ? 2 : 1;
            }
            else if (isxdigit(pattern[i]) && i + 1 < pattern.size() && isxdigit(pattern[i + 1])) {
                bytes.push_back((uint8_t)strtoul(pattern.substr(i, 2).c_str(), nullptr, 16));
                mask.push_back('x');
                i += 2;
            }
            else {
                ++i;
            }
        }
        return bytes;
    }

    inline uintptr_t scan_memory_range(uintptr_t start, uintptr_t end,
        const std::vector<uint8_t>& pattern,
        const std::string& mask,
        int threads = 4)
    {
        if (threads < 1) threads = 1;
        std::atomic<uintptr_t> result{ 0 };
        SIZE_T pat_sz = pattern.size();
        const SIZE_T block_sz = 64 * 1024;

        uintptr_t total = end - start;
        uintptr_t chunk = total / threads;

        std::vector<std::thread> workers;
        workers.reserve(threads);

        for (int t = 0; t < threads; ++t) {
            uintptr_t chunk_start = start + t * chunk;
            uintptr_t chunk_end = (t + 1 == threads) ? end : (chunk_start + chunk);

            workers.emplace_back([=, &result]() {
                std::vector<uint8_t> buffer;
                buffer.reserve(block_sz + pat_sz - 1);

                MEMORY_BASIC_INFORMATION mbi;
                for (uintptr_t addr = chunk_start;
                    addr < chunk_end && result.load(std::memory_order_relaxed) == 0;)
                {
                    if (!VirtualQueryEx(process_handle, (LPCVOID)addr, &mbi, sizeof(mbi)))
                        break;

                    DWORD prot = mbi.Protect;
                    bool readable = (mbi.State & MEM_COMMIT)
                        && !(prot & (PAGE_GUARD | PAGE_NOACCESS))
                        && (prot & (PAGE_READONLY
                            | PAGE_READWRITE
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE));

                    if (readable) {
                        uintptr_t base = (uintptr_t)mbi.BaseAddress;
                        SIZE_T  region = mbi.RegionSize;
                        SIZE_T  offset = 0;

                        while (offset < region && !result.load(std::memory_order_relaxed)) {
                            SIZE_T to_read = std::min<SIZE_T>(block_sz + pat_sz - 1, region - offset);
                            buffer.resize(to_read);

                            SIZE_T got = 0;
                            if (NtReadVirtualMemory(process_handle,
                                (PVOID)(base + offset),
                                buffer.data(),
                                to_read,
                                &got) < 0)
                            {
                                break;
                            }

                            SIZE_T limit = (got < pat_sz) ? 0 : (got - pat_sz + 1);
                            for (SIZE_T i = 0; i < limit && !result.load(std::memory_order_relaxed); ++i) {
                                bool ok = true;
                                for (SIZE_T j = 0; j < pat_sz; ++j) {
                                    if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                                        ok = false;
                                        break;
                                    }
                                }
                                if (ok) {
                                    result.store(base + offset + i, std::memory_order_relaxed);
                                    return;
                                }
                            }

                            offset += block_sz;
                        }
                    }

                    addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                }
                });
        }

        for (auto& th : workers)
            th.join();

        return result.load(std::memory_order_relaxed);
    }

    inline uintptr_t aob_scan(const std::string& pat, int threads = 8) {
        std::string mask;
        auto bytes = parse_pattern(pat, mask);
        return scan_memory_range(0x0000000000000000ULL,
            0x7FFFFFFFFFFFULL,
            bytes,
            mask,
            threads);
    }

    std::vector<uintptr_t> multi_aob_scan(const std::string& pattern) {
        uintptr_t start = 0x0000000000000000;
        uintptr_t end = 0x7FFFFFFFFFFF;

        std::string mask;
        auto pattern_bytes = parse_pattern(pattern, mask);
        std::vector<uintptr_t> results;

        MEMORY_BASIC_INFORMATION mem_info;
        for (uintptr_t addr = start; addr < end;) {
            if (VirtualQueryEx(process_handle, (LPCVOID)addr, &mem_info, sizeof(mem_info)) == 0)
                break;

            if (mem_info.State == MEM_COMMIT && !(mem_info.Protect & PAGE_GUARD) &&
                (mem_info.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY))) {

                std::vector<uint8_t> buffer(mem_info.RegionSize);
                SIZE_T bytes_read;
                NTSTATUS status = NtReadVirtualMemory(process_handle, (LPCVOID)addr, buffer.data(), mem_info.RegionSize, &bytes_read);

                if (status == 0) {
                    SIZE_T pattern_size = pattern_bytes.size();

                    for (SIZE_T i = 0; i <= bytes_read - pattern_size; ++i) {
                        bool match = true;
                        for (SIZE_T j = 0; j < pattern_size; ++j) {
                            if (mask[j] == 'x' && buffer[i + j] != pattern_bytes[j]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            results.push_back(addr + i);
                        }
                    }
                }
            }

            addr += mem_info.RegionSize;
        }

        return results;
    }

    inline bool eb_scan(uint64_t val, std::vector<uintptr_t>& table, int threads = 8) {
        uintptr_t start = 0x000000000000ULL;
        uintptr_t end = 0x7FFFFFFFFFFFULL;
        uintptr_t range = end - start;
        uintptr_t chunk_size = range / threads;

        std::vector<std::vector<uintptr_t>> results(threads);
        std::vector<std::thread> worker_threads;

        for (int t = 0; t < threads; ++t) {
            uintptr_t chunk_start = start + t * chunk_size;
            uintptr_t chunk_end = (t == threads - 1) ? end : chunk_start + chunk_size;

            worker_threads.emplace_back([=, &results]() {
                uintptr_t address = chunk_start;
                MEMORY_BASIC_INFORMATION mem_info;
                std::vector<uint8_t> buffer;

                while (address < chunk_end) {
                    if (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address), &mem_info, sizeof(mem_info)) != sizeof(mem_info)) {
                        address += 0x1000;
                        continue;
                    }

                    if (!(mem_info.State & MEM_COMMIT) || (mem_info.Protect & PAGE_GUARD) || (mem_info.Protect & PAGE_NOACCESS)) {
                        address += mem_info.RegionSize;
                        continue;
                    }

                    SIZE_T region_size = mem_info.RegionSize;
                    if (region_size < sizeof(uint64_t)) {
                        address += region_size;
                        continue;
                    }

                    if (buffer.size() < region_size)
                        buffer.resize(region_size);

                    SIZE_T bytes_read = 0;
                    if (NtReadVirtualMemory(process_handle, reinterpret_cast<LPCVOID>(address), buffer.data(), region_size, &bytes_read) == 0) {
                        const uint8_t* data = buffer.data();
                        const uint8_t* end = data + bytes_read - sizeof(uint64_t);

                        for (const uint8_t* p = data; p <= end; ++p) {
                            if (*reinterpret_cast<const uint64_t*>(p) == val) {
                                results[t].push_back(address + (p - data));
                            }
                        }
                    }

                    address += region_size;
                }
                });
        }

        for (auto& th : worker_threads)
            th.join();

        for (const auto& res : results)
            table.insert(table.end(), res.begin(), res.end());

        return !table.empty();
    }


    auto string_scan(const std::string& target_string) -> uintptr_t {
        SYSTEM_INFO sys_info{};
        GetSystemInfo(&sys_info);

        auto address = static_cast<std::uint8_t*>(sys_info.lpMinimumApplicationAddress);
        auto max_address = static_cast<std::uint8_t*>(sys_info.lpMaximumApplicationAddress);
        auto string_size = target_string.size();

        while (address < max_address) {
            MEMORY_BASIC_INFORMATION memory_info{};
            if (!VirtualQueryEx(process_handle, address, &memory_info, sizeof(memory_info))) {
                address += 0x1000;
                continue;
            }

            if (memory_info.State == MEM_COMMIT && is_readable(memory_info.Protect)) {
                std::vector<std::uint8_t> buffer(memory_info.RegionSize);
                SIZE_T bytes_read = 0;

                if (NtReadVirtualMemory(process_handle, memory_info.BaseAddress, buffer.data(), static_cast<ULONG>(buffer.size()), &bytes_read)) {
                    for (std::size_t i = 0; i <= bytes_read - string_size; ++i) {
                        if (std::memcmp(buffer.data() + i, target_string.data(), string_size) == 0) {
                            return reinterpret_cast<uintptr_t>(memory_info.BaseAddress) + i;
                        }
                    }
                }
            }
            address += memory_info.RegionSize;
        }

        return 0;
    }

    bool is_valid_pointer(uintptr_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                return true;
            }
        }
        return false;
    }


    auto get_first_module_32() -> MODULEENTRY32W {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process_handle));
        MODULEENTRY32W modEntry; 
        modEntry.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hSnapshot, &modEntry)) {
            CloseHandle(hSnapshot);
            return modEntry;
        }

        CloseHandle(hSnapshot);
        return {};
    }


    auto get_hyperion() -> uintptr_t {
        uintptr_t modBaseAddr = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W modEntry;
            modEntry.dwSize = sizeof(modEntry);
            if (Module32FirstW(hSnap, &modEntry)) {
                do {
                    if (!_wcsicmp(modEntry.szModule, L"RobloxPlayerBeta.dll")) {  // Ensure WCHAR string
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(hSnap, &modEntry));
            }
        }
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    size_t get_hyperion_size() {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        HANDLE hProcess = get_handle();
        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
            return 0;

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (reinterpret_cast<uintptr_t>(hMods[i]) == get_hyperion())
                    return static_cast<size_t>(modInfo.SizeOfImage);
            }
        }

        return 0;
    }


    auto free_memory(uintptr_t address, size_t size) -> bool {
        if (!process_handle || address == 0) return false;

        PVOID baseAddress = reinterpret_cast<PVOID>(address);
        SIZE_T regionSize = size;
        NTSTATUS status = VirtualFreeEx(process_handle, &baseAddress, regionSize, MEM_RELEASE);

        return status == 0;
    }

    bool patch_working_set() {
        return write_longlong(find_working_set() + 0x208, 0x20); // W skibidi
    }

    auto readable_string(uintptr_t address) -> bool
    {
        constexpr size_t max_len = 512;
        char buffer[max_len]{};
        SIZE_T bytes_read = 0;

        if (NtReadVirtualMemory(process_handle, reinterpret_cast<void*>(address), buffer, max_len, &bytes_read) != 0)
            return false;

        for (size_t i = 0; i < bytes_read; ++i)
        {
            char c = buffer[i];
            if (c == '\0')
                return i >= 3;

            if (c < 0x20 || c > 0x7E)
                return false;
        }

        return false;
    }

    ~TMemory() {
        if (process_handle) {
            CloseHandle(process_handle);
        }
    }
};

inline auto process = std::make_unique<TMemory>();