// SPDX-License-Identifier: MIT
// Debugger-Erkennung am EIGENEN Prozess.
//
// Windows:
//   * PEB->BeingDebugged
//   * PEB->NtGlobalFlag (Heap-Tracing-Flags 0x70)
//   * Heap-Flags / ForceFlags des Prozess-Heaps
//   * CheckRemoteDebuggerPresent
//   * NtQueryInformationProcess: DebugPort, DebugObjectHandle, DebugFlags
//   * Hardware-Breakpoints (DR0-DR3, DR7)
//   * RDTSC-Zeitmessung (Single-Stepping)
// Linux:
//   * /proc/self/status -> TracerPid
//   * Elternprozess ist ein bekannter Tracer/Debugger
//   * LD_PRELOAD/LD_AUDIT gesetzt
//
// Es werden ausschliesslich Informationen ueber den eigenen Prozess gelesen.

#include "aegis/detect.hpp"

#include <cstring>
#include <string>

#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif
#else
#include <cstdlib>
#include <fstream>
#include <sstream>
#endif

namespace aegis::detect {
namespace {

#if defined(_WIN32)

// PEB-Offsets (stabil seit Windows XP, x86 und x64 getrennt).
#if defined(_WIN64)
constexpr std::size_t kPebGlobalFlagOffset = 0xBC;
constexpr std::size_t kPebProcessHeapOffset = 0x30;
constexpr std::size_t kHeapFlagsOffset = 0x70;
constexpr std::size_t kHeapForceFlagsOffset = 0x74;
#else
constexpr std::size_t kPebGlobalFlagOffset = 0x68;
constexpr std::size_t kPebProcessHeapOffset = 0x18;
constexpr std::size_t kHeapFlagsOffset = 0x40;
constexpr std::size_t kHeapForceFlagsOffset = 0x44;
#endif

inline std::uint8_t read_u8(const void* base, std::size_t offset) noexcept {
    return *reinterpret_cast<const std::uint8_t*>(static_cast<const std::uint8_t*>(base) + offset);
}

inline std::uint32_t read_u32(const void* base, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, sizeof(value));
    return value;
}

inline void* read_ptr(const void* base, std::size_t offset) noexcept {
    void* value = nullptr;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, sizeof(value));
    return value;
}

void* current_peb() noexcept {
    // NtCurrentTeb() ist in <winternl.h> deklariert.
    return reinterpret_cast<void*>(NtCurrentTeb()->ProcessEnvironmentBlock);
}

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn nt_query_information_process() noexcept {
    static NtQueryInformationProcessFn function = []() -> NtQueryInformationProcessFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) return nullptr;
        return reinterpret_cast<NtQueryInformationProcessFn>(
            ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }();
    return function;
}

/// cycles pro Aufruf - unter Single-Stepping explodiert der Wert.
std::uint64_t cycles_per_call(int iterations) noexcept {
#if defined(_MSC_VER)
    const std::uint64_t start = __rdtsc();
#else
    const std::uint64_t start = __builtin_ia32_rdtsc();
#endif
    volatile std::uint64_t sink = 0;
    for (int i = 0; i < iterations; ++i) {
        sink += static_cast<std::uint64_t>(::GetTickCount64());
    }
#if defined(_MSC_VER)
    const std::uint64_t end = __rdtsc();
#else
    const std::uint64_t end = __builtin_ia32_rdtsc();
#endif
    (void)sink;
    return (end - start) / static_cast<std::uint64_t>(iterations);
}

#else  // POSIX

bool is_tracer_name(const std::string& name) {
    if (name.empty()) return false;
    std::size_t count = 0;
    const aegis::data::TextEntry* table = aegis::data::tracer_names(count);
    return aegis::data::equals_any(table, count, name.c_str());
}

/// Sucht "Key:\tWert" in /proc/self/status.
std::string status_field(const std::string& status, const char* key) {
    const std::string prefix = std::string(key) + ":";
    std::size_t pos = 0;
    while (pos < status.size()) {
        std::size_t end = status.find('\n', pos);
        if (end == std::string::npos) end = status.size();
        const std::string line = status.substr(pos, end - pos);
        if (line.compare(0, prefix.size(), prefix) == 0) {
            return platform::trim(line.substr(prefix.size()));
        }
        pos = end + 1;
    }
    return std::string();
}

#endif

}  // namespace

void debugger(const Config& config, Findings& out) {
    if (!config.check_debugger) return;

#if defined(_WIN32)
    void* peb = current_peb();
    if (peb != nullptr) {
        if (read_u8(peb, 0x02) != 0) {
            add(out, true, "dbg.peb_being_debugged", Category::Debugger, Severity::Critical, 70,
                "PEB->BeingDebugged ist gesetzt", /*decisive=*/true);
        }

        const std::uint32_t global_flag = read_u32(peb, kPebGlobalFlagOffset);
        if ((global_flag & 0x70u) != 0) {
            add(out, true, "dbg.nt_global_flag", Category::Debugger, Severity::High, 40,
                platform::format("PEB->NtGlobalFlag = 0x%08X", global_flag));
        }

        const void* heap = read_ptr(peb, kPebProcessHeapOffset);
        if (heap != nullptr) {
            const std::uint32_t heap_flags = read_u32(heap, kHeapFlagsOffset);
            const std::uint32_t force_flags = read_u32(heap, kHeapForceFlagsOffset);
            if ((heap_flags & ~0x2u) != 0 || force_flags != 0) {
                add(out, true, "dbg.heap_flags", Category::Debugger, Severity::High, 35,
                    platform::format("Heap-Flags 0x%08X / Force 0x%08X", heap_flags, force_flags));
            }
        }
    }

    BOOL remote = FALSE;
    if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &remote) && remote) {
        add(out, true, "dbg.remote_present", Category::Debugger, Severity::High, 40,
            "CheckRemoteDebuggerPresent meldet einen Debugger");
    }

    if (NtQueryInformationProcessFn query = nt_query_information_process()) {
        // ProcessDebugPort (7)
        ULONG_PTR debug_port = 0;
        if (NT_SUCCESS(query(::GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr)) &&
            debug_port != 0) {
            add(out, true, "dbg.debug_port", Category::Debugger, Severity::Critical, 60,
                platform::format("DebugPort = 0x%llX",
                                 static_cast<unsigned long long>(debug_port)),
                /*decisive=*/true);
        }

        // ProcessDebugObjectHandle (30)
        HANDLE debug_object = nullptr;
        if (NT_SUCCESS(query(::GetCurrentProcess(), 30, &debug_object, sizeof(debug_object), nullptr)) &&
            debug_object != nullptr) {
            add(out, true, "dbg.debug_object", Category::Debugger, Severity::Critical, 60,
                "Debug-Object-Handle vorhanden", /*decisive=*/true);
        }

        // ProcessDebugFlags (31): 0 => Debugging aktiv
        ULONG debug_flags = 1;
        if (NT_SUCCESS(query(::GetCurrentProcess(), 31, &debug_flags, sizeof(debug_flags), nullptr)) &&
            debug_flags == 0) {
            add(out, true, "dbg.debug_flags", Category::Debugger, Severity::High, 45,
                "ProcessDebugFlags == 0");
        }
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (::GetThreadContext(::GetCurrentThread(), &context)) {
        if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
            add(out, true, "dbg.hardware_breakpoints", Category::Debugger, Severity::Critical, 60,
                platform::format("Hardware-Breakpoints: DR0=%llX DR1=%llX DR2=%llX DR3=%llX",
                                 static_cast<unsigned long long>(context.Dr0),
                                 static_cast<unsigned long long>(context.Dr1),
                                 static_cast<unsigned long long>(context.Dr2),
                                 static_cast<unsigned long long>(context.Dr3)),
                /*decisive=*/true);
        }
    }

    const std::uint64_t cycles = cycles_per_call(200);
    if (cycles > 250000) {
        add(out, true, "dbg.rdtsc_latency", Category::Debugger, Severity::Medium, 20,
            platform::format("%llu Takte pro Aufruf (Single-Stepping?)",
                             static_cast<unsigned long long>(cycles)));
    }
#else
    const std::string status = platform::proc_self_status();
    if (!status.empty()) {
        const std::string tracer = status_field(status, "TracerPid");
        if (!tracer.empty() && tracer != "0") {
            add(out, true, "dbg.ptrace_tracer", Category::Debugger, Severity::Critical, 70,
                platform::format("TracerPid = %s", tracer.c_str()), /*decisive=*/true);
        }

        const std::string ppid = status_field(status, "PPid");
        if (!ppid.empty()) {
            const std::string comm = platform::trim(
                platform::read_file((std::string("/proc/") + ppid + "/comm").c_str(), 256));
            if (!comm.empty() && is_tracer_name(comm)) {
                add(out, true, "dbg.parent_tracer", Category::Debugger, Severity::Critical, 60,
                    platform::format("Elternprozess ist '%s' (PID %s)", comm.c_str(), ppid.c_str()),
                    /*decisive=*/true);
            }
        }
    }

    const char* preload = ::getenv("LD_PRELOAD");
    if (preload != nullptr && *preload != '\0') {
        add(out, true, "dbg.ld_preload", Category::Integrity, Severity::Medium, 22,
            platform::format("LD_PRELOAD=%s", preload));
    }

    const char* audit = ::getenv("LD_AUDIT");
    if (audit != nullptr && *audit != '\0') {
        add(out, true, "dbg.ld_audit", Category::Integrity, Severity::Medium, 22,
            platform::format("LD_AUDIT=%s", audit));
    }
#endif
}

}  // namespace aegis::detect
