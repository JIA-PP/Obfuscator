// SPDX-License-Identifier: MIT
// Inline-Hook-Erkennung in ntdll (optional).
//
// Analyse- und Monitoring-Werkzeuge patchen haeufig die ersten Bytes von
// Nt*-Funktionen (Sprung auf ihren eigenen Handler). Diese Pruefung liest
// die ersten Bytes einiger ntdll-Exporte und meldet typische Hook-Muster.
//
// ACHTUNG: Viele Antiviren-/EDR-Produkte patchen ntdll ebenfalls - das ist
// kein Angriff. Deshalb ist der Check standardmaessig AUS und niedrig
// gewichtet. Fuer Umgebungen, in denen AV/EDR ausgeschlossen ist, lohnt er.

#include "aegis/detect.hpp"

#include "aegis/crypto/xorstr.hpp"
#include "platform/platform.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace aegis::detect {

#if defined(_WIN32)
namespace {

bool looks_hooked(const std::uint8_t* code) noexcept {
    if (code[0] == 0xE9) return true;              // jmp rel32
    if (code[0] == 0xEB) return true;              // jmp rel8
    if (code[0] == 0xCC) return true;              // int3
    if (code[0] == 0xC3) return true;              // ret (Stub ersetzt)
    if (code[0] == 0x68) return true;              // push imm32; ret
    if (code[0] == 0xFF && code[1] == 0x25) return true;  // jmp [rip+disp]
    if (code[0] == 0x48 && code[1] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) return true;
    return false;
}

}  // namespace
#endif

void api_hooks(const Config& config, Findings& out) {
    if (!config.check_api_hooks) return;

#if defined(_WIN32)
    struct Probe {
        const wchar_t* module_name;
        const char* function_name;
    };
    static const Probe kProbes[] = {
        {L"ntdll.dll", "NtQueryInformationProcess"},
        {L"ntdll.dll", "NtQuerySystemInformation"},
        {L"ntdll.dll", "NtQueryVirtualMemory"},
        {L"ntdll.dll", "NtReadVirtualMemory"},
        {L"ntdll.dll", "NtProtectVirtualMemory"},
        {L"ntdll.dll", "LdrLoadDll"},
        {L"ntdll.dll", "LdrGetProcedureAddress"},
        {L"ntdll.dll", "NtClose"},
    };

    std::string hooked;
    for (const Probe& probe : kProbes) {
        HMODULE module = ::GetModuleHandleW(probe.module_name);
        if (module == nullptr) continue;
        const auto* function =
            reinterpret_cast<const std::uint8_t*>(::GetProcAddress(module, probe.function_name));
        if (function == nullptr) continue;
        if (!looks_hooked(function)) continue;

        if (!hooked.empty()) hooked += ", ";
        hooked += probe.function_name;
    }

    if (!hooked.empty()) {
        add(out, true, "integrity.inline_hook", Category::Integrity, Severity::Medium, 26,
            "Inline-Hook in: " + hooked + " (AV/EDR oder Analyse-Werkzeug)");
    }

    // Manipulierte Import-Adressen: zeigt ein IAT-Eintrag aus dem Heap/Stack?
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (kernel32 != nullptr && ntdll != nullptr) {
        const auto* entry = reinterpret_cast<const std::uint8_t*>(
            ::GetProcAddress(kernel32, "CreateToolhelp32Snapshot"));
        if (entry != nullptr) {
            // Thunk liegt in kernel32; ein Sprung aus dem Heap ist ein Hinweis.
            const auto* image_base = reinterpret_cast<const std::uint8_t*>(kernel32);
            if (entry < image_base) {
                add(out, true, "integrity.kernel32_thunk", Category::Integrity, Severity::Low, 10,
                    "kernel32-Export liegt ausserhalb des Abbilds");
            }
        }
    }
#else
    // Unter Linux uebernimmt diese Rolle LD_PRELOAD/plthook - geprueft in
    // detect::debugger() und detect::injected_modules().
    (void)out;
#endif
}

}  // namespace aegis::detect
