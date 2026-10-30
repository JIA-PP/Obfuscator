// SPDX-License-Identifier: MIT
// AEGIS Guard - Plattform-Implementierung (Windows).

#include "platform/platform.hpp"

#if defined(_WIN32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0601  // Windows 7+
#endif

// Reihenfolge ist wichtig: winsock2 vor windows.h, sonst fehlen die
// Adapter-Strukturen aus iphlpapi.h.
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cctype>
#include <chrono>
#include <cstring>

#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

namespace aegis::platform {
namespace {

std::wstring widen(std::string_view text) {
    if (text.empty()) return std::wstring();
    const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &out[0], length);
    return out;
}

std::string narrow(const wchar_t* text, std::size_t length = static_cast<std::size_t>(-1)) {
    if (text == nullptr) return std::string();
    if (length == static_cast<std::size_t>(-1)) {
        length = 0;
        while (text[length] != L'\0') ++length;
    }
    if (length == 0) return std::string();
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length), nullptr, 0,
                                           nullptr, nullptr);
    if (size <= 0) return std::string();
    std::string out(static_cast<std::size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length), &out[0], size, nullptr, nullptr);
    return out;
}

/// NtQueryInformationProcess(ProcessCommandLineInformation) - Windows 8.1+
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct UnicodeStringView {
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

std::string query_command_line(HANDLE process) {
    static NtQueryInformationProcessFn query = []() -> NtQueryInformationProcessFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) return nullptr;
        return reinterpret_cast<NtQueryInformationProcessFn>(
            ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }();
    if (query == nullptr) return std::string();

    constexpr ULONG kProcessCommandLineInformation = 60;
    std::uint8_t buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ULONG returned = 0;
    const LONG status = query(process, kProcessCommandLineInformation, buffer,
                              static_cast<ULONG>(sizeof(buffer)), &returned);
    if (status < 0) return std::string();

    const auto* text = reinterpret_cast<const UnicodeStringView*>(buffer);
    if (text->buffer == nullptr || text->length == 0) return std::string();
    const std::size_t characters = text->length / sizeof(wchar_t);
    return narrow(text->buffer, characters);
}

struct RegPath {
    HKEY root = nullptr;
    std::wstring subkey;
};

bool split_reg_path(const std::string& path, RegPath& out) {
    struct Prefix {
        const char* text;
        HKEY key;
    };
    static const Prefix kPrefixes[] = {
        {"HKLM\\", HKEY_LOCAL_MACHINE},   {"HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE},
        {"HKCU\\", HKEY_CURRENT_USER},    {"HKEY_CURRENT_USER\\", HKEY_CURRENT_USER},
        {"HKCR\\", HKEY_CLASSES_ROOT},    {"HKEY_CLASSES_ROOT\\", HKEY_CLASSES_ROOT},
        {"HKU\\", HKEY_USERS},            {"HKEY_USERS\\", HKEY_USERS},
        {"HKCC\\", HKEY_CURRENT_CONFIG},  {"HKEY_CURRENT_CONFIG\\", HKEY_CURRENT_CONFIG},
    };
    for (const Prefix& prefix : kPrefixes) {
        const std::size_t length = std::strlen(prefix.text);
        if (path.size() > length && _strnicmp(path.c_str(), prefix.text, length) == 0) {
            out.root = prefix.key;
            out.subkey = widen(path.substr(length));
            return out.root != nullptr && !out.subkey.empty();
        }
    }
    return false;
}

std::size_t count_snapshot_processes() {
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::size_t count = 0;
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            ++count;
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return count;
}

}  // namespace

std::vector<ProcessInfo> list_processes(bool with_cmdline) {
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = narrow(entry.szExeFile);

            HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                           entry.th32ProcessID);
            if (process != nullptr) {
                wchar_t path[MAX_PATH * 2] = {};
                DWORD size = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
                if (::QueryFullProcessImageNameW(process, 0, path, &size)) {
                    info.path = narrow(path, size);
                }
                if (with_cmdline) info.cmdline = query_command_line(process);
                ::CloseHandle(process);
            }
            if (info.path.empty() && !info.name.empty()) info.path = info.name;
            if (!info.name.empty()) processes.push_back(std::move(info));
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return processes;
}

bool is_generic_host(std::string_view normalized_name) noexcept {
    static constexpr std::string_view kHosts[] = {
        "python", "python2", "python3", "python3.8", "python3.9", "python3.10",
        "python3.11", "python3.12", "python3.13", "py", "pythonw",
        "java", "javaw", "javaws", "node", "nodejs", "dotnet", "mono", "ruby",
        "perl", "pwsh", "powershell", "wine", "wine64", "wine-preloader",
        "wine64-preloader",
    };
    for (std::string_view host : kHosts) {
        if (normalized_name == host) return true;
    }
    return false;
}

std::vector<std::string> list_own_thread_names() {
    std::vector<std::string> names;

    using GetThreadDescriptionFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);
    static GetThreadDescriptionFn get_description = []() -> GetThreadDescriptionFn {
        HMODULE kernel = ::GetModuleHandleW(L"kernel32.dll");
        if (kernel == nullptr) return nullptr;
        return reinterpret_cast<GetThreadDescriptionFn>(
            ::GetProcAddress(kernel, "GetThreadDescription"));
    }();
    if (get_description == nullptr) return names;

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return names;

    const DWORD own_pid = ::GetCurrentProcessId();
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (::Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != own_pid) continue;
            HANDLE thread = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (thread == nullptr) continue;
            PWSTR description = nullptr;
            if (SUCCEEDED(get_description(thread, &description)) && description != nullptr) {
                names.push_back(narrow(description));
                ::LocalFree(description);
            }
            ::CloseHandle(thread);
        } while (::Thread32Next(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return names;
}

std::vector<std::string> list_own_modules() {
    std::vector<std::string> modules;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                  ::GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return modules;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Module32FirstW(snapshot, &entry)) {
        do {
            std::string name = to_lower(narrow(entry.szModule));
            const std::size_t dot = name.rfind(".dll");
            if (dot != std::string::npos) name = name.substr(0, dot);
            if (!name.empty()) modules.push_back(std::move(name));
        } while (::Module32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return modules;
}

std::string own_executable_path() {
    wchar_t path[MAX_PATH * 2] = {};
    const DWORD size = ::GetModuleFileNameW(nullptr, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
    if (size == 0) return std::string();
    return narrow(path, size);
}

bool file_exists(const char* path) noexcept {
    if (path == nullptr) return false;
    const DWORD attributes = ::GetFileAttributesW(widen(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool dir_exists(const char* path) noexcept {
    if (path == nullptr) return false;
    const DWORD attributes = ::GetFileAttributesW(widen(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::string read_file(const char* path, std::size_t max_size) {
    if (path == nullptr) return std::string();
    HANDLE file = ::CreateFileW(widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return std::string();

    std::string content;
    content.resize(max_size);
    DWORD read = 0;
    if (::ReadFile(file, &content[0], static_cast<DWORD>(max_size), &read, nullptr)) {
        content.resize(read);
    } else {
        content.clear();
    }
    ::CloseHandle(file);
    return content;
}

std::string username() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (!::GetUserNameW(buffer, &size)) return std::string();
    return narrow(buffer, size > 0 ? size - 1 : 0);
}

std::string computername() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (!::GetComputerNameW(buffer, &size)) return std::string();
    return narrow(buffer, size);
}

std::string domain_name() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (::GetComputerNameExW(ComputerNameDnsDomain, buffer, &size) && size > 0) {
        return narrow(buffer, size);
    }
    const char* env = ::getenv("USERDOMAIN");
    return env != nullptr ? std::string(env) : std::string();
}

bool get_mac_addresses(std::vector<std::array<std::uint8_t, 6>>& out) {
    ULONG size = 16 * 1024;
    std::vector<std::uint8_t> buffer(size);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG status = ::GetAdaptersAddresses(AF_UNSPEC,
                                          GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                              GAA_FLAG_SKIP_DNS_SERVER,
                                          nullptr, addresses, &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        status = ::GetAdaptersAddresses(AF_UNSPEC,
                                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                            GAA_FLAG_SKIP_DNS_SERVER,
                                        nullptr, addresses, &size);
    }
    if (status != NO_ERROR) return false;

    bool any = false;
    for (IP_ADAPTER_ADDRESSES* current = addresses; current != nullptr; current = current->Next) {
        if (current->PhysicalAddressLength != 6) continue;
        std::array<std::uint8_t, 6> mac{};
        std::memcpy(mac.data(), current->PhysicalAddress, 6);
        out.push_back(mac);
        any = true;
    }
    return any;
}

unsigned cpu_cores() noexcept {
    const DWORD cores = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (cores != 0) return static_cast<unsigned>(cores);
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    return static_cast<unsigned>(info.dwNumberOfProcessors);
}

unsigned long long ram_mb() noexcept {
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (!::GlobalMemoryStatusEx(&status)) return 0;
    return static_cast<unsigned long long>(status.ullTotalPhys / (1024ull * 1024ull));
}

unsigned long long uptime_seconds() noexcept { return ::GetTickCount64() / 1000ull; }

unsigned long long disk_size_gb(const char* path) noexcept {
    ULARGE_INTEGER free_bytes{};
    ULARGE_INTEGER total_bytes{};
    ULARGE_INTEGER total_free{};
    if (!::GetDiskFreeSpaceExW(widen(path != nullptr ? path : "C:\\").c_str(), &free_bytes,
                               &total_bytes, &total_free)) {
        return 0;
    }
    return total_bytes.QuadPart / (1024ull * 1024ull * 1024ull);
}

unsigned screen_width() noexcept { return static_cast<unsigned>(::GetSystemMetrics(SM_CXSCREEN)); }
unsigned screen_height() noexcept { return static_cast<unsigned>(::GetSystemMetrics(SM_CYSCREEN)); }

std::uint64_t monotonic_ms() noexcept { return ::GetTickCount64(); }

void sleep_ms(unsigned milliseconds) noexcept { ::Sleep(milliseconds); }

std::uint64_t last_input_ms() noexcept {
    LASTINPUTINFO info{};
    info.cbSize = sizeof(info);
    if (!::GetLastInputInfo(&info)) return 0;
    return ::GetTickCount64() - info.dwTime;
}

unsigned mouse_buttons_down() noexcept {
    unsigned count = 0;
    if (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) ++count;
    if (::GetAsyncKeyState(VK_RBUTTON) & 0x8000) ++count;
    if (::GetAsyncKeyState(VK_MBUTTON) & 0x8000) ++count;
    if (::GetAsyncKeyState(VK_XBUTTON1) & 0x8000) ++count;
    if (::GetAsyncKeyState(VK_XBUTTON2) & 0x8000) ++count;
    return count;
}

bool cursor_position(int& x, int& y) noexcept {
    POINT point{};
    if (!::GetCursorPos(&point)) return false;
    x = point.x;
    y = point.y;
    return true;
}

unsigned long long process_count() noexcept { return count_snapshot_processes(); }

bool registry_key_exists(const char* path) noexcept {
    RegPath parts;
    if (path == nullptr || !split_reg_path(path, parts)) return false;
    HKEY key = nullptr;
    const LONG status = ::RegOpenKeyExW(parts.root, parts.subkey.c_str(), 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) return false;
    ::RegCloseKey(key);
    return true;
}

bool registry_value_contains(const char* key_path, const char* value_name, const char* needle) noexcept {
    RegPath parts;
    if (key_path == nullptr || value_name == nullptr || needle == nullptr) return false;
    if (!split_reg_path(key_path, parts)) return false;

    HKEY key = nullptr;
    if (::RegOpenKeyExW(parts.root, parts.subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }

    std::uint8_t buffer[4096];
    DWORD size = static_cast<DWORD>(sizeof(buffer));
    DWORD type = 0;
    const LONG status = ::RegQueryValueExW(key, widen(value_name).c_str(), nullptr, &type, buffer, &size);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) return false;

    const std::string text = narrow(reinterpret_cast<const wchar_t*>(buffer), size / sizeof(wchar_t));
    return icontains(text, needle);
}

bool registry_subkey_prefix_exists(const char* path, const char* prefix) noexcept {
    RegPath parts;
    if (path == nullptr || prefix == nullptr) return false;
    if (!split_reg_path(path, parts)) return false;

    HKEY key = nullptr;
    if (::RegOpenKeyExW(parts.root, parts.subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }

    const std::wstring wanted = widen(prefix);
    bool found = false;
    wchar_t name[512];
    for (DWORD index = 0;; ++index) {
        DWORD length = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
        const LONG status = ::RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (status != ERROR_SUCCESS) break;
        if (length >= wanted.size() && _wcsnicmp(name, wanted.c_str(), wanted.size()) == 0) {
            found = true;
            break;
        }
    }
    ::RegCloseKey(key);
    return found;
}

std::string smbios_strings() noexcept {
    const DWORD provider = static_cast<DWORD>('RSMB');
    const UINT size = ::GetSystemFirmwareTable(provider, 0, nullptr, 0);
    if (size == 0) return std::string();

    std::vector<std::uint8_t> buffer(size);
    if (::GetSystemFirmwareTable(provider, 0, buffer.data(), size) != size) return std::string();

    // RawSMBIOSData: 8 Byte Header, danach die Struktur-Tabelle
    if (buffer.size() < 12) return std::string();
    DWORD table_length = 0;
    std::memcpy(&table_length, buffer.data() + 4, sizeof(table_length));
    const std::size_t table_begin = 8;
    const std::size_t table_end = (table_begin + table_length < buffer.size())
                                      ? table_begin + table_length
                                      : buffer.size();

    std::string combined;
    std::size_t offset = table_begin;
    while (offset + 4 <= table_end) {
        const std::uint8_t length = buffer[offset + 1];
        if (length < 4) break;
        std::size_t cursor = offset + length;
        // String-Bereich: bis zur doppelten NUL
        while (cursor + 1 < table_end &&
               !(buffer[cursor] == 0 && buffer[cursor + 1] == 0)) {
            const std::size_t start = cursor;
            while (cursor < table_end && buffer[cursor] != 0) ++cursor;
            if (cursor > start) {
                combined.append(reinterpret_cast<const char*>(&buffer[start]), cursor - start);
                combined.push_back('\n');
            }
            if (cursor < table_end) ++cursor;
        }
        offset = cursor + 2;
        if (offset <= table_begin) break;
    }
    return combined;
}

std::string read_sysfs(const char*) { return std::string(); }
std::string proc_self_status() { return std::string(); }
std::string proc_self_cgroup() { return std::string(); }
std::string cpuinfo() { return std::string(); }

}  // namespace aegis::platform

#endif  // _WIN32
