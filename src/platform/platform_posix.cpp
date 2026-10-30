// SPDX-License-Identifier: MIT
// AEGIS Guard - Plattform-Implementierung (Linux / POSIX).

#include "platform/platform.hpp"

#if !defined(_WIN32)

#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>

namespace aegis::platform {
namespace {

std::string read_link(const char* path) {
    char buffer[4096];
    const ssize_t length = ::readlink(path, buffer, sizeof(buffer) - 1);
    if (length <= 0) return std::string();
    buffer[length] = '\0';
    return std::string(buffer);
}

bool is_numeric(const char* text) {
    if (text == nullptr || *text == '\0') return false;
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

std::string strip_newline(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    return value;
}

}  // namespace

std::vector<ProcessInfo> list_processes(bool with_cmdline) {
    std::vector<ProcessInfo> processes;
    DIR* dir = ::opendir("/proc");
    if (dir == nullptr) return processes;

    while (dirent* entry = ::readdir(dir)) {
        if (!is_numeric(entry->d_name)) continue;
        const std::string base = std::string("/proc/") + entry->d_name;

        ProcessInfo info;
        info.pid = std::strtoull(entry->d_name, nullptr, 10);
        info.name = strip_newline(read_file((base + "/comm").c_str(), 256));
        if (info.name.empty()) continue;

        if (with_cmdline) {
            const std::string raw = read_file((base + "/cmdline").c_str(), 8192);
            std::string cmd;
            cmd.reserve(raw.size());
            for (char c : raw) cmd.push_back(c == '\0' ? ' ' : c);
            info.cmdline = trim(cmd);
        }
        info.path = read_link((base + "/exe").c_str());
        processes.push_back(std::move(info));
    }
    ::closedir(dir);
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
    DIR* dir = ::opendir("/proc/self/task");
    if (dir == nullptr) return names;
    while (dirent* entry = ::readdir(dir)) {
        if (!is_numeric(entry->d_name)) continue;
        const std::string path = std::string("/proc/self/task/") + entry->d_name + "/comm";
        std::string name = strip_newline(read_file(path.c_str(), 256));
        if (!name.empty()) names.push_back(std::move(name));
    }
    ::closedir(dir);
    return names;
}

std::vector<std::string> list_own_modules() {
    std::vector<std::string> modules;
    const std::string maps = read_file("/proc/self/maps");
    std::size_t pos = 0;
    while (pos < maps.size()) {
        const std::size_t end = maps.find('\n', pos);
        const std::string line = maps.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        pos = (end == std::string::npos) ? maps.size() : end + 1;

        const std::size_t slash = line.find('/');
        if (slash == std::string::npos) continue;
        const std::string path = trim(line.substr(slash));
        if (path.empty() || path[0] != '/') continue;
        std::string base = to_lower(basename_of(path));
        // .so / .so.1 / .dylib entfernen
        for (const char* suffix : {".so", ".dylib"}) {
            const std::size_t at = base.find(suffix);
            if (at != std::string::npos) base = base.substr(0, at);
        }
        bool known = false;
        for (const std::string& existing : modules) {
            if (existing == base) {
                known = true;
                break;
            }
        }
        if (!known && !base.empty()) modules.push_back(std::move(base));
    }
    return modules;
}

std::string own_executable_path() { return read_link("/proc/self/exe"); }

bool file_exists(const char* path) noexcept {
    struct stat info {};
    return ::stat(path, &info) == 0 && S_ISREG(info.st_mode);
}

bool dir_exists(const char* path) noexcept {
    struct stat info {};
    return ::stat(path, &info) == 0 && S_ISDIR(info.st_mode);
}

std::string read_file(const char* path, std::size_t max_size) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::string();
    std::string content;
    content.resize(max_size);
    stream.read(&content[0], static_cast<std::streamsize>(max_size));
    content.resize(static_cast<std::size_t>(stream.gcount()));
    return content;
}

std::string username() {
    const char* user = ::getenv("USER");
    if (user == nullptr) user = ::getenv("LOGNAME");
    return user != nullptr ? std::string(user) : std::string();
}

std::string computername() {
    char buffer[256] = {};
    if (::gethostname(buffer, sizeof(buffer) - 1) != 0) return std::string();
    return std::string(buffer);
}

std::string domain_name() { return std::string(); }

bool get_mac_addresses(std::vector<std::array<std::uint8_t, 6>>& out) {
    DIR* dir = ::opendir("/sys/class/net");
    if (dir == nullptr) return false;
    bool any = false;
    while (dirent* entry = ::readdir(dir)) {
        if (entry->d_name[0] == '.') continue;
        const std::string path = std::string("/sys/class/net/") + entry->d_name + "/address";
        std::string text = trim(read_file(path.c_str(), 64));
        if (text.size() < 17) continue;
        std::array<std::uint8_t, 6> bytes{};
        bool ok = true;
        for (int i = 0; i < 6; ++i) {
            const std::string part = text.substr(static_cast<std::size_t>(i) * 3, 2);
            char* end = nullptr;
            const long value = std::strtol(part.c_str(), &end, 16);
            if (end == nullptr || value < 0 || value > 255) {
                ok = false;
                break;
            }
            bytes[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
        }
        if (ok) {
            out.push_back(bytes);
            any = true;
        }
    }
    ::closedir(dir);
    return any;
}

unsigned cpu_cores() noexcept {
    const long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
    return cores > 0 ? static_cast<unsigned>(cores) : 0;
}

unsigned long long ram_mb() noexcept {
    const long pages = ::sysconf(_SC_PHYS_PAGES);
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) return 0;
    return static_cast<unsigned long long>(pages) * static_cast<unsigned long long>(page_size) /
           (1024ull * 1024ull);
}

unsigned long long uptime_seconds() noexcept {
    const std::string text = read_file("/proc/uptime", 128);
    if (text.empty()) return 0;
    return static_cast<unsigned long long>(std::strtod(text.c_str(), nullptr));
}

unsigned long long disk_size_gb(const char* path) noexcept {
    struct statvfs info {};
    if (::statvfs(path != nullptr ? path : "/", &info) != 0) return 0;
    return static_cast<unsigned long long>(info.f_blocks) * info.f_frsize / (1024ull * 1024ull * 1024ull);
}

unsigned screen_width() noexcept { return 0; }
unsigned screen_height() noexcept { return 0; }

std::uint64_t monotonic_ms() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

void sleep_ms(unsigned milliseconds) noexcept {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

std::uint64_t last_input_ms() noexcept { return 0; }
unsigned mouse_buttons_down() noexcept { return 0; }
bool cursor_position(int& x, int& y) noexcept {
    (void)x;
    (void)y;
    return false;
}

unsigned long long process_count() noexcept {
    unsigned long long count = 0;
    DIR* dir = ::opendir("/proc");
    if (dir == nullptr) return 0;
    while (dirent* entry = ::readdir(dir)) {
        if (is_numeric(entry->d_name)) ++count;
    }
    ::closedir(dir);
    return count;
}

bool registry_key_exists(const char*) noexcept { return false; }
bool registry_value_contains(const char*, const char*, const char*) noexcept { return false; }
bool registry_subkey_prefix_exists(const char*, const char*) noexcept { return false; }

std::string smbios_strings() noexcept {
    static const char* kFields[] = {
        "/sys/class/dmi/id/sys_vendor",   "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_version", "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/board_name",   "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/bios_version", "/sys/class/dmi/id/chassis_vendor",
    };
    std::string combined;
    for (const char* field : kFields) {
        const std::string value = trim(read_file(field, 512));
        if (value.empty()) continue;
        combined += value;
        combined += '\n';
    }
    return combined;
}

std::string read_sysfs(const char* path) { return trim(read_file(path, 4096)); }
std::string proc_self_status() { return read_file("/proc/self/status", 64 * 1024); }
std::string proc_self_cgroup() { return read_file("/proc/self/cgroup", 16 * 1024); }
std::string cpuinfo() { return read_file("/proc/cpuinfo", 256 * 1024); }

}  // namespace aegis::platform

#endif  // !_WIN32
