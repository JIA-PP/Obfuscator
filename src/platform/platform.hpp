// SPDX-License-Identifier: MIT
// AEGIS Guard - Plattform-Abstraktion.
//
// Alle Betriebssystem-Abhaengigkeiten sind hier gekapselt. Die Detektoren
// arbeiten ausschliesslich gegen diese Schnittstelle, damit sie auf Windows
// und Linux identisch aussehen (und sich testen lassen).

#ifndef AEGIS_PLATFORM_HPP
#define AEGIS_PLATFORM_HPP

#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace aegis::platform {

// ---------------------------------------------------------------- Text-Helfer

inline char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

inline std::string to_lower(std::string_view text) {
    std::string out(text);
    for (char& c : out) c = lower(c);
    return out;
}

inline bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

inline bool icontains(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (lower(haystack[i + j]) != lower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Dateiname aus einem Pfad (Windows- und POSIX-Trenner).
inline std::string basename_of(std::string_view path) {
    std::size_t start = 0;
    for (std::size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '/' || path[i] == '\\') start = i + 1;
    }
    return std::string(path.substr(start));
}

inline std::string trim(std::string_view text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r' ||
                           text[begin] == '\n')) {
        ++begin;
    }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r' ||
                           text[end - 1] == '\n')) {
        --end;
    }
    return std::string(text.substr(begin, end - begin));
}

inline std::string format(const char* fmt, ...) {
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    return std::string(buffer);
}

// ---------------------------------------------------------------- Prozesse

struct ProcessInfo {
    std::uint64_t pid = 0;
    std::string name;     ///< z. B. "x64dbg.exe" (Dateiname)
    std::string path;     ///< voller Pfad, falls ermittelbar
    std::string cmdline;  ///< nur gefuellt, wenn with_cmdline == true
};

/// Liste laufender Prozesse. Fehler werden als leere Liste gemeldet.
std::vector<ProcessInfo> list_processes(bool with_cmdline);

/// Fuer die Werkzeugerkennung relevante, "generische" Host-Prozesse, deren
/// Kommandozeile auf eingebettete Analyse-Werkzeuge geprueft wird
/// (z. B. "python.exe -m angr", "java -jar ghidra.jar").
bool is_generic_host(std::string_view normalized_name) noexcept;

// ---------------------------------------------------------------- Eigenprozess

/// Namen aller Threads des eigenen Prozesses (Windows: GetThreadDescription).
/// Wird fuer die Frida-Erkennung genutzt ("gum-js-loop", "gmain", ...).
std::vector<std::string> list_own_thread_names();

/// Basenamen (klein, ohne Endung) der im eigenen Prozess geladenen Module.
std::vector<std::string> list_own_modules();

/// Pfad des eigenen Executables (leer, wenn nicht ermittelbar).
std::string own_executable_path();

// ---------------------------------------------------------------- Dateisystem

bool file_exists(const char* path) noexcept;
bool dir_exists(const char* path) noexcept;
/// Liest eine Datei vollstaendig (max. 8 MiB). Leerer String bei Fehler.
std::string read_file(const char* path, std::size_t max_size = 8u * 1024u * 1024u);

// ---------------------------------------------------------------- System

std::string username();
std::string computername();
std::string domain_name();

bool get_mac_addresses(std::vector<std::array<std::uint8_t, 6>>& out);

unsigned cpu_cores() noexcept;
unsigned long long ram_mb() noexcept;
unsigned long long uptime_seconds() noexcept;
unsigned long long disk_size_gb(const char* path) noexcept;
unsigned screen_width() noexcept;
unsigned screen_height() noexcept;

std::uint64_t monotonic_ms() noexcept;
void sleep_ms(unsigned milliseconds) noexcept;

/// Zeit seit dem letzten Benutzereingriff in Millisekunden (0 = unbekannt).
std::uint64_t last_input_ms() noexcept;
/// Anzahl der aktuell gedrueckten Maustasten (0 = keine).
unsigned mouse_buttons_down() noexcept;
/// Aktuelle Mausposition (x, y). false, wenn nicht verfuegbar.
bool cursor_position(int& x, int& y) noexcept;

/// Elemente in /proc bzw. Prozessanzahl - grobe Aktivitaetsmetrik.
unsigned long long process_count() noexcept;

// ---------------------------------------------------------------- Windows-spezifisch
// Auf anderen Plattformen liefern diese Funktionen false.

bool registry_key_exists(const char* path) noexcept;
bool registry_value_contains(const char* key, const char* value_name, const char* needle) noexcept;
bool registry_subkey_prefix_exists(const char* path, const char* prefix) noexcept;
/// Alle Strings der SMBIOS-Tabellen (Typ 0/1/2) zusammengefasst, leer bei Fehler.
std::string smbios_strings() noexcept;

// ---------------------------------------------------------------- Linux-spezifisch
// Auf anderen Plattformen leer.

std::string read_sysfs(const char* path);           ///< /sys/... als Text
std::string proc_self_status();                      ///< Inhalt von /proc/self/status
std::string proc_self_cgroup();                      ///< Inhalt von /proc/self/cgroup
std::string cpuinfo();                               ///< Inhalt von /proc/cpuinfo

}  // namespace aegis::platform

#endif  // AEGIS_PLATFORM_HPP
