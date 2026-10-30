// SPDX-License-Identifier: MIT
// AEGIS Guard - interne Datentabellen
//
// Die Tabellen werden von tools/aegis_tool.py aus tools/data/blacklist.json
// erzeugt (Datei: tables_generated.inc). Sie enthalten KEINEN Klartext:
//   * Namenslisten liegen als maskierte FNV-1a-64-Hashes vor.
//   * Pfade/Registry-Schluessel/Titel liegen XOR-verschluesselt vor und
//     werden erst zur Laufzeit in einen fluechtigen Puffer entschluesselt.
//
// Die .inc-Datei ist generiert - nicht haendisch editieren.

#ifndef AEGIS_DATA_TABLES_HPP
#define AEGIS_DATA_TABLES_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace aegis::data {

enum class ToolCategory : std::uint8_t {
    Disassembler = 0,
    Debugger = 1,
    Decompiler = 2,
    DotnetDecompiler = 3,
    Instrumentation = 4,
    NetworkSniffer = 5,
    MemoryScanner = 6,
    PackerDetector = 7,
    PeTool = 8,
    HexEditor = 9,
    HypervisorTool = 10,
    RuntimeHook = 11,
    Unknown = 12,
};

const char* to_string(ToolCategory category) noexcept;

/// Gehashte Namensliste (Prozess-, Modul- oder Fensterklassenname).
struct NameEntry {
    std::uint64_t hash;
    ToolCategory category;
};

/// Verschluesseltes Text-Artefakt (Pfad, Registry-Schluessel, Titel ...).
struct TextEntry {
    const std::uint8_t* data;
    std::uint16_t size;
    std::uint64_t key;
};

struct TitleEntry {
    TextEntry text;
    ToolCategory category;
};

struct RegistryValueEntry {
    TextEntry key;
    TextEntry needle;
    TextEntry value_name;
};

struct MacEntry {
    std::uint8_t prefix[3];
};

/// Maximale Laenge eines entschluesselten Text-Artefakts (inkl. NUL).
inline constexpr std::size_t kMaxTextEntry = 512;

/// Entschluesselt ein TextEntry in einen lokalen Puffer und nullt ihn danach.
class DecodedText {
public:
    explicit DecodedText(const TextEntry& entry) noexcept;
    ~DecodedText();
    DecodedText(const DecodedText&) = delete;
    DecodedText& operator=(const DecodedText&) = delete;

    const char* c_str() const noexcept { return buffer_; }
    bool valid() const noexcept { return valid_; }
    std::string str() const;

private:
    char buffer_[kMaxTextEntry];
    bool valid_ = false;
};

const NameEntry* analysis_processes(std::size_t& count) noexcept;
const NameEntry* analysis_modules(std::size_t& count) noexcept;
const NameEntry* analysis_window_classes(std::size_t& count) noexcept;
const NameEntry* vm_processes(std::size_t& count) noexcept;
const NameEntry* vm_modules(std::size_t& count) noexcept;
const NameEntry* sandbox_modules(std::size_t& count) noexcept;

const TitleEntry* analysis_titles(std::size_t& count) noexcept;

const TextEntry* vm_files(std::size_t& count) noexcept;
const TextEntry* vm_registry_keys(std::size_t& count) noexcept;
const RegistryValueEntry* vm_registry_values(std::size_t& count) noexcept;
const MacEntry* vm_mac_prefixes(std::size_t& count) noexcept;

const TextEntry* sandbox_files(std::size_t& count) noexcept;
const TextEntry* sandbox_users(std::size_t& count) noexcept;
const TextEntry* sandbox_computers(std::size_t& count) noexcept;
const TextEntry* command_line_markers(std::size_t& count) noexcept;
const TextEntry* vm_identifiers(std::size_t& count) noexcept;
const TextEntry* hypervisor_vendor_strings(std::size_t& count) noexcept;
const TextEntry* cpu_brand_markers(std::size_t& count) noexcept;
const TextEntry* container_markers(std::size_t& count) noexcept;
const TextEntry* container_files(std::size_t& count) noexcept;
const TextEntry* tracer_names(std::size_t& count) noexcept;
const TextEntry* instrumentation_threads(std::size_t& count) noexcept;

/// Substring-Suche (case-insensitiv) ueber eine verschluesselte Text-Tabelle.
bool contains_fragment(const TextEntry* table, std::size_t count, const char* haystack) noexcept;
/// Exakter Vergleich (case-insensitiv) gegen eine verschluesselte Tabelle.
bool equals_any(const TextEntry* table, std::size_t count, const char* value) noexcept;
/// Substring-Suche, aber gegen eine ganze Liste (Tabelle der Nadeln).
bool contains_any(const TextEntry* table, std::size_t count, const char* haystack) noexcept;

// ---------------------------------------------------------------- Suche
//
/// Sucht einen normalisierten Namen (siehe crypto::normalize_name_hash) in
/// einer Tabelle. Liefert nullptr, wenn nichts passt.
const NameEntry* find_name(const NameEntry* table, std::size_t count,
                           std::uint64_t hash) noexcept;

/// Prueft einen Fenstertitel gegen die (verschluesselten) Titel-Muster.
const TitleEntry* match_title(const char* title) noexcept;

/// Prueft, ob ein Text-Artefakt in der Tabelle enthalten ist (case-insensitiv).
bool contains_text(const TextEntry* table, std::size_t count, const char* value) noexcept;

/// Index des Artefakts in der Tabelle oder (std::size_t)-1.
std::size_t index_of_text(const TextEntry* table, std::size_t count, const char* value) noexcept;

}  // namespace aegis::data

#endif  // AEGIS_DATA_TABLES_HPP
