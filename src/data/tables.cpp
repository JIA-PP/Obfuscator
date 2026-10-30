// SPDX-License-Identifier: MIT
#include "data/tables.hpp"

#include <cstring>

#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/xorstr.hpp"

namespace aegis::data {

/// Muss mit tools/aegis_tool.py (HASH_MASK_KEY) uebereinstimmen.
constexpr std::uint64_t kHashMaskKey = 0x9E3779B97F4A7C15ULL;

namespace {

inline std::uint64_t unmask(std::uint64_t value, std::size_t index) noexcept {
    return value ^ crypto::splitmix64(kHashMaskKey + static_cast<std::uint64_t>(index));
}

bool platform_icontains(const char* haystack, const char* needle) noexcept {
    if (haystack == nullptr || needle == nullptr) return false;
    for (; *haystack != '\0'; ++haystack) {
        const char* h = haystack;
        const char* n = needle;
        while (*h != '\0' && *n != '\0' && crypto::ascii_lower(*h) == crypto::ascii_lower(*n)) {
            ++h;
            ++n;
        }
        if (*n == '\0') return true;
    }
    return *needle == '\0';
}

}  // namespace

const char* to_string(ToolCategory category) noexcept {
    switch (category) {
        case ToolCategory::Disassembler: return "Disassembler";
        case ToolCategory::Debugger: return "Debugger";
        case ToolCategory::Decompiler: return "Decompiler";
        case ToolCategory::DotnetDecompiler: return ".NET-Decompiler";
        case ToolCategory::Instrumentation: return "Instrumentierung";
        case ToolCategory::NetworkSniffer: return "Netzwerk-Sniffer";
        case ToolCategory::MemoryScanner: return "Memory-Scanner";
        case ToolCategory::PackerDetector: return "Packer-Detektor";
        case ToolCategory::PeTool: return "PE-Werkzeug";
        case ToolCategory::HexEditor: return "Hex-Editor";
        case ToolCategory::HypervisorTool: return "Hypervisor-Werkzeug";
        case ToolCategory::RuntimeHook: return "Runtime-Hook";
        default: return "Unbekannt";
    }
}

DecodedText::DecodedText(const TextEntry& entry) noexcept {
    buffer_[0] = '\0';
    if (entry.data == nullptr || entry.size == 0 || entry.size >= kMaxTextEntry) return;
    for (std::size_t i = 0; i < entry.size; ++i) {
        const std::uint8_t key = crypto::literal_byte_key(entry.key, i);
        buffer_[i] = static_cast<char>(entry.data[i] ^ key);
    }
    buffer_[entry.size] = '\0';
    valid_ = true;
}

DecodedText::~DecodedText() { crypto::secure_zero(buffer_, sizeof(buffer_)); }

std::string DecodedText::str() const { return valid_ ? std::string(buffer_) : std::string(); }

const NameEntry* find_name(const NameEntry* table, std::size_t count,
                           std::uint64_t hash) noexcept {
    if (table == nullptr) return nullptr;
    for (std::size_t i = 0; i < count; ++i) {
        if (unmask(table[i].hash, i) == hash) return &table[i];
    }
    return nullptr;
}

const TitleEntry* match_title(const char* title) noexcept {
    if (title == nullptr) return nullptr;
    std::size_t count = 0;
    const TitleEntry* table = analysis_titles(count);
    for (std::size_t i = 0; i < count; ++i) {
        const DecodedText pattern(table[i].text);
        if (!pattern.valid()) continue;
        // Substring-Suche, case-insensitiv
        const char* hay = title;
        const char* needle = pattern.c_str();
        if (*needle == '\0') continue;
        for (; *hay != '\0'; ++hay) {
            const char* h = hay;
            const char* n = needle;
            while (*n != '\0' && *h != '\0' && crypto::ascii_lower(*h) == crypto::ascii_lower(*n)) {
                ++h;
                ++n;
            }
            if (*n == '\0') return &table[i];
        }
    }
    return nullptr;
}

std::size_t index_of_text(const TextEntry* table, std::size_t count, const char* value) noexcept {
    if (table == nullptr || value == nullptr) return static_cast<std::size_t>(-1);
    for (std::size_t i = 0; i < count; ++i) {
        const DecodedText entry(table[i]);
        if (!entry.valid()) continue;
        if (crypto::ascii_iequal(entry.c_str(), value)) return i;
    }
    return static_cast<std::size_t>(-1);
}

bool contains_text(const TextEntry* table, std::size_t count, const char* value) noexcept {
    return index_of_text(table, count, value) != static_cast<std::size_t>(-1);
}

bool contains_fragment(const TextEntry* table, std::size_t count, const char* haystack) noexcept {
    if (table == nullptr || haystack == nullptr) return false;
    for (std::size_t i = 0; i < count; ++i) {
        const DecodedText needle(table[i]);
        if (needle.valid() && platform_icontains(haystack, needle.c_str())) return true;
    }
    return false;
}

bool equals_any(const TextEntry* table, std::size_t count, const char* value) noexcept {
    return contains_text(table, count, value);
}

bool contains_any(const TextEntry* table, std::size_t count, const char* haystack) noexcept {
    return contains_fragment(table, count, haystack);
}

// Die generierten Tabellen + Zugriffsfunktionen.
#include "data/tables_generated.inc"

}  // namespace aegis::data
