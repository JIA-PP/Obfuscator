// SPDX-License-Identifier: MIT
// AEGIS Guard - Anti-Analyse-Modul
//
// fnv.hpp - Hash-Primitive (FNV-1a 64) und SplitMix64.
//
// Die Hash-Funktionen laufen zur Compile-Zeit und zur Laufzeit identisch,
// damit Blacklist-Eintraege als Hash-Tabelle ausgeliefert werden koennen,
// ohne dass Klartext-Namen im Binary landen.

#ifndef AEGIS_CRYPTO_FNV_HPP
#define AEGIS_CRYPTO_FNV_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace aegis::crypto {

inline constexpr std::uint64_t kFnvOffsetBasis = 0xCBF29CE484222325ULL;
inline constexpr std::uint64_t kFnvPrime = 0x100000001B3ULL;

/// FNV-1a 64 ueber rohe Bytes.
constexpr std::uint64_t fnv1a64(const char* data, std::size_t size) noexcept {
    std::uint64_t h = kFnvOffsetBasis;
    for (std::size_t i = 0; i < size; ++i) {
        h ^= static_cast<std::uint8_t>(data[i]);
        h *= kFnvPrime;
    }
    return h;
}

constexpr std::uint64_t fnv1a64(std::string_view s) noexcept {
    return fnv1a64(s.data(), s.size());
}

constexpr char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr bool ascii_iequal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    }
    return true;
}

/// Normalisierung fuer Namensvergleiche:
///  - Kleinschreibung
///  - Pfadanteile entfernen (alles bis zum letzten '/' oder '\\')
///  - bekannte Endungen entfernen (".exe", ".bin", ".dll", ".so", ".app", ".py")
///  - alles ab dem ersten '#' oder ':' abschneiden (z. B. "x64dbg.exe#1")
///
/// Das Ergebnis wird gehasht, damit die Vergleichsliste kompakt bleibt.
constexpr std::size_t normalized_length(std::string_view raw) noexcept {
    // Dateinamen-Anteil bestimmen
    std::size_t begin = 0;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '/' || raw[i] == '\\') begin = i + 1;
    }
    std::size_t end = raw.size();
    for (std::size_t i = begin; i < raw.size(); ++i) {
        if (raw[i] == '#' || raw[i] == ':') {
            end = i;
            break;
        }
    }
    return end > begin ? end - begin : 0;
}

constexpr std::string_view strip_known_extension(std::string_view name) noexcept {
    struct Ext {
        std::string_view text;
    };
    constexpr std::string_view kExts[] = {".exe", ".bin", ".dll", ".so", ".app", ".py", ".jar", ".bat", ".cmd"};
    for (std::string_view ext : kExts) {
        if (name.size() > ext.size()) {
            const std::size_t off = name.size() - ext.size();
            bool match = true;
            for (std::size_t i = 0; i < ext.size(); ++i) {
                if (ascii_lower(name[off + i]) != ext[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return name.substr(0, off);
        }
    }
    return name;
}

/// Liefert den normalisierten (gehashten) Namen, wie ihn die Blacklist-Tabelle
/// erwartet. Gleiche Funktion existiert in tools/aegis_tool.py.
constexpr std::uint64_t normalize_name_hash(std::string_view raw) noexcept {
    const std::size_t begin_off = [&] {
        std::size_t b = 0;
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '/' || raw[i] == '\\') b = i + 1;
        }
        return b;
    }();

    std::size_t end = raw.size();
    for (std::size_t i = begin_off; i < raw.size(); ++i) {
        if (raw[i] == '#' || raw[i] == ':') {
            end = i;
            break;
        }
    }
    if (end <= begin_off) return fnv1a64("");

    std::string_view name = raw.substr(begin_off, end - begin_off);
    name = strip_known_extension(name);

    std::uint64_t h = kFnvOffsetBasis;
    for (char c : name) {
        h ^= static_cast<std::uint8_t>(ascii_lower(c));
        h *= kFnvPrime;
    }
    return h;
}

/// SplitMix64 - schneller, gut verteilter Bit-Mixer.
constexpr std::uint64_t splitmix64(std::uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

}  // namespace aegis::crypto

#endif  // AEGIS_CRYPTO_FNV_HPP
