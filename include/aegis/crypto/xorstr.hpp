// SPDX-License-Identifier: MIT
// AEGIS Guard - Anti-Analyse-Modul
//
// xorstr.hpp - Compile-Zeit-verschluesselte String-Literale.
//
// Motivation: Signaturen von Analyse-Werkzeugen suchen im Binary nach
// Klartext-Artefakten ("VBoxService", "frida", "SBieDll", ...). Mit
// AEGIS_STR(...) liegen diese Literale nur als Chiffrat im .rdata vor.
//
// Eigenschaften:
//   * Verschluesselung passiert vollstaendig im Compiler (constexpr).
//   * Der Schluessel ist pro Literal verschieden (__LINE__ / __COUNTER__),
//     zusaetzlich existiert ein Build-Seed.
//   * Vergleiche (equals_ci / contains_ci) entschluesseln byteweise in ein
//     Register - es existiert zu keinem Zeitpunkt ein vollstaendiger
//     Klartext-String auf dem Stack oder Heap.
//   * Dekodierung ist noinline + volatile-barriere, damit der Optimierer
//     den Vergleich nicht zu einem Klartext-Vergleich zusammenfaltet.
//
// WICHTIG: Das ist Verschleierung, keine Kryptographie gegen einen Angreifer,
// der den Schluessel aus dem Binary extrahiert. Es erhoeht den Aufwand
// (statische Signaturen greifen nicht mehr), mehr nicht.

#ifndef AEGIS_CRYPTO_XORSTR_HPP
#define AEGIS_CRYPTO_XORSTR_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "aegis/crypto/fnv.hpp"

// Verhindert, dass der Optimierer den Wert kennt: ohne diese Barriere kann
// GCC/MSVC den gesamten Entschluesselungsausdruck zur Compile-Zeit falten und
// das Chiffrat durch den Klartext ersetzen (IPA-Konstantenpropagierung).
#if defined(_MSC_VER)
#include <intrin.h>
#define AEGIS_NOINLINE __declspec(noinline)
#define AEGIS_NOIPA
#define AEGIS_BARRIER(value) \
    ::_ReadWriteBarrier();   \
    (void)(value)
#else
#define AEGIS_NOINLINE __attribute__((noinline))
#if defined(__GNUC__) && (__GNUC__ >= 9)
#define AEGIS_NOIPA __attribute__((noipa))
#else
#define AEGIS_NOIPA
#endif
#define AEGIS_BARRIER(value) __asm__ __volatile__("" : "+r"(value))
#endif

// Sicherheitsnetz fuer unbekannte Compiler (z. B. clang-cl ohne __GNUC__).
#ifndef AEGIS_NOIPA
#define AEGIS_NOIPA
#endif

#ifndef AEGIS_LITERAL_KEY
#define AEGIS_LITERAL_KEY 0x9E3779B97F4A7C15ULL
#endif

namespace aegis::crypto {

/// Ueberschreibt einen Speicherbereich "sicher" (der Compiler darf die
/// Schleife nicht wegoptimieren).
inline void secure_zero(void* data, std::size_t size) noexcept {
    volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *p++ = 0;
}

/// Dekodiert EIN Byte. Implementiert in einer eigenen Uebersetzungseinheit
/// (src/crypto/xorstr_runtime.cpp), damit der Optimierer Chiffrat und
/// Schluessel nicht ueber Dateigrenzen hinweg falten kann. Ohne diesen Kniff
/// ersetzt GCC bei -O3 Teile des Chiffrats durch den Klartext.
char decrypt_byte(const std::uint8_t* cipher, std::uint64_t key, std::size_t index) noexcept;

constexpr std::uint8_t literal_byte_key(std::uint64_t key, std::size_t index) noexcept {
    return static_cast<std::uint8_t>(
        splitmix64(key ^ (static_cast<std::uint64_t>(index) * 0x2545F4914F6CDD1DULL)) >> 24);
}

/// Pro Verwendungsstelle unterschiedlicher Startschluessel.
constexpr std::uint64_t literal_seed(unsigned line, unsigned counter) noexcept {
    const std::uint64_t mixed = splitmix64(static_cast<std::uint64_t>(AEGIS_LITERAL_KEY) ^
                                           (static_cast<std::uint64_t>(line) << 32) ^
                                           static_cast<std::uint64_t>(counter));
    return mixed | 1ULL;  // niemals 0
}

/// Compile-Zeit verschluesseltes Literal. Wird als Temporary erzeugt:
///
///     if (AEGIS_STR("vmware-vmx").equals_ci(name)) { ... }
template <std::size_t N>
class EncryptedLiteral {
public:
    static_assert(N >= 2, "EncryptedLiteral erwartet ein String-Literal");

    constexpr EncryptedLiteral(const char (&text)[N], std::uint64_t key) noexcept
        : key_(key ^ 0xA5A5A5A5A5A5A5A5ULL) {
        std::uint64_t k = key_ ^ 0xA5A5A5A5A5A5A5A5ULL;
        for (std::size_t i = 0; i < N; ++i) {
            data_[i] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(text[i]) ^
                                                 literal_byte_key(k, i));
        }
    }

    constexpr std::size_t size() const noexcept { return N - 1; }  // ohne NUL

    char decode(std::size_t index) const noexcept {
        return decrypt_byte(data_, key_ ^ 0xA5A5A5A5A5A5A5A5ULL, index);
    }

    /// Byteweiser, case-insensitiver Vergleich ohne Klartextpuffer.
    AEGIS_NOINLINE bool equals_ci(const char* other) const noexcept {
        if (other == nullptr) return false;
        for (std::size_t i = 0; i < N; ++i) {
            const char a = decode(i);
            const char b = other[i];
            if (ascii_lower(a) != ascii_lower(b)) return false;
            if (a == '\0') return true;
        }
        return false;
    }

    AEGIS_NOINLINE bool equals_ci(std::string_view other) const noexcept {
        if (other.size() != size()) return false;
        for (std::size_t i = 0; i < size(); ++i) {
            if (ascii_lower(decode(i)) != ascii_lower(other[i])) return false;
        }
        return true;
    }

    AEGIS_NOINLINE bool equals(const char* other) const noexcept {
        if (other == nullptr) return false;
        for (std::size_t i = 0; i < N; ++i) {
            const char a = decode(i);
            if (a != other[i]) return false;
            if (a == '\0') return true;
        }
        return false;
    }

    /// Substring-Suche (case-insensitiv) im Klartext-Puffer `haystack`.
    /// Das Nadel-Literal selbst bleibt dabei verschluesselt.
    AEGIS_NOINLINE bool contains_ci(const char* haystack, std::size_t haystack_len) const noexcept {
        if (haystack == nullptr || haystack_len < size()) return false;
        const std::size_t needle_len = size();
        const std::size_t last = haystack_len - needle_len;
        for (std::size_t start = 0; start <= last; ++start) {
            std::size_t i = 0;
            for (; i < needle_len; ++i) {
                if (ascii_lower(decode(i)) != ascii_lower(haystack[start + i])) break;
            }
            if (i == needle_len) return true;
        }
        return false;
    }

    /// Prueft, ob das entschluesselte Literal im Nullterminierten String steckt.
    AEGIS_NOINLINE bool contained_in_ci(const char* haystack) const noexcept {
        if (haystack == nullptr) return false;
        std::size_t len = 0;
        while (haystack[len] != '\0') ++len;
        return contains_ci(haystack, len);
    }

    /// Entschluesselt in einen Aufrufer-Puffer (Groesse >= N). Der Aufrufer
    /// ist dafuer verantwortlich, den Puffer danach zu nullen.
    void copy_to(char* out) const noexcept {
        for (std::size_t i = 0; i < N; ++i) out[i] = decode(i);
    }

    /// Bequemer, aber unsicherer Weg (Heap-Kopie). Nur fuer Logging/Tests.
    std::string to_string() const {
        char buffer[N];
        copy_to(buffer);
        std::string result(buffer, N - 1);
        secure_zero(buffer, sizeof(buffer));
        return result;
    }

    /// Liefert den Klartext-Hash (ohne Klartext zu materialisieren).
    std::uint64_t to_hash() const noexcept {
        std::uint64_t h = kFnvOffsetBasis;
        for (std::size_t i = 0; i + 1 < N; ++i) {
            h ^= static_cast<std::uint8_t>(ascii_lower(decode(i)));
            h *= kFnvPrime;
        }
        return h;
    }

private:
    std::uint8_t data_[N];
    std::uint64_t key_;
};

}  // namespace aegis::crypto

/// Verschluesseltes String-Literal. `lit` MUSS ein Literal sein.
#define AEGIS_STR(lit)                                                                       \
    (::aegis::crypto::EncryptedLiteral<sizeof(lit)>(                                         \
        lit, ::aegis::crypto::literal_seed(__LINE__, __COUNTER__)))

#endif  // AEGIS_CRYPTO_XORSTR_HPP
