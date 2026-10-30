// SPDX-License-Identifier: MIT
// Laufzeit-Entschluesselung fuer AEGIS_STR-Literale.
//
// Bewusst in einer eigenen Uebersetzungseinheit: der Optimierer darf Chiffrat
// und Schluessel nicht sehen, sonst ersetzt er (GCC ab -O2/-O3, IPA-CP) die
// Entschluesselung durch einen Klartext-Vergleich und legt die Klartext-
// Strings ins Binary. `noipa` + volatile + Assembler-Barriere verhindern
// zusaetzlich jede Faltung innerhalb dieser Datei.

#include <cstddef>
#include <cstdint>

#include "aegis/crypto/xorstr.hpp"

namespace aegis::crypto {

AEGIS_NOINLINE AEGIS_NOIPA char decrypt_byte(const std::uint8_t* cipher, std::uint64_t key,
                                             std::size_t index) noexcept {
    // Assembler-Barriere: ab hier ist `key` fuer den Compiler unbekannt.
    AEGIS_BARRIER(key);

    volatile std::uint8_t stored = cipher[index];
    std::uint8_t value = stored;
    AEGIS_BARRIER(value);

    const std::uint8_t mask = literal_byte_key(key, index);
    volatile std::uint8_t mixed = static_cast<std::uint8_t>(value ^ mask);
    return static_cast<char>(mixed);
}

}  // namespace aegis::crypto
