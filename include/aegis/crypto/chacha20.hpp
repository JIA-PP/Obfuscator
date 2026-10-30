// SPDX-License-Identifier: MIT
// AEGIS Guard - ChaCha20 (RFC 8439) und AEAD-Konstruktion (Encrypt-then-MAC).

#ifndef AEGIS_CRYPTO_CHACHA20_HPP
#define AEGIS_CRYPTO_CHACHA20_HPP

#include <cstddef>
#include <cstdint>

namespace aegis::crypto {

inline constexpr std::size_t kChaCha20KeySize = 32;
inline constexpr std::size_t kChaCha20NonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;

/// Erzeugt einen 64-Byte-Keystream-Block.
void chacha20_block(const std::uint8_t key[kChaCha20KeySize],
                    const std::uint8_t nonce[kChaCha20NonceSize],
                    std::uint32_t counter,
                    std::uint8_t out[64]) noexcept;

/// XORt `size` Bytes in-place (Ver- und Entschluesselung sind identisch).
void chacha20_xor(std::uint8_t* data, std::size_t size,
                  const std::uint8_t key[kChaCha20KeySize],
                  const std::uint8_t nonce[kChaCha20NonceSize],
                  std::uint32_t counter = 0) noexcept;

struct AeadResult {
    bool ok = false;
};

/// Versiegelt `plaintext` (Groesse `size`) nach `ciphertext` (gleiche Groesse)
/// und schreibt den 16-Byte-Tag. `associated` darf nullptr sein.
void aead_seal(const std::uint8_t key[kChaCha20KeySize],
               const std::uint8_t nonce[kChaCha20NonceSize],
               const std::uint8_t* associated, std::size_t associated_size,
               const std::uint8_t* plaintext, std::size_t size,
               std::uint8_t* ciphertext,
               std::uint8_t tag[kAeadTagSize]) noexcept;

/// Prueft den Tag und entschluesselt nach `plaintext`.
/// Bei manipulierten Daten wird false zurueckgegeben (und `plaintext` genullt).
bool aead_open(const std::uint8_t key[kChaCha20KeySize],
               const std::uint8_t nonce[kChaCha20NonceSize],
               const std::uint8_t* associated, std::size_t associated_size,
               const std::uint8_t* ciphertext, std::size_t size,
               const std::uint8_t tag[kAeadTagSize],
               std::uint8_t* plaintext) noexcept;

}  // namespace aegis::crypto

#endif  // AEGIS_CRYPTO_CHACHA20_HPP
