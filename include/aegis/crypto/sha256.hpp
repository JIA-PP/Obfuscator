// SPDX-License-Identifier: MIT
// AEGIS Guard - SHA-256 + HMAC-SHA-256 (FIPS 180-4 / RFC 2104).
//
// Wird fuer die Integritaetspruefung verschluesselter Konfigurationsblobs
// (Encrypt-then-MAC) sowie fuer Selbst-Integritaets-Checks verwendet.

#ifndef AEGIS_CRYPTO_SHA256_HPP
#define AEGIS_CRYPTO_SHA256_HPP

#include <cstddef>
#include <cstdint>

namespace aegis::crypto {

inline constexpr std::size_t kSha256DigestSize = 32;

class Sha256 {
public:
    Sha256() noexcept;
    void update(const void* data, std::size_t size) noexcept;
    void final(std::uint8_t out[kSha256DigestSize]) noexcept;

    static void hash(const void* data, std::size_t size,
                     std::uint8_t out[kSha256DigestSize]) noexcept;

private:
    void compress(const std::uint8_t block[64]) noexcept;

    std::uint32_t state_[8];
    std::uint64_t bit_length_;
    std::uint8_t buffer_[64];
    std::size_t buffer_size_;
};

void hmac_sha256(const std::uint8_t* key, std::size_t key_size,
                 const std::uint8_t* message, std::size_t message_size,
                 std::uint8_t out[kSha256DigestSize]) noexcept;

/// Konstante-Zeit-Vergleich (kein early exit).
bool constant_time_equal(const void* a, const void* b, std::size_t size) noexcept;

}  // namespace aegis::crypto

#endif  // AEGIS_CRYPTO_SHA256_HPP
