// SPDX-License-Identifier: MIT
#include "aegis/crypto/chacha20.hpp"

#include <cstring>

#include "aegis/crypto/sha256.hpp"

namespace aegis::crypto {
namespace {

inline std::uint32_t rotl32(std::uint32_t x, int n) noexcept {
    return (x << n) | (x >> (32 - n));
}

inline std::uint32_t load_le32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void store_le32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

inline void quarter_round(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c,
                          std::uint32_t& d) noexcept {
    a += b;
    d ^= a;
    d = rotl32(d, 16);
    c += d;
    b ^= c;
    b = rotl32(b, 12);
    a += b;
    d ^= a;
    d = rotl32(d, 8);
    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

/// Leitet zwei getrennte Unterschluessel fuer Verschluesselung und MAC ab.
void derive_keys(const std::uint8_t key[kChaCha20KeySize],
                 std::uint8_t enc_key[kChaCha20KeySize],
                 std::uint8_t mac_key[32]) noexcept {
    static constexpr char kEncLabel[] = "aegis/aead/v1/enc";
    static constexpr char kMacLabel[] = "aegis/aead/v1/mac";

    std::uint8_t material[32 + sizeof(kEncLabel) - 1];
    std::memcpy(material, key, 32);
    std::memcpy(material + 32, kEncLabel, sizeof(kEncLabel) - 1);
    Sha256::hash(material, sizeof(material), enc_key);

    std::uint8_t material2[32 + sizeof(kMacLabel) - 1];
    std::memcpy(material2, key, 32);
    std::memcpy(material2 + 32, kMacLabel, sizeof(kMacLabel) - 1);
    Sha256::hash(material2, sizeof(material2), mac_key);

    volatile std::uint8_t* wipe = material;
    for (std::size_t i = 0; i < sizeof(material); ++i) wipe[i] = 0;
    wipe = material2;
    for (std::size_t i = 0; i < sizeof(material2); ++i) wipe[i] = 0;
}

/// MAC ueber (associated || nonce || ciphertext).
void compute_tag(const std::uint8_t mac_key[32],
                 const std::uint8_t nonce[kChaCha20NonceSize],
                 const std::uint8_t* associated, std::size_t associated_size,
                 const std::uint8_t* ciphertext, std::size_t size,
                 std::uint8_t tag[kAeadTagSize]) noexcept {
    Sha256 inner;
    inner.update(associated, associated_size);
    inner.update(nonce, kChaCha20NonceSize);
    inner.update(ciphertext, size);

    std::uint8_t digest[32];
    inner.final(digest);

    // HMAC-artige Verstaerkung: mac_key als HMAC-Schluessel ueber den Digest.
    std::uint8_t full[32];
    hmac_sha256(mac_key, 32, digest, sizeof(digest), full);
    std::memcpy(tag, full, kAeadTagSize);

    volatile std::uint8_t* wipe = digest;
    for (std::size_t i = 0; i < sizeof(digest); ++i) wipe[i] = 0;
    wipe = full;
    for (std::size_t i = 0; i < sizeof(full); ++i) wipe[i] = 0;
}

}  // namespace

void chacha20_block(const std::uint8_t key[kChaCha20KeySize],
                    const std::uint8_t nonce[kChaCha20NonceSize],
                    std::uint32_t counter,
                    std::uint8_t out[64]) noexcept {
    std::uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646Eu;
    state[2] = 0x79622D32u;
    state[3] = 0x6B206574u;
    for (std::size_t i = 0; i < 8; ++i) state[4 + i] = load_le32(key + i * 4);
    state[12] = counter;
    state[13] = load_le32(nonce + 0);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);

    std::uint32_t working[16];
    std::memcpy(working, state, sizeof(working));

    for (int round = 0; round < 10; ++round) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }

    for (std::size_t i = 0; i < 16; ++i) store_le32(out + i * 4, working[i] + state[i]);
}

void chacha20_xor(std::uint8_t* data, std::size_t size,
                  const std::uint8_t key[kChaCha20KeySize],
                  const std::uint8_t nonce[kChaCha20NonceSize],
                  std::uint32_t counter) noexcept {
    std::uint8_t stream[64];
    std::size_t offset = 0;
    while (offset < size) {
        chacha20_block(key, nonce, counter++, stream);
        const std::size_t chunk = (size - offset) < 64 ? (size - offset) : 64;
        for (std::size_t i = 0; i < chunk; ++i) data[offset + i] ^= stream[i];
        offset += chunk;
    }
    volatile std::uint8_t* wipe = stream;
    for (std::size_t i = 0; i < sizeof(stream); ++i) wipe[i] = 0;
}

void aead_seal(const std::uint8_t key[kChaCha20KeySize],
               const std::uint8_t nonce[kChaCha20NonceSize],
               const std::uint8_t* associated, std::size_t associated_size,
               const std::uint8_t* plaintext, std::size_t size,
               std::uint8_t* ciphertext,
               std::uint8_t tag[kAeadTagSize]) noexcept {
    std::uint8_t enc_key[32];
    std::uint8_t mac_key[32];
    derive_keys(key, enc_key, mac_key);

    if (size > 0) std::memcpy(ciphertext, plaintext, size);
    chacha20_xor(ciphertext, size, enc_key, nonce, 0);
    compute_tag(mac_key, nonce, associated, associated_size, ciphertext, size, tag);
}

bool aead_open(const std::uint8_t key[kChaCha20KeySize],
               const std::uint8_t nonce[kChaCha20NonceSize],
               const std::uint8_t* associated, std::size_t associated_size,
               const std::uint8_t* ciphertext, std::size_t size,
               const std::uint8_t tag[kAeadTagSize],
               std::uint8_t* plaintext) noexcept {
    std::uint8_t enc_key[32];
    std::uint8_t mac_key[32];
    derive_keys(key, enc_key, mac_key);

    std::uint8_t expected[kAeadTagSize];
    compute_tag(mac_key, nonce, associated, associated_size, ciphertext, size, expected);

    if (!constant_time_equal(expected, tag, kAeadTagSize)) {
        if (size > 0) std::memset(plaintext, 0, size);
        return false;
    }

    if (size > 0) std::memcpy(plaintext, ciphertext, size);
    chacha20_xor(plaintext, size, enc_key, nonce, 0);
    return true;
}

}  // namespace aegis::crypto
