// SPDX-License-Identifier: MIT
#include "aegis/crypto/sha256.hpp"

#include <cstring>

namespace aegis::crypto {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr std::uint32_t kInitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32u - n));
}

inline std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

}  // namespace

Sha256::Sha256() noexcept : bit_length_(0), buffer_size_(0) {
    std::memcpy(state_, kInitialState, sizeof(state_));
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) noexcept {
    if (size == 0) return;
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    bit_length_ += static_cast<std::uint64_t>(size) * 8u;

    while (size > 0) {
        const std::size_t free_space = 64 - buffer_size_;
        const std::size_t take = size < free_space ? size : free_space;
        std::memcpy(buffer_ + buffer_size_, bytes, take);
        buffer_size_ += take;
        bytes += take;
        size -= take;
        if (buffer_size_ == 64) {
            compress(buffer_);
            buffer_size_ = 0;
        }
    }
}

void Sha256::final(std::uint8_t out[kSha256DigestSize]) noexcept {
    const std::uint64_t bit_length = bit_length_;

    const std::uint8_t pad = 0x80;
    update(&pad, 1);
    const std::uint8_t zero = 0x00;
    while (buffer_size_ != 56) update(&zero, 1);

    std::uint8_t length_bytes[8];
    for (std::size_t i = 0; i < 8; ++i) {
        length_bytes[i] = static_cast<std::uint8_t>(bit_length >> (56 - 8 * i));
    }
    // update() wuerde bit_length_ erneut erhoehen; das ist nach dem Merken egal.
    std::memcpy(buffer_ + buffer_size_, length_bytes, 8);
    compress(buffer_);
    buffer_size_ = 0;

    for (std::size_t i = 0; i < 8; ++i) store_be32(out + i * 4, state_[i]);
}

void Sha256::hash(const void* data, std::size_t size,
                  std::uint8_t out[kSha256DigestSize]) noexcept {
    Sha256 ctx;
    ctx.update(data, size);
    ctx.final(out);
}

void hmac_sha256(const std::uint8_t* key, std::size_t key_size,
                 const std::uint8_t* message, std::size_t message_size,
                 std::uint8_t out[kSha256DigestSize]) noexcept {
    std::uint8_t block[64];
    std::memset(block, 0, sizeof(block));
    if (key_size > 64) {
        Sha256::hash(key, key_size, block);  // nur die ersten 32 Bytes sind belegt
    } else if (key_size > 0) {
        std::memcpy(block, key, key_size);
    }

    std::uint8_t inner[64];
    std::uint8_t outer[64];
    for (std::size_t i = 0; i < 64; ++i) {
        inner[i] = static_cast<std::uint8_t>(block[i] ^ 0x36);
        outer[i] = static_cast<std::uint8_t>(block[i] ^ 0x5C);
    }

    std::uint8_t inner_digest[kSha256DigestSize];
    {
        Sha256 ctx;
        ctx.update(inner, sizeof(inner));
        ctx.update(message, message_size);
        ctx.final(inner_digest);
    }

    Sha256 ctx;
    ctx.update(outer, sizeof(outer));
    ctx.update(inner_digest, sizeof(inner_digest));
    ctx.final(out);

    volatile std::uint8_t* wipe = block;
    for (std::size_t i = 0; i < sizeof(block); ++i) wipe[i] = 0;
    wipe = inner_digest;
    for (std::size_t i = 0; i < sizeof(inner_digest); ++i) wipe[i] = 0;
}

bool constant_time_equal(const void* a, const void* b, std::size_t size) noexcept {
    const auto* pa = static_cast<const std::uint8_t*>(a);
    const auto* pb = static_cast<const std::uint8_t*>(b);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < size; ++i) diff = static_cast<std::uint8_t>(diff | (pa[i] ^ pb[i]));
    return diff == 0;
}

}  // namespace aegis::crypto
