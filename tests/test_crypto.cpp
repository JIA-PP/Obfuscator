// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cstring>
#include <string>

#include "aegis/crypto/chacha20.hpp"
#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/sha256.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "test_framework.hpp"

using namespace aegis;

namespace {

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    static const char* kDigits = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        text.push_back(kDigits[data[i] >> 4]);
        text.push_back(kDigits[data[i] & 0x0F]);
    }
    return text;
}

}  // namespace

TEST_CASE(sha256_referenzwerte) {
    std::uint8_t digest[32];

    crypto::Sha256::hash("abc", 3, digest);
    CHECK_EQ(to_hex(digest, 32),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    crypto::Sha256::hash("", 0, digest);
    CHECK_EQ(to_hex(digest, 32),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    const std::string big(1000, 'a');
    crypto::Sha256::hash(big.data(), big.size(), digest);
    CHECK_EQ(to_hex(digest, 32),
             std::string("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"));
}

TEST_CASE(sha256_inkrementell) {
    std::uint8_t one_shot[32];
    std::uint8_t incremental[32];

    const std::string text = "AEGIS Guard testet inkrementelles Hashing über Blockgrenzen hinweg.";
    crypto::Sha256::hash(text.data(), text.size(), one_shot);

    crypto::Sha256 context;
    for (std::size_t offset = 0; offset < text.size(); offset += 7) {
        const std::size_t chunk = std::min<std::size_t>(7, text.size() - offset);
        context.update(text.data() + offset, chunk);
    }
    context.final(incremental);

    CHECK(crypto::constant_time_equal(one_shot, incremental, 32));
}

TEST_CASE(hmac_sha256_rfc4231) {
    std::uint8_t key[20];
    std::memset(key, 0x0b, sizeof(key));
    std::uint8_t digest[32];

    const char* message = "Hi There";
    crypto::hmac_sha256(key, sizeof(key), reinterpret_cast<const std::uint8_t*>(message),
                        std::strlen(message), digest);

    CHECK_EQ(to_hex(digest, 32),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

TEST_CASE(chacha20_referenzwerte) {
    std::uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(i);
    std::uint8_t nonce[12] = {};

    std::uint8_t block[64];
    crypto::chacha20_block(key, nonce, 1, block);
    CHECK_EQ(to_hex(block, 64),
             std::string("18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c"
                         "7208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd"));

    std::uint8_t stream[100] = {};
    crypto::chacha20_xor(stream, sizeof(stream), key, nonce, 7);
    CHECK_EQ(to_hex(stream, 100),
             std::string("185838beabf85b1605467c46149350e877815eefc73f7d9b3d94b198d7fef9c9"
                         "17cd76043d85feff6cfc7272f1e6dfb201def102acf0175b4fe41f026a6d9cf2"
                         "4b562eb04c19cb21e1625bd563cc818ed0ddc55580ff29b6fd4ec5a1b1757451"
                         "a0e7a1c1"));
}

TEST_CASE(aead_rundreise_und_manipulation) {
    std::uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(0xA0 + i);
    std::uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

    const std::string plaintext = "process\tx64dbg\nmodule\tscyllahide\n";
    std::string ciphertext(plaintext.size(), '\0');
    std::uint8_t tag[16];
    const std::uint8_t associated[] = "kontext";

    crypto::aead_seal(key, nonce, associated, sizeof(associated) - 1,
                      reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size(),
                      reinterpret_cast<std::uint8_t*>(&ciphertext[0]), tag);

    CHECK(ciphertext != plaintext);

    std::string decrypted(plaintext.size(), '\0');
    CHECK(crypto::aead_open(key, nonce, associated, sizeof(associated) - 1,
                            reinterpret_cast<const std::uint8_t*>(ciphertext.data()),
                            ciphertext.size(), tag,
                            reinterpret_cast<std::uint8_t*>(&decrypted[0])));
    CHECK_EQ(decrypted, plaintext);

    // Ein gekipptes Bit muss auffallen.
    ciphertext[3] = static_cast<char>(ciphertext[3] ^ 0x01);
    CHECK(!crypto::aead_open(key, nonce, associated, sizeof(associated) - 1,
                             reinterpret_cast<const std::uint8_t*>(ciphertext.data()),
                             ciphertext.size(), tag,
                             reinterpret_cast<std::uint8_t*>(&decrypted[0])));

    // Falscher Kontext ebenfalls.
    ciphertext[3] = static_cast<char>(ciphertext[3] ^ 0x01);
    CHECK(!crypto::aead_open(key, nonce, reinterpret_cast<const std::uint8_t*>("anders"),
                             sizeof("anders") - 1,
                             reinterpret_cast<const std::uint8_t*>(ciphertext.data()),
                             ciphertext.size(), tag,
                             reinterpret_cast<std::uint8_t*>(&decrypted[0])));
}

TEST_CASE(xorstr_vergleiche) {
    const auto literal = AEGIS_STR("VBoxService.exe");

    CHECK(literal.equals_ci("vboxservice.exe"));
    CHECK(literal.equals_ci("VBOXSERVICE.EXE"));
    CHECK(!literal.equals_ci("vboxservice"));
    CHECK(!literal.equals_ci(""));
    CHECK_EQ(literal.size(), std::size_t(15));
    CHECK_EQ(literal.to_string(), std::string("VBoxService.exe"));

    const auto pattern = AEGIS_STR("Ghidra");
    CHECK(pattern.contained_in_ci("Ghidra: projekt.exe - CodeBrowser"));
    CHECK(!pattern.contained_in_ci("Notepad"));
    CHECK(pattern.contains_ci("xxGHIDRAxx", 10));
    CHECK(!pattern.contains_ci("xxGHIDRAxx", 6));
}

TEST_CASE(xorstr_entschluesselt_korrekt) {
    // Die eigentliche Pruefung "kein Klartext im Binary" macht
    // tools/check_no_plaintext.py (laeuft in der CI ueber die Artefakte).
    const auto literal = AEGIS_STR("ScyllaHide");
    CHECK(literal.equals("ScyllaHide"));
    CHECK(literal.equals_ci("scyllahide"));

    char buffer[16];
    literal.copy_to(buffer);
    CHECK_EQ(std::string(buffer), std::string("ScyllaHide"));
    crypto::secure_zero(buffer, sizeof(buffer));

    // Gleicher Text, andere Verwendungsstelle => anderer Schluessel.
    const auto other = AEGIS_STR("ScyllaHide");
    CHECK_EQ(literal.to_hash(), other.to_hash());
}

TEST_CASE(namen_normalisierung) {
    const std::uint64_t reference = crypto::normalize_name_hash("x64dbg");

    CHECK_EQ(crypto::normalize_name_hash("x64dbg.exe"), reference);
    CHECK_EQ(crypto::normalize_name_hash("X64DBG.EXE"), reference);
    CHECK_EQ(crypto::normalize_name_hash("C:\\Tools\\x64dbg.exe"), reference);
    CHECK_EQ(crypto::normalize_name_hash("/opt/tools/x64dbg"), reference);
    CHECK_EQ(crypto::normalize_name_hash("x64dbg#1"), reference);

    CHECK(crypto::normalize_name_hash("x64dbg") != crypto::normalize_name_hash("x32dbg"));
    CHECK(crypto::normalize_name_hash("radare2.so") == crypto::normalize_name_hash("radare2"));
}

TEST_CASE(secure_zero_loescht) {
    char buffer[16];
    std::memset(buffer, 0x5A, sizeof(buffer));
    crypto::secure_zero(buffer, sizeof(buffer));
    for (char value : buffer) CHECK_EQ(static_cast<int>(value), 0);
}

TEST_CASE(splitmix64_verteilung) {
    // Keine Kollisionen in den ersten 4096 Werten - reicht als Smoke-Test.
    std::uint64_t seen[4096];
    for (std::uint64_t i = 0; i < 4096; ++i) {
        seen[i] = crypto::splitmix64(i);
        for (std::uint64_t j = 0; j < i; ++j) CHECK(seen[j] != seen[i]);
    }
}
