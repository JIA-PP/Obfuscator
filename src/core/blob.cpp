// SPDX-License-Identifier: MIT
#include "aegis/blob.hpp"

#include <cstring>

#include "aegis/crypto/chacha20.hpp"
#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/xorstr.hpp"

namespace aegis {
namespace {

constexpr char kKindProcess[] = "process";
constexpr char kKindModule[] = "module";
constexpr char kKindWindowClass[] = "window_class";
constexpr char kKindWindowTitle[] = "window_title";
constexpr char kKindFile[] = "file";

/// Zerlegen einer Zeile "kind<TAB>value" bzw. "kind:value".
bool split_line(const std::string& line, std::string& kind, std::string& value) {
    const std::size_t tab = line.find('\t');
    if (tab != std::string::npos) {
        kind = line.substr(0, tab);
        value = line.substr(tab + 1);
        return true;
    }
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos) {
        kind = line.substr(0, colon);
        value = line.substr(colon + 1);
        return true;
    }
    return false;
}

}  // namespace

bool EncryptedDataset::extract_key(std::uint8_t out[32]) const noexcept {
    for (std::size_t word = 0; word < 4; ++word) {
        const std::uint64_t mask = crypto::splitmix64(key_mask + static_cast<std::uint64_t>(word));
        const std::uint64_t value = key_words[word] ^ mask;
        std::memcpy(out + word * 8, &value, sizeof(value));
    }
    return true;
}

bool EncryptedDataset::decrypt(std::string& plaintext) const {
    plaintext.clear();
    if (!loaded()) return false;

    std::uint8_t key[32];
    extract_key(key);

    std::string buffer;
    buffer.resize(size);
    const bool ok = crypto::aead_open(key, nonce, context, context_size, ciphertext, size, tag,
                                      reinterpret_cast<std::uint8_t*>(&buffer[0]));
    crypto::secure_zero(key, sizeof(key));
    if (!ok) {
        crypto::secure_zero(&buffer[0], buffer.size());
        return false;
    }
    plaintext.swap(buffer);
    return true;
}

void DatasetEntries::clear() noexcept {
    for (auto* list : {&processes, &modules, &window_classes, &window_titles, &files}) {
        for (std::string& entry : *list) {
            crypto::secure_zero(&entry[0], entry.size());
        }
        list->clear();
    }
}

std::size_t DatasetEntries::total() const noexcept {
    return processes.size() + modules.size() + window_classes.size() + window_titles.size() +
           files.size();
}

std::size_t parse_dataset(const std::string& text, DatasetEntries& out) {
    out.clear();
    std::size_t accepted = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(pos, end - pos);
        pos = end + 1;

        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        std::size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) ++start;
        line.erase(0, start);

        if (line.empty() || line[0] == '#') continue;

        std::string kind;
        std::string value;
        if (!split_line(line, kind, value)) continue;
        if (value.empty()) continue;

        if (kind == kKindProcess) {
            out.processes.push_back(value);
        } else if (kind == kKindModule) {
            out.modules.push_back(value);
        } else if (kind == kKindWindowClass) {
            out.window_classes.push_back(value);
        } else if (kind == kKindWindowTitle) {
            out.window_titles.push_back(value);
        } else if (kind == kKindFile) {
            out.files.push_back(value);
        } else {
            continue;  // unbekanntes Format: ignorieren
        }
        ++accepted;
    }
    return accepted;
}

bool load_dataset(const EncryptedDataset& dataset, DatasetEntries& out) {
    std::string plaintext;
    if (!dataset.decrypt(plaintext)) {
        plaintext.clear();
        return false;
    }
    const std::size_t accepted = parse_dataset(plaintext, out);
    crypto::secure_zero(&plaintext[0], plaintext.size());
    plaintext.clear();
    return accepted > 0;
}

}  // namespace aegis
