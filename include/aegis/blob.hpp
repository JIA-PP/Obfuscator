// SPDX-License-Identifier: MIT
// AEGIS Guard - blob.hpp
//
// Verschluesselte Zusatz-Konfiguration ("Dataset").
//
// Ein Dataset ist eine mit ChaCha20 verschluesselte und per HMAC-SHA-256
// authentifizierte Liste zusaetzlicher Analyse-Artefakte (Prozessnamen,
// Modulnamen, Fensterklassen, Fenstertitel, Dateipfade). Es wird zur
// BUILD-Zeit von tools/aegis_tool.py erzeugt und liegt als Byte-Array im
// Binary. Der Schluessel wird in vier maskierten 64-Bit-Woertern abgelegt,
// damit ein `strings`-Scan oder einfaches Signatur-Matching nicht greift.
//
// Format des Klartexts (UTF-8, Zeilen):
//     # Kommentar
//     process<TAB>x64dbg
//     module<TAB>scyllahide
//     window_class<TAB>WinDbgFrameClass
//     window_title<TAB>Ghidra
//     file<TAB>C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
//
// Unbekannte "kind"-Werte werden ignoriert (Vorwaertskompatibilitaet).

#ifndef AEGIS_BLOB_HPP
#define AEGIS_BLOB_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aegis {

struct EncryptedDataset {
    const std::uint8_t* ciphertext = nullptr;
    std::size_t size = 0;
    std::uint8_t nonce[12] = {};
    std::uint8_t tag[16] = {};
    /// Schluessel als vier maskierte Woerter: key_word[i] ^ splitmix64(mask + i)
    std::uint64_t key_words[4] = {};
    std::uint64_t key_mask = 0;
    /// Optionaler Kontext (wird in den MAC eingerechnet).
    const std::uint8_t* context = nullptr;
    std::size_t context_size = 0;

    /// Rekonstruiert den 32-Byte-Schluessel und nullt die temporaeren Puffer.
    bool extract_key(std::uint8_t out[32]) const noexcept;

    /// Entschluesselt und prueft den MAC. Bei Erfolg steht der Klartext in
    /// `plaintext`; der Aufrufer muss ihn anschliessend nullen.
    bool decrypt(std::string& plaintext) const;

    /// Wie decrypt(), aber ohne Klartext-Rueckgabe: parst direkt und nullt
    /// den Zwischenpuffer danach.
    bool loaded() const noexcept { return ciphertext != nullptr && size > 0; }
};

struct DatasetEntries {
    std::vector<std::string> processes;
    std::vector<std::string> modules;
    std::vector<std::string> window_classes;
    std::vector<std::string> window_titles;
    std::vector<std::string> files;

    void clear() noexcept;
    std::size_t total() const noexcept;
};

/// Parst das Klartext-Format (siehe oben). Rueckgabe: Anzahl uebernommener
/// Eintraege; 0 bedeutet "leer oder unbrauchbar".
std::size_t parse_dataset(const std::string& text, DatasetEntries& out);

/// Laedt ein Dataset in `out`; gibt false zurueck, wenn MAC-Pruefung oder
/// Parsing fehlschlaegt (dann ist das Dataset zu behandeln wie "nicht
/// vorhanden" - oder, je nach Policy, als Manipulation).
bool load_dataset(const EncryptedDataset& dataset, DatasetEntries& out);

}  // namespace aegis

#endif  // AEGIS_BLOB_HPP
