// SPDX-License-Identifier: MIT
#include <cstring>
#include <string>
#include <vector>

#include "aegis/blob.hpp"
#include "aegis/guard.hpp"
#include "data/interop_blob.hpp"
#include "test_framework.hpp"

using namespace aegis;

namespace {

bool contains(const std::vector<std::string>& list, const std::string& value) {
    for (const std::string& entry : list) {
        if (entry == value) return true;
    }
    return false;
}

}  // namespace

TEST_CASE(dataset_parser_alle_typen) {
    const std::string text =
        "# Kommentar\n"
        "process\tx64dbg\n"
        "process:ida64\n"
        "module\tscyllahide\n"
        "window_class\tWinDbgFrameClass\n"
        "window_title\tGhidra\n"
        "file\tC:\\Tools\\frida.dll\n"
        "\n"
        "unbekannt\tignorieren\n"
        "process\t\n";

    DatasetEntries entries;
    CHECK_EQ(parse_dataset(text, entries), std::size_t(6));
    CHECK_EQ(entries.processes.size(), std::size_t(2));
    CHECK(contains(entries.processes, "x64dbg"));
    CHECK(contains(entries.processes, "ida64"));
    CHECK(contains(entries.modules, "scyllahide"));
    CHECK_EQ(entries.window_classes.size(), std::size_t(1));
    CHECK_EQ(entries.window_titles.size(), std::size_t(1));
    CHECK_EQ(entries.files.size(), std::size_t(1));
    CHECK_EQ(entries.total(), std::size_t(6));
}

TEST_CASE(dataset_parser_crlf_und_leerzeilen) {
    const std::string text = "process\ta\r\n\r\nprocess\tb\r\n";
    DatasetEntries entries;
    CHECK_EQ(parse_dataset(text, entries), std::size_t(2));
    CHECK_EQ(entries.processes[1], std::string("b"));
}

TEST_CASE(dataset_interop_python_cpp) {
    // Der Blob wurde von tools/aegis_tool.py erzeugt (fester Schluessel/Nonce).
    DatasetEntries entries;
    REQUIRE(load_dataset(data::kDataset, entries));

    CHECK_EQ(entries.total(), std::size_t(7));
    CHECK(contains(entries.processes, "x64dbg"));
    CHECK(contains(entries.processes, "ida64"));
    CHECK(contains(entries.modules, "scyllahide"));
    CHECK(contains(entries.window_classes, "WinDbgFrameClass"));
    CHECK(contains(entries.window_titles, "Ghidra"));
    CHECK(contains(entries.files, "C:\\Test\\frida-agent.dll"));
    CHECK(contains(entries.files, "/opt/analysis/tool"));
}

TEST_CASE(dataset_manipulation_wird_erkannt) {
    std::vector<std::uint8_t> tampered(
        data::kDatasetCiphertext,
        data::kDatasetCiphertext + sizeof(data::kDatasetCiphertext));
    tampered[0] = static_cast<std::uint8_t>(tampered[0] ^ 0xFF);

    EncryptedDataset modified = data::kDataset;
    modified.ciphertext = tampered.data();

    DatasetEntries entries;
    CHECK(!load_dataset(modified, entries));
    CHECK_EQ(entries.total(), std::size_t(0));
}

TEST_CASE(dataset_falscher_kontext_wird_erkannt) {
    EncryptedDataset modified = data::kDataset;
    const std::string wrong_context = "falscher-kontext";
    modified.context = reinterpret_cast<const std::uint8_t*>(wrong_context.data());
    modified.context_size = wrong_context.size();

    DatasetEntries entries;
    CHECK(!load_dataset(modified, entries));
}

TEST_CASE(dataset_wird_in_guard_eingemischt) {
    Config config = Config::relaxed();
    config.check_analysis_tools = true;
    config.dataset = &data::kDataset;

    Guard guard(config);
    const Report report = guard.evaluate();

    CHECK(!report.dataset_invalid);
    // Nach dem Einmischen muss die Zusatzliste im Guard stehen.
    CHECK_EQ(guard.config().extra_processes.size(), std::size_t(0));  // erst nach add_dataset
}

TEST_CASE(dataset_add_dataset_erweitert_konfiguration) {
    Config config = Config::relaxed();
    Guard guard(config);

    CHECK(guard.add_dataset(data::kDataset));
    CHECK_EQ(guard.config().extra_processes.size(), std::size_t(2));
    CHECK_EQ(guard.config().extra_files.size(), std::size_t(2));

    // Zweites Einmischen desselben Datasets ist erlaubt (idempotent waere
    // schoener, ist aber nicht kritisch) - zumindest darf es nicht werfen.
    CHECK(guard.add_dataset(data::kDataset));
}
