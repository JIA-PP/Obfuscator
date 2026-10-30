// SPDX-License-Identifier: MIT
#include <string>
#include <vector>

#include "aegis/crypto/fnv.hpp"
#include "aegis/detect.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"
#include "test_framework.hpp"

using namespace aegis;

namespace {

const data::NameEntry* find_process(const char* name, std::size_t& count, const data::NameEntry*& table) {
    table = data::analysis_processes(count);
    return data::find_name(table, count, crypto::normalize_name_hash(name));
}

bool findings_contain(const Findings& findings, const char* id) {
    for (const Finding& finding : findings) {
        if (finding.id == id) return true;
    }
    return false;
}

bool evidence_contains(const Findings& findings, const std::string& needle) {
    for (const Finding& finding : findings) {
        if (finding.evidence.find(needle) != std::string::npos) return true;
    }
    return false;
}

Config all_disabled() {
    Config config;
    config.check_hypervisor = false;
    config.check_hardware = false;
    config.check_artifacts = false;
    config.check_sandbox_env = false;
    config.check_analysis_tools = false;
    config.check_windows = false;
    config.check_debugger = false;
    config.check_timing = false;
    config.check_injected_modules = false;
    config.check_api_hooks = false;
    config.check_container = false;
    config.check_user_interaction = false;
    return config;
}

}  // namespace

TEST_CASE(tabelle_erkennt_bekannte_werkzeuge) {
    std::size_t count = 0;
    const data::NameEntry* table = nullptr;

    const data::NameEntry* x64dbg = find_process("x64dbg.exe", count, table);
    REQUIRE(x64dbg != nullptr);
    CHECK_EQ(x64dbg->category, data::ToolCategory::Debugger);

    const data::NameEntry* ida = find_process("C:\\Program Files\\IDA 8.3\\ida64.exe", count, table);
    REQUIRE(ida != nullptr);
    CHECK_EQ(ida->category, data::ToolCategory::Disassembler);

    const data::NameEntry* dnspy = find_process("dnSpy.exe", count, table);
    REQUIRE(dnspy != nullptr);
    CHECK_EQ(dnspy->category, data::ToolCategory::DotnetDecompiler);

    const data::NameEntry* http = find_process("HTTPDebuggerUI.exe", count, table);
    REQUIRE(http != nullptr);
    CHECK_EQ(http->category, data::ToolCategory::NetworkSniffer);

    const data::NameEntry* frida = find_process("frida-server", count, table);
    REQUIRE(frida != nullptr);
    CHECK_EQ(frida->category, data::ToolCategory::Instrumentation);

    const data::NameEntry* cutter = find_process("Cutter.exe", count, table);
    REQUIRE(cutter != nullptr);
    CHECK_EQ(cutter->category, data::ToolCategory::Disassembler);
}

TEST_CASE(tabelle_ignoriert_harmlose_prozesse) {
    std::size_t count = 0;
    const data::NameEntry* table = data::analysis_processes(count);

    CHECK(data::find_name(table, count, crypto::normalize_name_hash("explorer.exe")) == nullptr);
    CHECK(data::find_name(table, count, crypto::normalize_name_hash("notepad.exe")) == nullptr);
    CHECK(data::find_name(table, count, crypto::normalize_name_hash("svchost.exe")) == nullptr);
    CHECK(data::find_name(table, count, crypto::normalize_name_hash("code.exe")) == nullptr);
    CHECK(data::find_name(table, count, crypto::normalize_name_hash("")) == nullptr);
}

TEST_CASE(tabelle_erkennt_analyse_module) {
    std::size_t count = 0;
    const data::NameEntry* table = data::analysis_modules(count);

    const data::NameEntry* frida_agent =
        data::find_name(table, count, crypto::normalize_name_hash("frida-agent-64.dll"));
    REQUIRE(frida_agent != nullptr);
    CHECK_EQ(frida_agent->category, data::ToolCategory::Instrumentation);

    const data::NameEntry* scylla =
        data::find_name(table, count, crypto::normalize_name_hash("ScyllaHideVT.dll"));
    REQUIRE(scylla != nullptr);
    CHECK_EQ(scylla->category, data::ToolCategory::RuntimeHook);
}

TEST_CASE(fenstertitel_werden_erkannt) {
    CHECK(data::match_title("Ghidra: mal.exe - CodeBrowser") != nullptr);
    CHECK(data::match_title("x64dbg - [CPU]") != nullptr);
    CHECK(data::match_title("IDA Pro - analyse.idb") != nullptr);
    CHECK(data::match_title("Wireshark 4.0.0") != nullptr);
    CHECK(data::match_title("Unbenannt - Editor") == nullptr);
    CHECK(data::match_title("") == nullptr);
}

TEST_CASE(text_artefakte_werden_entschluesselt) {
    std::size_t count = 0;
    const data::TextEntry* files = data::vm_files(count);
    REQUIRE(count > 5);

    bool found_vbox_guest = false;
    for (std::size_t i = 0; i < count; ++i) {
        const data::DecodedText path(files[i]);
        REQUIRE(path.valid());
        if (platform::icontains(path.c_str(), "VBoxGuest.sys")) found_vbox_guest = true;
    }
    CHECK(found_vbox_guest);

    std::size_t mac_count = 0;
    const data::MacEntry* macs = data::vm_mac_prefixes(mac_count);
    REQUIRE(mac_count > 3);
    bool has_virtualbox_oui = false;
    for (std::size_t i = 0; i < mac_count; ++i) {
        if (macs[i].prefix[0] == 0x08 && macs[i].prefix[1] == 0x00 && macs[i].prefix[2] == 0x27) {
            has_virtualbox_oui = true;
        }
    }
    CHECK(has_virtualbox_oui);
}

TEST_CASE(alle_detektoren_deaktiviert_liefern_nichts) {
    const Config config = all_disabled();
    Findings findings;

    detect::hypervisor(config, findings);
    detect::hardware(config, findings);
    detect::artifacts(config, findings);
    detect::sandbox_environment(config, findings);
    detect::analysis_tools(config, findings);
    detect::windows_enum(config, findings);
    detect::debugger(config, findings);
    detect::timing(config, findings);
    detect::api_hooks(config, findings);
    detect::injected_modules(config, findings);

    CHECK_EQ(findings.size(), std::size_t(0));
}

TEST_CASE(detektoren_laufen_ohne_absturz) {
    Config config = Config::balanced();
    config.check_timing = false;  // 1,5 s Sleep waeren im Test unnoetig

    Findings findings;
    detect::hypervisor(config, findings);
    detect::hardware(config, findings);
    detect::artifacts(config, findings);
    detect::sandbox_environment(config, findings);
    detect::analysis_tools(config, findings);
    detect::windows_enum(config, findings);
    detect::debugger(config, findings);
    detect::injected_modules(config, findings);

    // Kein Absturz, plausible IDs.
    for (const Finding& finding : findings) {
        CHECK(!finding.id.empty());
        CHECK(finding.weight > 0);
    }
}

TEST_CASE(prozessscan_findet_eigenen_prozess_ueber_zusatzliste) {
    Config config = Config::balanced();
    config.scan_command_lines = false;
    config.check_hypervisor = false;
    config.check_hardware = false;
    config.check_artifacts = false;
    config.check_sandbox_env = false;
    config.check_windows = false;
    config.check_debugger = false;
    config.check_timing = false;
    config.check_injected_modules = false;

    // Der Testprozess heisst "aegis_tests" (Linux) bzw. "aegis_tests.exe".
    config.extra_processes = {"aegis_tests"};

    Findings findings;
    detect::analysis_tools(config, findings);

    REQUIRE(!findings.empty());
    CHECK(findings_contain(findings, "tool.process"));
    CHECK(evidence_contains(findings, "aegis_tests"));

    bool decisive = false;
    for (const Finding& finding : findings) {
        if (finding.id == "tool.process" && finding.decisive) decisive = true;
    }
    CHECK(decisive);
    CHECK_EQ(findings[0].category, Category::AnalysisTool);
}

TEST_CASE(prozessscan_respektiert_allowlist) {
    Config config = Config::balanced();
    config.extra_processes = {"aegis_tests"};
    config.process_allowlist = {"aegis_tests"};
    config.check_hypervisor = false;
    config.check_hardware = false;
    config.check_artifacts = false;
    config.check_sandbox_env = false;
    config.check_windows = false;
    config.check_debugger = false;
    config.check_timing = false;
    config.check_injected_modules = false;

    Findings findings;
    detect::analysis_tools(config, findings);
    CHECK(!evidence_contains(findings, "aegis_tests"));
}

TEST_CASE(prozessscan_ignoriert_unbekannte_namen) {
    Config config = Config::balanced();
    config.scan_command_lines = false;

    Findings findings;
    detect::analysis_tools(config, findings);
    CHECK(!findings_contain(findings, "tool.process"));
}

TEST_CASE(plattform_liefert_prozessliste) {
    const std::vector<platform::ProcessInfo> processes = platform::list_processes(false);
    CHECK(!processes.empty());

    bool found_self = false;
    for (const platform::ProcessInfo& process : processes) {
        if (platform::icontains(process.name, "aegis_tests")) found_self = true;
    }
    CHECK(found_self);
}

TEST_CASE(plattform_hardwarewerte_plausibel) {
    CHECK(platform::cpu_cores() > 0);
    CHECK(platform::ram_mb() > 0);
    CHECK(platform::monotonic_ms() > 0);
    CHECK(!platform::computername().empty());
    CHECK(platform::process_count() > 0);
}
