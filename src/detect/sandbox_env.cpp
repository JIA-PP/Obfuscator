// SPDX-License-Identifier: MIT
// Sandbox-/Analyse-Umgebung: Benutzer, Rechnername, Prozessanzahl,
// Benutzerinteraktion, Container.
//
// Diese Pruefungen sind einzeln schwach (und absichtlich niedrig gewichtet) -
// sie sind fuer die Kombination mit VM- und Werkzeug-Erkennung gedacht.

#include "aegis/detect.hpp"

#include <cstdlib>

#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {
namespace {

bool name_in_table(const data::TextEntry* table, std::size_t count, const std::string& value) {
    if (value.empty()) return false;
    for (std::size_t i = 0; i < count; ++i) {
        const data::DecodedText entry(table[i]);
        if (entry.valid() && platform::iequals(entry.c_str(), value)) return true;
    }
    return false;
}

void check_names(Findings& out) {
    const std::string user = platform::username();
    const std::string computer = platform::computername();

    std::size_t user_count = 0;
    const data::TextEntry* users = data::sandbox_users(user_count);
    if (name_in_table(users, user_count, user)) {
        add(out, true, "sandbox.username", Category::Environment, Severity::Low, 12,
            "Benutzername '" + user + "' ist ein typischer Analyse-Account");
    }

    std::size_t computer_count = 0;
    const data::TextEntry* computers = data::sandbox_computers(computer_count);
    if (name_in_table(computers, computer_count, computer)) {
        add(out, true, "sandbox.computername", Category::Environment, Severity::Low, 12,
            "Rechnername '" + computer + "' ist ein typischer Analyse-Host");
    }
}

void check_container(const Config& config, Findings& out) {
    if (!config.check_container) return;

    bool container = false;
    std::string evidence;

#if defined(_WIN32)
    // Windows-Container: Registry-Artefakt der Container-Runtime
    if (platform::registry_key_exists(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Container")) {
        container = true;
        evidence = "Windows-Container-Registry vorhanden";
    }
#else
    const std::string cgroup = platform::proc_self_cgroup();
    std::size_t marker_count = 0;
    const data::TextEntry* markers = data::container_markers(marker_count);
    if (!cgroup.empty() && data::contains_any(markers, marker_count, cgroup.c_str())) {
        container = true;
        std::string excerpt;
        for (char c : cgroup) {
            if (excerpt.size() >= 120) {
                excerpt += "...";
                break;
            }
            excerpt.push_back(c == '\n' ? ' ' : c);
        }
        evidence = "cgroup: " + excerpt;
    }

    if (!container) {
        std::size_t file_count = 0;
        const data::TextEntry* files = data::container_files(file_count);
        for (std::size_t i = 0; i < file_count; ++i) {
            const data::DecodedText path(files[i]);
            if (!path.valid()) continue;
            if (!platform::file_exists(path.c_str()) && !platform::dir_exists(path.c_str())) continue;
            container = true;
            evidence = "Container-Marker-Datei: " + std::string(path.c_str());
            break;
        }
    }

    if (!container) {
        const char* ci = ::getenv("CI");
        if (ci != nullptr && (*ci == '1' || *ci == 't' || *ci == 'T')) {
            container = true;
            evidence = "CI-Umgebungsvariable gesetzt";
        }
    }
#endif

    if (container) {
        add(out, true, "sandbox.container", Category::Sandbox, Severity::Low, 14, evidence);
    }
}

void check_process_count(const Config& config, Findings& out) {
    const unsigned long long count = platform::process_count();
    if (count > 0 && count < config.min_process_count) {
        add(out, true, "sandbox.process_count", Category::Sandbox, Severity::Low, 12,
            platform::format("Nur %llu Prozesse aktiv (< %u)", count, config.min_process_count));
    }
}

/// Ein echter Arbeitsplatz hat Mausbewegung/Benutzereingaben. Analysesysteme
/// laufen meist headless. Standardmaessig deaktiviert (Server-Fehlalarm!).
void check_interaction(Findings& out) {
    const std::uint64_t idle_ms = platform::last_input_ms();
    int x0 = 0, y0 = 0;
    const bool have_position = platform::cursor_position(x0, y0);

    if (have_position) {
        platform::sleep_ms(400);
        int x1 = 0, y1 = 0;
        if (platform::cursor_position(x1, y1) && (x1 != x0 || y1 != y0)) return;
    }

    if (idle_ms > 60000) {
        add(out, true, "sandbox.no_input", Category::Sandbox, Severity::Info, 8,
            platform::format("Keine Benutzereingabe seit %llu s",
                             static_cast<unsigned long long>(idle_ms / 1000)));
    }
}

}  // namespace

void sandbox_environment(const Config& config, Findings& out) {
    if (!config.check_sandbox_env) return;

    check_names(out);
    check_process_count(config, out);
    check_container(config, out);

    if (config.check_user_interaction) check_interaction(out);
}

}  // namespace aegis::detect
