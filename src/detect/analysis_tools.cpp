// SPDX-License-Identifier: MIT
// Erkennung laufender Reverse-Engineering-Werkzeuge.
//
// Strategie:
//   1. Prozessliste aufnehmen (Name + Pfad + optional Kommandozeile).
//   2. Namen normalisieren (Pfad, Endung, Kleinschreibung) und ueber eine
//      maskierte FNV-1a-Hashtabelle vergleichen - im Binary steht kein
//      Klartext-Werkzeugname.
//   3. Bei generischen Host-Prozessen (python, java, node, dotnet, ...)
//      zusaetzlich die Kommandozeile pruefen, weil z. B. Ghidra, angr oder
//      frida als Python-/Java-Programm laufen.
//   4. Konfigurierte Zusatznamen (Config bzw. verschluesseltes Dataset)
//      werden mitgeprueft.
//
// Ein Treffer ist "decisive": die konfigurierte Reaktion wird sofort
// ausgefuehrt, unabhaengig vom Gesamt-Score.

#include "aegis/detect.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {
namespace {

struct ToolHit {
    std::string name;             ///< normalisierter Name (Schluessel)
    std::string raw_name;         ///< wie im System sichtbar
    data::ToolCategory category;
    std::vector<std::uint64_t> pids;
    std::string source;           ///< "Prozess" / "Zusatzliste"
    std::string command_line;     ///< gesetzt, wenn ueber die Kommandozeile erkannt
};

std::string join_pids(const std::vector<std::uint64_t>& pids) {
    std::string text;
    for (std::size_t i = 0; i < pids.size() && i < 6; ++i) {
        if (i > 0) text += ", ";
        text += std::to_string(pids[i]);
    }
    if (pids.size() > 6) text += ", ...";
    return text;
}

bool is_allowlisted(const Config& config, std::string_view normalized) {
    for (const std::string& allowed : config.process_allowlist) {
        const std::uint64_t hash = crypto::normalize_name_hash(allowed);
        if (hash == crypto::normalize_name_hash(normalized)) return true;
    }
    return false;
}

/// Prueft einen Namen gegen Tabelle und Zusatzliste.
const data::NameEntry* match_table(const data::NameEntry* table, std::size_t count,
                                   std::uint64_t hash) noexcept {
    return data::find_name(table, count, hash);
}

bool matches_extra(const std::vector<std::uint64_t>& extra_hashes, std::uint64_t hash) noexcept {
    return std::find(extra_hashes.begin(), extra_hashes.end(), hash) != extra_hashes.end();
}

/// Marker in Kommandozeilen generischer Host-Prozesse.
/// Die Muster stehen in einer generierten, XOR-verschluesselten Tabelle -
/// im Quelltext und im Binary existiert kein Klartext-Literal dafuer.
bool has_command_line_marker(const std::string& command_line) {
    if (command_line.empty() || command_line.size() < 4) return false;

    std::size_t count = 0;
    const data::TextEntry* markers = data::command_line_markers(count);
    const std::string lowered = platform::to_lower(command_line);

    for (std::size_t i = 0; i < count; ++i) {
        const data::DecodedText marker(markers[i]);
        if (marker.valid() && lowered.find(marker.c_str()) != std::string::npos) return true;
    }
    return false;
}

/// Kuerzt lange Kommandozeilen fuer die Beweisfuehrung.
std::string shorten(const std::string& text, std::size_t limit = 160) {
    if (text.size() <= limit) return text;
    return text.substr(0, limit) + "...";
}

}  // namespace

void analysis_tools(const Config& config, Findings& out) {
    if (!config.check_analysis_tools) return;

    std::vector<std::uint64_t> extra_hashes;
    extra_hashes.reserve(config.extra_processes.size());
    for (const std::string& extra : config.extra_processes) {
        extra_hashes.push_back(crypto::normalize_name_hash(extra));
    }

    std::size_t analysis_count = 0;
    std::size_t vm_count = 0;
    const data::NameEntry* analysis_table = data::analysis_processes(analysis_count);
    const data::NameEntry* vm_table = data::vm_processes(vm_count);

    const std::vector<platform::ProcessInfo> processes =
        platform::list_processes(config.scan_command_lines);

    std::map<std::string, ToolHit> hits;

    for (const platform::ProcessInfo& process : processes) {
        if (process.name.empty()) continue;

        const std::string normalized = platform::to_lower(platform::basename_of(process.name));
        if (normalized.empty()) continue;
        if (is_allowlisted(config, normalized)) continue;

        const std::uint64_t hash = crypto::normalize_name_hash(normalized);

        const data::NameEntry* entry = match_table(analysis_table, analysis_count, hash);
        if (entry != nullptr) {
            ToolHit& hit = hits[normalized];
            hit.name = normalized;
            hit.raw_name = process.name;
            hit.category = entry->category;
            hit.source = "Prozess";
            hit.pids.push_back(process.pid);
            continue;
        }

        if (matches_extra(extra_hashes, hash)) {
            ToolHit& hit = hits[normalized];
            hit.name = normalized;
            hit.raw_name = process.name;
            hit.category = data::ToolCategory::Unknown;
            hit.source = "Zusatzliste";
            hit.pids.push_back(process.pid);
            continue;
        }

        if (vm_table != nullptr && data::find_name(vm_table, vm_count, hash) != nullptr) {
            add(out, true, "vm.process", Category::Virtualization, Severity::Medium, 20,
                platform::format("VM-Gastprozess '%s' (PID %llu)", process.name.c_str(),
                                 static_cast<unsigned long long>(process.pid)));
            continue;
        }

        if (config.scan_command_lines && platform::is_generic_host(normalized)) {
            if (has_command_line_marker(process.cmdline)) {
                const std::string key = std::string("cmd:") + normalized;
                ToolHit& hit = hits[key];
                hit.name = key;
                hit.raw_name = process.name;
                hit.category = data::ToolCategory::Instrumentation;
                hit.source = "Prozess";
                hit.command_line = shorten(process.cmdline);
                hit.pids.push_back(process.pid);
            }
        }
    }

    for (const auto& pair : hits) {
        const ToolHit& hit = pair.second;
        std::string evidence;
        if (!hit.command_line.empty()) {
            evidence = platform::format("Kommandozeile '%s' (PID %s) enthaelt ein Analyse-Werkzeug",
                                        hit.command_line.c_str(), join_pids(hit.pids).c_str());
        } else {
            evidence = platform::format("%s '%s' laeuft (PID %s) - Kategorie: %s",
                                        hit.source.c_str(), hit.raw_name.c_str(),
                                        join_pids(hit.pids).c_str(), data::to_string(hit.category));
        }
        add(out, true, "tool.process", Category::AnalysisTool, Severity::Critical, 60, evidence,
            /*decisive=*/true);
    }
}

}  // namespace aegis::detect
