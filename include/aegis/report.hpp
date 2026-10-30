// SPDX-License-Identifier: MIT
// AEGIS Guard - report.hpp
//
// Ergebnis einer Pruefung: Liste der Findings, gewichteter Score und die
// daraus abgeleitete Entscheidung.

#ifndef AEGIS_REPORT_HPP
#define AEGIS_REPORT_HPP

#include <cstdint>
#include <string>

#include "aegis/config.hpp"
#include "aegis/finding.hpp"

namespace aegis {

struct Report {
    Findings findings;
    int score = 0;
    Severity max_severity = Severity::Info;
    bool blocked = false;
    bool decisive_hit = false;
    /// Wurde ein konfiguriertes Dataset manipuliert / nicht authentisch?
    bool dataset_invalid = false;
    std::uint64_t elapsed_us = 0;
    /// Kurze, menschenlesbare Begruendung der Entscheidung.
    std::string reason;

    bool any(Category category) const noexcept;
    bool has(std::string_view id_prefix) const noexcept;
    /// Enthaelt alle IDs der Findings, mit ';' getrennt.
    std::string id_list() const;
    /// Menschenlesbare Mehrzeiler-Ausgabe (fuer Logs / Demo).
    std::string summary() const;
    /// Maschinenlesbares JSON (fuer CI, Telemetrie, Tests).
    std::string to_json() const;
};

/// Summiert Findings und entscheidet anhand der Config-Schwellen.
Report evaluate_policy(const Config& config, Findings findings, bool dataset_invalid = false);

}  // namespace aegis

#endif  // AEGIS_REPORT_HPP
