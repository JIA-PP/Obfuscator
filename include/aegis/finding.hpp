// SPDX-License-Identifier: MIT
// AEGIS Guard - finding.hpp
//
// Ein "Finding" ist ein einzelner Nachweis einer Analyseumgebung.
// Detektoren fuellen eine Liste solcher Findings; die Policy summiert
// Gewichtungen und entscheidet daraus ueber Blockieren oder Durchlassen.

#ifndef AEGIS_FINDING_HPP
#define AEGIS_FINDING_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

enum class Severity : std::uint8_t {
    Info = 1,   // Hinweis, allein nicht ausreichend
    Low = 2,    // verdaechtig
    Medium = 3, // wahrscheinlich Analyseumgebung
    High = 4,   // deutliche Analyseumgebung
    Critical = 5,
};

enum class Category : std::uint8_t {
    Virtualization,  // VM/Hypervisor
    Sandbox,         // Sandbox / Container / automatisches Analyse-Setup
    AnalysisTool,    // laufendes Reverse-Engineering-Werkzeug
    Debugger,        // Debugger haengt am eigenen Prozess
    Timing,          // Zeitmanipulation / Zeitraffer
    Hardware,        // unplausible Hardware-Ausstattung
    Integrity,       // Hooks / Manipulation am eigenen Binary
    Environment,     // Benutzer-, Rechner-, Sprach-, Regionsartefakte
};

std::string_view to_string(Severity severity) noexcept;
std::string_view to_string(Category category) noexcept;

struct Finding {
    std::string id;        // stabiler Bezeichner, z. B. "vm.cpuid.vendor"
    Category category = Category::Environment;
    Severity severity = Severity::Info;
    int weight = 0;        // Beitrag zum Gesamt-Score
    std::string evidence;  // Klartext-Beweis (nur Laufzeitdaten, keine Geheimnisse)
    bool decisive = false; // loest sofort die Reaktion aus, unabhaengig vom Score
};

using Findings = std::vector<Finding>;

/// Fuegt ein Finding hinzu, sofern `present` wahr ist. Liefert `present` zurueck,
/// damit Aufrufer kurzschliessen koennen.
bool add(Findings& out, bool present, std::string_view id, Category category,
         Severity severity, int weight, std::string evidence, bool decisive = false);

/// Gewichtung passend zur Severity (Basis fuer Standardwerte).
int default_weight(Severity severity) noexcept;

}  // namespace aegis

#endif  // AEGIS_FINDING_HPP
