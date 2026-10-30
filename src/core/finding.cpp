// SPDX-License-Identifier: MIT
#include "aegis/finding.hpp"

#include <stdexcept>
#include <utility>

namespace aegis {

std::string_view to_string(Severity severity) noexcept {
    switch (severity) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

std::string_view to_string(Category category) noexcept {
    switch (category) {
        case Category::Virtualization: return "virtualization";
        case Category::Sandbox: return "sandbox";
        case Category::AnalysisTool: return "analysis-tool";
        case Category::Debugger: return "debugger";
        case Category::Timing: return "timing";
        case Category::Hardware: return "hardware";
        case Category::Integrity: return "integrity";
        case Category::Environment: return "environment";
    }
    return "environment";
}

int default_weight(Severity severity) noexcept {
    switch (severity) {
        case Severity::Info: return 5;
        case Severity::Low: return 12;
        case Severity::Medium: return 22;
        case Severity::High: return 35;
        case Severity::Critical: return 60;
    }
    return 0;
}

bool add(Findings& out, bool present, std::string_view id, Category category, Severity severity,
         int weight, std::string evidence, bool decisive) {
    if (!present) return false;
    Finding finding;
    finding.id.assign(id);
    finding.category = category;
    finding.severity = severity;
    finding.weight = weight > 0 ? weight : default_weight(severity);
    finding.evidence = std::move(evidence);
    finding.decisive = decisive;
    out.push_back(std::move(finding));
    return true;
}

}  // namespace aegis
