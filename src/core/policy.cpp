// SPDX-License-Identifier: MIT
#include "aegis/report.hpp"

#include <algorithm>
#include <cstdio>

#include "aegis/version.hpp"

namespace aegis {
namespace {

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04X", static_cast<unsigned char>(c));
                    out += buffer;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string severity_tag(Severity severity) {
    std::string tag(to_string(severity));
    while (tag.size() < 8) tag.push_back(' ');
    return tag;
}

}  // namespace

bool Report::any(Category category) const noexcept {
    return std::any_of(findings.begin(), findings.end(),
                       [category](const Finding& finding) { return finding.category == category; });
}

bool Report::has(std::string_view id_prefix) const noexcept {
    return std::any_of(findings.begin(), findings.end(), [id_prefix](const Finding& finding) {
        return finding.id.size() >= id_prefix.size() &&
               finding.id.compare(0, id_prefix.size(), id_prefix) == 0;
    });
}

std::string Report::id_list() const {
    std::string text;
    for (const Finding& finding : findings) {
        if (!text.empty()) text += ';';
        text += finding.id;
    }
    return text;
}

std::string Report::summary() const {
    std::string text;
    text += "AEGIS Guard ";
    text += AEGIS_VERSION_STRING;
    text += "  Score: ";
    text += std::to_string(score);
    text += "  Ergebnis: ";
    text += blocked ? "BLOCKIERT" : "durchgelassen";
    if (decisive_hit) text += " (decisives Finding)";
    if (dataset_invalid) text += " [Dataset manipuliert]";
    text += '\n';

    if (findings.empty()) {
        text += "  keine Auffaelligkeiten\n";
        return text;
    }

    for (const Finding& finding : findings) {
        char line[512];
        std::snprintf(line, sizeof(line), "  [%-8s +%3d] %-34s %s\n",
                      severity_tag(finding.severity).c_str(), finding.weight, finding.id.c_str(),
                      finding.evidence.c_str());
        text += line;
    }
    if (!reason.empty()) {
        text += "  Begruendung: ";
        text += reason;
        text += '\n';
    }
    return text;
}

std::string Report::to_json() const {
    std::string json;
    json += "{\"version\":\"";
    json += AEGIS_VERSION_STRING;
    json += "\",\"score\":";
    json += std::to_string(score);
    json += ",\"blocked\":";
    json += blocked ? "true" : "false";
    json += ",\"decisive\":";
    json += decisive_hit ? "true" : "false";
    json += ",\"dataset_invalid\":";
    json += dataset_invalid ? "true" : "false";
    json += ",\"max_severity\":\"";
    json += to_string(max_severity);
    json += "\",\"elapsed_us\":";
    json += std::to_string(elapsed_us);
    json += ",\"findings\":[";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& finding = findings[i];
        if (i > 0) json += ',';
        json += "{\"id\":\"";
        json += json_escape(finding.id);
        json += "\",\"category\":\"";
        json += to_string(finding.category);
        json += "\",\"severity\":\"";
        json += to_string(finding.severity);
        json += "\",\"weight\":";
        json += std::to_string(finding.weight);
        json += ",\"decisive\":";
        json += finding.decisive ? "true" : "false";
        json += ",\"evidence\":\"";
        json += json_escape(finding.evidence);
        json += "\"}";
    }
    json += "]}";
    return json;
}

Report evaluate_policy(const Config& config, Findings findings, bool dataset_invalid) {
    Report report;
    report.dataset_invalid = dataset_invalid;
    report.findings = std::move(findings);

    if (dataset_invalid) {
        Finding tampered;
        tampered.id = "integrity.dataset";
        tampered.category = Category::Integrity;
        tampered.severity = Severity::High;
        tampered.weight = 60;
        tampered.evidence =
            "Verschluesseltes Zusatz-Dataset konnte nicht authentifiziert werden";
        report.findings.push_back(std::move(tampered));
    }

    for (const Finding& finding : report.findings) {
        report.score += finding.weight;
        if (finding.severity > report.max_severity) report.max_severity = finding.severity;
        if (finding.decisive) report.decisive_hit = true;
    }

    const bool decisive_block = report.decisive_hit && config.block_on_decisive;
    const bool score_block = report.score >= config.score_threshold;
    report.blocked = decisive_block || score_block;

    if (decisive_block) {
        report.reason = "decisives Finding";
    } else if (score_block) {
        report.reason = "Score " + std::to_string(report.score) + " >= Schwelle " +
                        std::to_string(config.score_threshold);
    } else {
        report.reason = "Score " + std::to_string(report.score) + " < Schwelle " +
                        std::to_string(config.score_threshold);
    }
    return report;
}

}  // namespace aegis
