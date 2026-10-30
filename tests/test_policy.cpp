// SPDX-License-Identifier: MIT
#include <string>

#include "aegis/config.hpp"
#include "aegis/report.hpp"
#include "test_framework.hpp"

using namespace aegis;

namespace {

Finding make_finding(Category category, Severity severity, int weight, bool decisive = false) {
    Finding finding;
    finding.id = "test.finding";
    finding.category = category;
    finding.severity = severity;
    finding.weight = weight;
    finding.evidence = "Beispiel";
    finding.decisive = decisive;
    return finding;
}

}  // namespace

TEST_CASE(policy_score_unter_schwelle) {
    Config config;
    config.score_threshold = 50;
    config.block_on_decisive = true;

    Findings findings;
    findings.push_back(make_finding(Category::Hardware, Severity::Low, 20));
    findings.push_back(make_finding(Category::Environment, Severity::Low, 12));

    const Report report = evaluate_policy(config, findings);
    CHECK_EQ(report.score, 32);
    CHECK(!report.blocked);
    CHECK_EQ(report.max_severity, Severity::Low);
}

TEST_CASE(policy_score_ueber_schwelle) {
    Config config;
    config.score_threshold = 50;

    Findings findings;
    findings.push_back(make_finding(Category::Virtualization, Severity::High, 40));
    findings.push_back(make_finding(Category::Sandbox, Severity::Medium, 22));

    const Report report = evaluate_policy(config, findings);
    CHECK_EQ(report.score, 62);
    CHECK(report.blocked);
    CHECK(!report.decisive_hit);
}

TEST_CASE(policy_decisive_blockiert_sofort) {
    Config config;
    config.score_threshold = 1000;

    Findings findings;
    findings.push_back(make_finding(Category::AnalysisTool, Severity::Critical, 10, true));

    const Report report = evaluate_policy(config, findings);
    CHECK(report.blocked);
    CHECK(report.decisive_hit);

    config.block_on_decisive = false;
    const Report relaxed = evaluate_policy(config, findings);
    CHECK(!relaxed.blocked);
}

TEST_CASE(policy_dataset_manipulation) {
    Config config;
    config.score_threshold = 55;

    const Report report = evaluate_policy(config, {}, true);
    CHECK(report.dataset_invalid);
    CHECK(report.blocked);
    CHECK(report.has("integrity.dataset"));
}

TEST_CASE(report_json_und_summary) {
    Config config;
    config.score_threshold = 55;

    Findings findings;
    Finding tricky;
    tricky.id = "vm.test";
    tricky.category = Category::Virtualization;
    tricky.severity = Severity::High;
    tricky.weight = 35;
    tricky.evidence = "Pfad \"C:\\\\Tools\\x64dbg.exe\"";
    findings.push_back(tricky);

    const Report report = evaluate_policy(config, findings);
    const std::string json = report.to_json();

    CHECK(json.find("\"score\":35") != std::string::npos);
    CHECK(json.find("\"blocked\":false") != std::string::npos);
    CHECK(json.find("\"category\":\"virtualization\"") != std::string::npos);
    // Escaping muss gueltiges JSON erzeugen.
    CHECK(json.find("Pfad \\\"C:\\\\\\\\Tools\\\\x64dbg.exe\\\"") != std::string::npos);

    const std::string summary = report.summary();
    CHECK(summary.find("vm.test") != std::string::npos);
    CHECK(summary.find("Score: 35") != std::string::npos);
}

TEST_CASE(report_abfragen) {
    Findings findings;
    findings.push_back(make_finding(Category::Debugger, Severity::Critical, 70, true));
    Finding tool = make_finding(Category::AnalysisTool, Severity::Critical, 60);
    tool.id = "tool.process";
    findings.push_back(tool);

    const Report report = evaluate_policy(Config::balanced(), findings);

    CHECK(report.any(Category::Debugger));
    CHECK(report.any(Category::AnalysisTool));
    CHECK(!report.any(Category::Hardware));
    CHECK(report.has("tool."));
    CHECK(!report.has("vm."));
    CHECK_EQ(report.id_list(), std::string("test.finding;tool.process"));
}

TEST_CASE(profile_schwellen) {
    const Config relaxed = Config::relaxed();
    const Config balanced = Config::balanced();
    const Config aggressive = Config::aggressive();

    CHECK(relaxed.score_threshold >= balanced.score_threshold);
    CHECK(balanced.score_threshold > aggressive.score_threshold);

    CHECK(aggressive.check_api_hooks);
    CHECK(aggressive.check_user_interaction);
    CHECK(!balanced.check_api_hooks);
    CHECK(aggressive.min_ram_mb > balanced.min_ram_mb);
    CHECK(aggressive.strict_mode);
    CHECK(!balanced.strict_mode);
}
