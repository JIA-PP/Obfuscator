// SPDX-License-Identifier: MIT
// AEGIS Guard - Beispielprogramm.
//
// Zeigt drei Betriebsarten:
//   1. Bericht   (Standard): alle Checks laufen, nichts wird beendet.
//   2. Schutz    (--protect): wie in einer echten Anwendung - bei Verdacht
//                wird der Prozess sofort beendet.
//   3. Wachhund  (--watchdog 20): prueft zyklisch im Hintergrund und beendet
//                den Prozess, wenn spaeter ein Analyse-Werkzeug startet.
//
// Beispiele:
//   ./aegis_demo                      # Bericht
//   ./aegis_demo --json               # Bericht als JSON
//   ./aegis_demo --profile aggressive # strengere Schwellen
//   ./aegis_demo --watchdog 15        # 15 s ueberwachen
//   ./aegis_demo --protect            # echte Schutzreaktion

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "aegis/aegis.hpp"

namespace {

void print_usage() {
    std::printf(
        "AEGIS Guard %s - Demo\n"
        "\n"
        "  --report              Bericht ausgeben (Standard)\n"
        "  --json                Bericht als JSON\n"
        "  --quiet               nur Ergebniszeile\n"
        "  --protect             Schutzreaktion ausfuehren (beendet den Prozess!)\n"
        "  --watchdog <sekunden> nach dem Start zyklisch weiterpruefen\n"
        "  --interval <ms>       Watchdog-Intervall (Standard 4000)\n"
        "  --profile <name>      relaxed | balanced | aggressive\n"
        "  --action <name>       none | exit | exitcode | terminate | message\n"
        "  --allow-hypervisor <vendor>  z. B. \"Microsoft Hv\" fuer VBS/WSL2\n"
        "  --allow-process <name>       Prozess von der Werkzeugliste ausnehmen\n"
        "  --extra-process <name>       weiteren Werkzeugnamen pruefen\n"
        "  --simulate <severity> critical|high|medium|low  (synthetischer Befund)\n"
        "  --ignore-vm          VM-/Sandbox-/Timing-Checks aus (Demo auf echten Hosts)\n"
        "  --version             Version ausgeben\n"
        "  --help                diese Hilfe\n",
        aegis::Guard::version());
}

aegis::Action parse_action(const std::string& name, bool& ok) {
    ok = true;
    if (name == "none") return aegis::Action::None;
    if (name == "exit") return aegis::Action::ExitClean;
    if (name == "exitcode") return aegis::Action::ExitCode;
    if (name == "terminate") return aegis::Action::Terminate;
    if (name == "message") return aegis::Action::MessageThenExit;
    ok = false;
    return aegis::Action::Terminate;
}

aegis::Severity parse_severity(const std::string& name) {
    if (name == "critical") return aegis::Severity::Critical;
    if (name == "high") return aegis::Severity::High;
    if (name == "medium") return aegis::Severity::Medium;
    return aegis::Severity::Low;
}

}  // namespace

int main(int argc, char** argv) {
    aegis::Config config = aegis::Config::balanced();
    bool as_json = false;
    bool quiet = false;
    bool protect = false;
    unsigned watchdog_seconds = 0;
    std::string simulate;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const bool has_value = (i + 1 < argc);

        if (argument == "--help" || argument == "-h") {
            print_usage();
            return 0;
        }
        if (argument == "--version") {
            std::printf("AEGIS Guard %s\n", aegis::Guard::version());
            return 0;
        }
        if (argument == "--json") {
            as_json = true;
        } else if (argument == "--quiet") {
            quiet = true;
        } else if (argument == "--protect") {
            protect = true;
        } else if (argument == "--watchdog" && has_value) {
            watchdog_seconds = static_cast<unsigned>(std::stoul(argv[++i]));
        } else if (argument == "--interval" && has_value) {
            config.watchdog_interval_ms = static_cast<unsigned>(std::stoul(argv[++i]));
        } else if (argument == "--profile" && has_value) {
            const std::string profile = argv[++i];
            if (profile == "relaxed") config = aegis::Config::relaxed();
            else if (profile == "aggressive") config = aegis::Config::aggressive();
            else config = aegis::Config::balanced();
        } else if (argument == "--action" && has_value) {
            bool ok = false;
            config.action = parse_action(argv[++i], ok);
            if (!ok) {
                std::fprintf(stderr, "Unbekannte Aktion\n");
                return 2;
            }
        } else if (argument == "--allow-hypervisor" && has_value) {
            config.hypervisor_allowlist.emplace_back(argv[++i]);
        } else if (argument == "--allow-process" && has_value) {
            config.process_allowlist.emplace_back(argv[++i]);
        } else if (argument == "--extra-process" && has_value) {
            config.extra_processes.emplace_back(argv[++i]);
        } else if (argument == "--ignore-vm") {
            // Fuer Vorfuehrungen in einer echten VM: nur Werkzeug-/Debugger-Checks.
            config.check_hypervisor = false;
            config.check_hardware = false;
            config.check_artifacts = false;
            config.check_sandbox_env = false;
            config.check_timing = false;
            config.check_container = false;
        } else if (argument == "--simulate" && has_value) {
            simulate = argv[++i];
        } else if (argument == "--report") {
            // Standardverhalten
        } else {
            std::fprintf(stderr, "Unbekannte Option: %s (--help fuer Hilfe)\n", argument.c_str());
            return 2;
        }
    }

    aegis::Guard guard(config);

    // Synthetischer Befund, um die Entscheidungslogik zu zeigen.
    if (!simulate.empty()) {
        aegis::Findings findings;
        const aegis::Severity severity = parse_severity(simulate);
        aegis::add(findings, true, "simulated.finding", aegis::Category::AnalysisTool, severity,
                   aegis::default_weight(severity), "synthetischer Befund (--simulate)", false);
        const aegis::Report report = aegis::evaluate_policy(config, findings);
        std::printf("%s", as_json ? (report.to_json() + "\n").c_str() : report.summary().c_str());
        if (protect && report.blocked) aegis::response::apply(config);
        return report.blocked ? 1 : 0;
    }

    if (protect) {
        // Echte Anwendung: bei Verdacht wird der Prozess beendet.
        std::printf("AEGIS Guard %s - Schutzmodus\n", aegis::Guard::version());
        aegis::Report report;
        if (!guard.protect(&report)) return 1;  // nicht erreichbar bei Terminate
    }

    const aegis::Report report = guard.evaluate();

    if (as_json) {
        std::printf("%s\n", report.to_json().c_str());
    } else if (quiet) {
        std::printf("%s (%d Punkte, Schwelle %d)\n", report.blocked ? "BLOCKIERT" : "OK",
                    report.score, config.score_threshold);
    } else {
        std::printf("%s", report.summary().c_str());
        std::printf("  Laufzeit: %llu us\n",
                    static_cast<unsigned long long>(report.elapsed_us));
    }

    if (watchdog_seconds > 0) {
        std::printf("\nWachhund aktiv fuer %u s - jetzt ein Analyse-Werkzeug starten ...\n",
                    watchdog_seconds);
        guard.start_watchdog([](const aegis::Report& blocked) {
            std::printf("\nWachhund: %s\n", blocked.summary().c_str());
            std::fflush(stdout);
        });

        const unsigned total_ms = watchdog_seconds * 1000;
        for (unsigned elapsed = 0; elapsed < total_ms; elapsed += 500) {
            aegis::response::sleep_ms(500);
            std::printf(".");
            std::fflush(stdout);
        }
        guard.stop_watchdog();
        std::printf("\nWachhund beendet - kein weiterer Befund.\n");
    }

    return report.blocked ? 1 : 0;
}
