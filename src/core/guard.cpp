// SPDX-License-Identifier: MIT
#include "aegis/guard.hpp"

#include <chrono>
#include <random>

#include "aegis/blob.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "aegis/detect.hpp"
#include "aegis/response.hpp"
#include "aegis/version.hpp"
#include "platform/platform.hpp"

namespace aegis {
namespace {

struct DetectorEntry {
    const char* id;
    void (*run)(const Config&, Findings&);
};

/// Reihenfolge: guenstige, eindeutige Checks zuerst.
constexpr DetectorEntry kDetectors[] = {
    {"debugger", &detect::debugger},
    {"hypervisor", &detect::hypervisor},
    {"analysis_tools", &detect::analysis_tools},
    {"windows", &detect::windows_enum},
    {"injected_modules", &detect::injected_modules},
    {"artifacts", &detect::artifacts},
    {"sandbox_env", &detect::sandbox_environment},
    {"hardware", &detect::hardware},
    {"timing", &detect::timing},
    {"api_hooks", &detect::api_hooks},
};

void merge_dataset(const DatasetEntries& entries, Config& config) {
    config.extra_processes.insert(config.extra_processes.end(), entries.processes.begin(),
                                  entries.processes.end());
    config.extra_modules.insert(config.extra_modules.end(), entries.modules.begin(),
                                entries.modules.end());
    config.extra_window_classes.insert(config.extra_window_classes.end(),
                                       entries.window_classes.begin(), entries.window_classes.end());
    config.extra_window_titles.insert(config.extra_window_titles.end(), entries.window_titles.begin(),
                                      entries.window_titles.end());
    config.extra_files.insert(config.extra_files.end(), entries.files.begin(), entries.files.end());
}

}  // namespace

Guard::Guard() : config_(Config::balanced()) {}
Guard::Guard(Config config) : config_(std::move(config)) {}

Guard::~Guard() { stop_watchdog(); }

const char* Guard::version() noexcept { return AEGIS_VERSION_STRING; }

bool Guard::add_dataset(const EncryptedDataset& dataset) {
    DatasetEntries entries;
    if (!load_dataset(dataset, entries)) {
        entries.clear();
        return false;
    }
    merge_dataset(entries, config_);
    entries.clear();
    config_.dataset = nullptr;  // bereits eingemischt
    return true;
}

Report Guard::evaluate() {
    const auto started = std::chrono::steady_clock::now();

    Config effective = config_;
    bool dataset_invalid = false;

    if (config_.dataset != nullptr && config_.dataset->loaded()) {
        DatasetEntries entries;
        if (load_dataset(*config_.dataset, entries)) {
            merge_dataset(entries, effective);
        } else {
            dataset_invalid = true;
        }
        entries.clear();
    }

    Findings findings;
    for (const DetectorEntry& detector : kDetectors) {
        try {
            detector.run(effective, findings);
        } catch (...) {
            if (effective.fail_closed) {
                add(findings, true, std::string("integrity.check_failed:") + detector.id,
                    Category::Integrity, Severity::Low, 8,
                    std::string("Detektor '") + detector.id + "' warf eine Ausnahme");
            }
        }
    }

    Report report = evaluate_policy(effective, std::move(findings), dataset_invalid);
    report.elapsed_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                             started)
            .count());
    return report;
}

bool Guard::protect(Report* out_report) {
    Report report = evaluate();
    if (out_report != nullptr) *out_report = report;
    if (!report.blocked) return true;

    response::apply(config_);
    return false;  // nur erreichbar bei Action::None
}

bool Guard::protect() { return protect(nullptr); }

void Guard::start_watchdog(std::function<void(const Report&)> on_block) {
    if (running_.exchange(true)) return;

    worker_ = std::thread([this, on_block = std::move(on_block)]() { watchdog_loop(on_block); });
}

void Guard::stop_watchdog() {
    if (!running_.exchange(false)) {
        if (worker_.joinable()) worker_.join();
        return;
    }
    if (worker_.joinable()) worker_.join();
}

bool Guard::watchdog_running() const noexcept { return running_.load(); }

void Guard::watchdog_loop(std::function<void(const Report&)> on_block) {
    std::mt19937_64 rng(static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^
                        reinterpret_cast<std::uintptr_t>(this));

    while (running_.load()) {
        // Wartezeit mit Jitter, damit kein erkennbares Zeitmuster entsteht.
        unsigned interval = config_.watchdog_interval_ms;
        if (config_.watchdog_jitter) {
            const unsigned spread = interval / 2;
            if (spread > 0) {
                const unsigned offset = static_cast<unsigned>(rng() % (spread * 2 + 1));
                interval = interval - spread + offset;
            }
        }
        if (interval == 0) interval = 1;

        // In kleinen Schritten schlafen, damit stop_watchdog() schnell greift.
        unsigned remaining = interval;
        while (remaining > 0 && running_.load()) {
            const unsigned slice = remaining > 100 ? 100 : remaining;
            platform::sleep_ms(slice);
            remaining -= slice;
        }
        if (!running_.load()) break;

        Report report = evaluate();
        if (report.blocked) {
            if (on_block) {
                try {
                    on_block(report);
                } catch (...) {
                    // Rueckruf darf die Reaktion nicht verhindern.
                }
            }
            response::apply(config_);
        }
    }
}

bool protect_once(const Config& config, Report* out_report) {
    Guard guard(config);
    return guard.protect(out_report);
}

}  // namespace aegis
