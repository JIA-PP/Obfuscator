// SPDX-License-Identifier: MIT
// Fremde Module und Threads im eigenen Prozess.
//
// Wenn ein Analyse-Werkzeug bereits laeuft, ist es oft schon im Zielprozess:
//   * frida-agent-64.dll / frida-agent-64.so  (dynamische Instrumentierung)
//   * ScyllaHide*.dll                          (Anti-Anti-Debug-Plugin)
//   * Sandbox-DLLs (SbieDll, cmdvrt32, api_log ...)
//   * Threads mit GLib-/Gum-Namen ("gum-js-loop", "gmain", "gdbus")
//     sind ein sehr spezifischer Frida-Hinweis.

#include "aegis/detect.hpp"

#include <string>
#include <vector>

#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {
namespace {

bool thread_looks_like_instrumentation(const std::string& name) {
    if (name.empty()) return false;
    std::size_t count = 0;
    const data::TextEntry* table = data::instrumentation_threads(count);
    return data::contains_any(table, count, name.c_str());
}

}  // namespace

void injected_modules(const Config& config, Findings& out) {
    if (!config.check_injected_modules) return;

    std::size_t analysis_count = 0;
    std::size_t sandbox_count = 0;
    const data::NameEntry* analysis_table = data::analysis_modules(analysis_count);
    const data::NameEntry* sandbox_table = data::sandbox_modules(sandbox_count);

    const std::vector<std::string> modules = platform::list_own_modules();

    for (const std::string& module : modules) {
        if (module.empty()) continue;
        const std::uint64_t hash = crypto::normalize_name_hash(module);

        bool extra = false;
        for (const std::string& configured : config.extra_modules) {
            if (crypto::normalize_name_hash(configured) == hash) {
                extra = true;
                break;
            }
        }

        if (const data::NameEntry* entry = data::find_name(analysis_table, analysis_count, hash)) {
            add(out, true, "tool.module_loaded", Category::AnalysisTool, Severity::Critical, 55,
                platform::format("Analyse-Modul '%s' (%s) im Prozess geladen", module.c_str(),
                                 data::to_string(entry->category)),
                /*decisive=*/true);
        } else if (data::find_name(sandbox_table, sandbox_count, hash) != nullptr) {
            add(out, true, "sandbox.module_loaded", Category::Sandbox, Severity::High, 40,
                platform::format("Sandbox-Modul '%s' im Prozess geladen", module.c_str()));
        } else if (extra) {
            add(out, true, "tool.module_extra", Category::AnalysisTool, Severity::Critical, 55,
                platform::format("Konfiguriertes Modul '%s' im Prozess geladen", module.c_str()),
                /*decisive=*/true);
        }
    }

    if (config.scan_thread_names) {
        for (const std::string& thread : platform::list_own_thread_names()) {
            if (thread_looks_like_instrumentation(thread)) {
                add(out, true, "tool.thread_name", Category::AnalysisTool, Severity::High, 45,
                    platform::format("Verdaechtiger Threadname '%s' (Instrumentierungs-Laufzeit)",
                                     thread.c_str()));
            }
        }
    }
}

}  // namespace aegis::detect
