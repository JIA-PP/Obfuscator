// SPDX-License-Identifier: MIT
// Fenstererkennung.
//
// Viele Analyse-Werkzeuge lassen sich umbenennen, aber ihre Fensterklasse
// (z. B. "WinDbgFrameClass", "OLLYDBG", "x64dbg") oder ihr Fenstertitel
// bleibt gleich. Unter Linux gibt es keine portable Fensterabfrage ohne
// zusaetzliche Abhaengigkeiten (X11/Wayland) - dort ist der Check leer.

#include "aegis/detect.hpp"

#include <string>

#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace aegis::detect {

#if defined(_WIN32)
namespace {

struct WindowScanContext {
    Findings* findings = nullptr;
    int hits = 0;
};

std::string narrow_window_text(const wchar_t* text, int length) {
    if (length <= 0) return std::string();
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, text, length, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return std::string();
    std::string out(static_cast<std::size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, length, &out[0], size, nullptr, nullptr);
    return out;
}

BOOL CALLBACK enum_window_proc(HWND window, LPARAM parameter) {
    auto* context = reinterpret_cast<WindowScanContext*>(parameter);
    if (context == nullptr || context->findings == nullptr) return TRUE;
    if (!::IsWindowVisible(window)) return TRUE;

    wchar_t class_name[256] = {};
    const int class_length = ::GetClassNameW(window, class_name, 255);
    wchar_t title[512] = {};
    const int title_length = ::GetWindowTextW(window, title, 511);

    if (class_length > 0) {
        const std::string name = platform::to_lower(narrow_window_text(class_name, class_length));
        std::size_t count = 0;
        const data::NameEntry* table = data::analysis_window_classes(count);
        if (table != nullptr && data::find_name(table, count, crypto::normalize_name_hash(name)) != nullptr) {
            add(*context->findings, true, "tool.window_class", Category::AnalysisTool,
                Severity::Critical, 65,
                platform::format("Fensterklasse '%s' gefunden", name.c_str()),
                /*decisive=*/true);
            ++context->hits;
        }
    }

    if (title_length > 0) {
        const std::string text = narrow_window_text(title, title_length);
        if (!text.empty()) {
            const data::TitleEntry* match = data::match_title(text.c_str());
            if (match != nullptr) {
                add(*context->findings, true, "tool.window_title", Category::AnalysisTool,
                    Severity::Critical, 65,
                    platform::format("Fenstertitel '%s' (%s)", text.c_str(),
                                     data::to_string(match->category)),
                    /*decisive=*/true);
                ++context->hits;
            }
            (void)match;
        }
    }

    // Nach einigen Treffern aufhoeren - wir brauchen keine Beweissammlung.
    return context->hits < 8 ? TRUE : FALSE;
}

}  // namespace
#endif

void windows_enum(const Config& config, Findings& out) {
    if (!config.check_windows) return;

#if defined(_WIN32)
    WindowScanContext context;
    context.findings = &out;
    ::EnumWindows(&enum_window_proc, reinterpret_cast<LPARAM>(&context));

    // Zusaetzliche, per Dataset/Config konfigurierte Titel-Muster.
    for (const std::string& pattern : config.extra_window_titles) {
        if (pattern.empty()) continue;
        struct ExtraContext {
            const std::string* pattern;
            Findings* findings;
            bool found;
        } extra{&pattern, &out, false};

        ::EnumWindows(
            [](HWND window, LPARAM parameter) -> BOOL {
                auto* state = reinterpret_cast<ExtraContext*>(parameter);
                wchar_t title[512] = {};
                const int length = ::GetWindowTextW(window, title, 511);
                if (length <= 0) return TRUE;
                const std::string text = narrow_window_text(title, length);
                if (platform::icontains(text, *state->pattern)) {
                    state->found = true;
                    return FALSE;
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&extra));

        if (extra.found) {
            add(out, true, "tool.window_title_extra", Category::AnalysisTool, Severity::Critical, 60,
                platform::format("Fenstertitel enthaelt '%s'", pattern.c_str()),
                /*decisive=*/true);
        }
    }
#else
    (void)out;
#endif
}

}  // namespace aegis::detect
