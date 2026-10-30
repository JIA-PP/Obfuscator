// SPDX-License-Identifier: MIT
#include "aegis/response.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "aegis/crypto/xorstr.hpp"
#include "platform/platform.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <csignal>
#include <unistd.h>
#endif

namespace aegis::response {
namespace {

/// Standardtext, verschluesselt abgelegt.
void default_message(char* title, std::size_t title_size, char* body, std::size_t body_size) {
    const auto title_literal = AEGIS_STR("AEGIS Guard");
    const auto body_literal = AEGIS_STR(
        "Dieses Programm kann in dieser Umgebung nicht ausgefuehrt werden.");
    const std::size_t title_length = title_size - 1 < title_literal.size() ? title_size - 1
                                                                          : title_literal.size();
    const std::size_t body_length = body_size - 1 < body_literal.size() ? body_size - 1
                                                                       : body_literal.size();
    for (std::size_t i = 0; i < title_length; ++i) title[i] = title_literal.decode(i);
    title[title_length] = '\0';
    for (std::size_t i = 0; i < body_length; ++i) body[i] = body_literal.decode(i);
    body[body_length] = '\0';
}

}  // namespace

void sleep_ms(unsigned milliseconds) noexcept { platform::sleep_ms(milliseconds); }

void notify(const char* title, const char* body) noexcept {
#if defined(_WIN32)
    ::MessageBoxA(nullptr, body, title, MB_ICONSTOP | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
#else
    std::fprintf(stderr, "%s: %s\n", title, body);
    std::fflush(stderr);
#endif
}

[[noreturn]] void hard_terminate(int exit_code) noexcept {
#if defined(_WIN32)
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(exit_code));
    // Fallback, falls TerminateProcess blockiert wurde.
    ::ExitProcess(static_cast<UINT>(exit_code));
#else
    // SIGKILL auf sich selbst: keine atexit-Handler, kein Flush, kein Core.
    ::kill(::getpid(), SIGKILL);
    ::_exit(exit_code);
#endif
    for (;;) {  // nicht erreichbar; unterdrueckt "noreturn"-Warnungen
    }
}

[[noreturn]] void clean_exit(int exit_code) noexcept {
#if defined(_WIN32)
    ::ExitProcess(static_cast<UINT>(exit_code));
#else
    ::_exit(exit_code);
#endif
}

void apply(const Config& config) noexcept {
    switch (config.action) {
        case Action::None:
            return;

        case Action::ExitClean:
            clean_exit(0);

        case Action::ExitCode:
            clean_exit(config.exit_code);

        case Action::Terminate:
            hard_terminate(config.exit_code);

        case Action::MessageThenExit: {
            char title[128];
            char body[512];
            default_message(title, sizeof(title), body, sizeof(body));
            if (!config.message_title.empty()) {
                std::snprintf(title, sizeof(title), "%s", config.message_title.c_str());
            }
            if (!config.message_body.empty()) {
                std::snprintf(body, sizeof(body), "%s", config.message_body.c_str());
            }
            notify(title, body);
            crypto::secure_zero(title, sizeof(title));
            crypto::secure_zero(body, sizeof(body));
            clean_exit(config.exit_code);
        }
    }
    hard_terminate(config.exit_code);
}

}  // namespace aegis::response
