// SPDX-License-Identifier: MIT
// AEGIS Guard - response.hpp
//
// Reaktion auf ein positives Ergebnis.
//
// Wichtig: Die Reaktion wird bewusst NUR auf den eigenen Prozess angewendet.
// Es werden keine fremden Prozesse beendet, keine Dateien geloescht und keine
// Systemzustaende veraendert.

#ifndef AEGIS_RESPONSE_HPP
#define AEGIS_RESPONSE_HPP

#include <cstdint>

#include "aegis/config.hpp"

namespace aegis::response {

/// Beendet den aktuellen Prozess "hart": TerminateProcess() unter Windows,
/// _exit()/SIGKILL unter POSIX. Kehrt nie zurueck.
[[noreturn]] void hard_terminate(int exit_code) noexcept;

/// Beendet den Prozess regulaer ueber die Plattform-API.
[[noreturn]] void clean_exit(int exit_code) noexcept;

/// Zeigt einen Hinweis an (MessageBox unter Windows, stderr unter POSIX).
void notify(const char* title, const char* body) noexcept;

/// Kurz warten (fuer die Reaktion, z. B. damit Logs noch geschrieben werden).
void sleep_ms(unsigned milliseconds) noexcept;

/// Fuehrt die in `config.action` konfigurierte Reaktion aus. Kehrt nur bei
/// Action::None zurueck.
void apply(const Config& config) noexcept;

}  // namespace aegis::response

#endif  // AEGIS_RESPONSE_HPP
