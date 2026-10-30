// SPDX-License-Identifier: MIT
// AEGIS Guard - guard.hpp
//
// Zentrale Klasse. Typische Verwendung:
//
//     #include "aegis/aegis.hpp"
//
//     int main() {
//         aegis::Guard guard;          // Standardprofil
//         guard.protect();             // prueft, beendet sich bei Verdacht
//         ...
//         guard.start_watchdog();      // ueberwacht weiter im Hintergrund
//         run_application();
//     }
//
// `protect()` kehrt nur zurueck, wenn kein blockierender Befund vorliegt.

#ifndef AEGIS_GUARD_HPP
#define AEGIS_GUARD_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "aegis/config.hpp"
#include "aegis/report.hpp"

namespace aegis {

class Guard {
public:
    /// Standardkonstruktor nutzt Config::balanced().
    Guard();
    explicit Guard(Config config);

    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;

    ~Guard();

    /// Fuehrt alle aktivierten Detektoren aus. Veraendert nichts.
    Report evaluate();

    /// Prueft und reagiert (siehe Config::action). Gibt true zurueck, wenn die
    /// Anwendung weiterlaufen darf. Kann den Prozess beenden (noreturn-Pfad).
    bool protect();

    /// Wie protect(), aber mit Zugriff auf den Report (z. B. fuer Logging).
    bool protect(Report* out_report);

    /// Laedt ein verschluesseltes Dataset und mischt dessen Eintraege in die
    /// Konfiguration. Gibt false zurueck, wenn Authentifizierung fehlschlaegt.
    bool add_dataset(const EncryptedDataset& dataset);

    /// Startet die zyklische Hintergrundpruefung. `on_block` wird vor der
    /// Reaktion aufgerufen (optional, z. B. fuer Logging).
    void start_watchdog(std::function<void(const Report&)> on_block = {});
    void stop_watchdog();
    bool watchdog_running() const noexcept;

    Config& config() noexcept { return config_; }
    const Config& config() const noexcept { return config_; }

    static const char* version() noexcept;

private:
    void watchdog_loop(std::function<void(const Report&)> on_block);

    Config config_;
    std::atomic<bool> running_{false};
    std::thread worker_;
};

/// Einmalige Pruefung ohne Guard-Objekt (Convenience fuer sehr kleine Programme).
bool protect_once(const Config& config = Config::balanced(), Report* out_report = nullptr);

}  // namespace aegis

#endif  // AEGIS_GUARD_HPP
