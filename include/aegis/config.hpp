// SPDX-License-Identifier: MIT
// AEGIS Guard - config.hpp
//
// Konfiguration von Detektion und Reaktion.
//
// Alle Schwellen sind bewusst konservativ voreingestellt (Profil "balanced"),
// damit ein normaler Endnutzer-Rechner nicht faelschlich gesperrt wird.
// Profil "aggressive" verschaerft die Heuristiken (fuer Software, die
// ausschliesslich auf echten Arbeitsplaetzen laufen soll).

#ifndef AEGIS_CONFIG_HPP
#define AEGIS_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "aegis/blob.hpp"

namespace aegis {

/// Was passiert, wenn ein Check anschlaegt?
enum class Action : std::uint8_t {
    None = 0,          ///< nur Bericht (Report), kein Eingriff
    ExitClean = 1,     ///< ExitProcess(0) - unauffaellig
    ExitCode = 2,      ///< ExitProcess(exit_code)
    Terminate = 3,     ///< TerminateProcess / SIGKILL (kein atexit, kein Cleanup)
    MessageThenExit = 4, ///< Hinweisfenster (bzw. stderr) + ExitCode
};

struct Config {
    // ---------------------------------------------------------------- Reaktion
    Action action = Action::Terminate;
    /// Exit-Code fuer ExitCode/Terminate. Hinweis: POSIX wertet nur die
    /// unteren 8 Bit aus (0x7E57 -> 87 im Shell-Status).
    int exit_code = 0x7E57;
    std::string message_title;  ///< leer => eingebauter, verschluesselter Text
    std::string message_body;

    // ---------------------------------------------------------------- Schwellen
    int score_threshold = 55;      ///< ab diesem Score wird blockiert
    bool block_on_decisive = true; ///< einzelnes "decisive" Finding blockiert sofort

    // ---------------------------------------------------------------- Detektoren
    bool check_hypervisor = true;    ///< CPUID-Hypervisor-Bit + Vendor
    bool check_hardware = true;      ///< CPU/RAM/Uptime/Platte
    bool check_artifacts = true;     ///< Dateien, Registry, MAC-OUI, DMI
    bool check_sandbox_env = true;   ///< Benutzer-/Rechnernamen, Sandbox-DLLs
    bool check_analysis_tools = true;///< laufende RE-Werkzeuge
    bool check_windows = true;       ///< Fensterklassen/-titel
    bool check_debugger = true;      ///< Debugger am eigenen Prozess
    bool check_timing = true;        ///< Zeitraffer / Sleep-Skew
    bool check_injected_modules = true; ///< fremde Module im eigenen Prozess
    bool check_api_hooks = false;    ///< Inline-Hooks in ntdll (FP durch AV/EDR!)
    bool check_user_interaction = false; ///< Maus-/Tastatur-Aktivitaet (Server-FP!)
    bool check_container = true;     ///< Container-/CI-Umgebung
    bool scan_command_lines = true;  ///< Kommandozeilen von Host-Prozessen
    bool scan_thread_names = true;   ///< Frida-Thread-Namen
    bool fail_closed = true;         ///< Fehler in einem Check => als Hinweis werten

    // ---------------------------------------------------------------- Tuning
    bool strict_mode = false;   ///< verschaerfte Schwellen (Profil "aggressive")

    /// Hypervisor-Vendor, der toleriert wird (z. B. "Microsoft Hv" fuer
    /// Windows-Hosts mit VBS/Credential Guard oder WSL2).
    std::vector<std::string> hypervisor_allowlist;

    /// Prozessnamen (normalisiert, ohne .exe), die niemals als Werkzeug gelten.
    std::vector<std::string> process_allowlist;

    unsigned min_cpu_cores = 2;
    unsigned min_ram_mb = 2048;
    unsigned min_uptime_seconds = 420;   ///< 7 Minuten
    unsigned min_process_count = 22;
    /// Dauer des Zeitraffer-Tests (0 = Test ueberspringen). Kostet Startzeit.
    unsigned timing_sleep_ms = 1200;
    unsigned long long min_disk_gb = 40;

    // ---------------------------------------------------------------- Zusatzdaten
    /// Optionales, verschluesseltes Dataset (siehe blob.hpp).
    const EncryptedDataset* dataset = nullptr;

    /// Zusaetzliche Namen (bereits entschluesselt) - von Guard aus dem
    /// Dataset befuellt oder manuell gesetzt.
    std::vector<std::string> extra_processes;
    std::vector<std::string> extra_modules;
    std::vector<std::string> extra_window_classes;
    std::vector<std::string> extra_window_titles;
    std::vector<std::string> extra_files;

    // ---------------------------------------------------------------- Watchdog
    bool watchdog_enabled = true;
    unsigned watchdog_interval_ms = 4000;
    bool watchdog_jitter = true;   ///< +/- 40 % Zufall, damit Muster nicht erkennbar

    // ---------------------------------------------------------------- Profile
    static Config relaxed();     ///< nur eindeutige VM-/Tool-Hinweise
    static Config balanced();    ///< Standard
    static Config aggressive();  ///< maximal streng, mehr Fehlalarme

    /// Setzt die Schwellen passend zu `strict_mode`.
    void apply_profile();
};

}  // namespace aegis

#endif  // AEGIS_CONFIG_HPP
