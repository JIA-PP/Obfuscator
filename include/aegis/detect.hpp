// SPDX-License-Identifier: MIT
// AEGIS Guard - detect.hpp
//
// Einzelne Detektoren. Jeder Detektor ist eine freie Funktion, die die
// Konfiguration liest und Findings anhaengt. Dadurch sind Detektoren
// einzeln testbar und lassen sich in eigenen Werkzeugen wiederverwenden.

#ifndef AEGIS_DETECT_HPP
#define AEGIS_DETECT_HPP

#include "aegis/config.hpp"
#include "aegis/finding.hpp"

namespace aegis::detect {

/// CPUID: Hypervisor-Bit, Vendor-Leaf, Marken-String.
void hypervisor(const Config& config, Findings& out);

/// CPU-Kerne, RAM, Uptime, Datentraeger, Bildschirm.
void hardware(const Config& config, Findings& out);

/// Dateien, Registry, MAC-OUI, DMI/SMBIOS, Geraete.
void artifacts(const Config& config, Findings& out);

/// Benutzer-/Rechnernamen, Sandbox-DLLs, Prozessanzahl, Interaktion.
void sandbox_environment(const Config& config, Findings& out);

/// Laufende Reverse-Engineering-Werkzeuge (Kernfunktion).
void analysis_tools(const Config& config, Findings& out);

/// Fensterklassen und -titel.
void windows_enum(const Config& config, Findings& out);

/// Debugger am eigenen Prozess (PEB, NtQueryInformationProcess, DRx, Timing).
void debugger(const Config& config, Findings& out);

/// Zeitraffer / Zeitmanipulation.
void timing(const Config& config, Findings& out);

/// Inline-Hooks in ntdll/kernel32 (optional, FP-anfaellig).
void api_hooks(const Config& config, Findings& out);

/// Fremde Module im eigenen Prozess (Frida, ScyllaHide, ...).
void injected_modules(const Config& config, Findings& out);

}  // namespace aegis::detect

#endif  // AEGIS_DETECT_HPP
