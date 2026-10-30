# Integration in eine eigene Anwendung

## 1. Minimale Variante

```cpp
#include "aegis/aegis.hpp"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    aegis::Guard guard;      // Config::balanced()
    guard.protect();         // beendet sich bei Verdacht
    return run_application();
}
```

`protect()` gibt `true` zurück, wenn nichts gefunden wurde. Bei einer
Blockade wird der Prozess gemäß `config.action` beendet – die Funktion kehrt
dann nicht zurück (außer bei `Action::None`).

## 2. Mit eigener Reaktion und Protokollierung

```cpp
aegis::Config config = aegis::Config::balanced();
config.action = aegis::Action::MessageThenExit;
config.message_title = "MeinProgramm";
config.message_body  = "Dieses Programm läuft nicht in einer virtuellen Maschine.";

aegis::Guard guard(config);

aegis::Report report;
if (!guard.protect(&report)) {
    return 1;                       // nur bei Action::None erreichbar
}
log_debug(report.summary());        // optional: eigenes Log
```

`report.to_json()` liefert eine maschinenlesbare Variante für Support-Tickets
oder Telemetrie (an anderer Stelle prüfen, ob das datenschutzrechtlich
zulässig ist).

## 3. Watchdog (Werkzeug startet nach dem Programmstart)

```cpp
guard.start_watchdog([](const aegis::Report& report) {
    // läuft unmittelbar vor der Reaktion (z. B. Log schreiben)
    write_log(report.summary());
});

// ... Hauptschleife ...

guard.stop_watchdog();   // beim Beenden
```

Das Intervall ist `config.watchdog_interval_ms` (Standard 4000 ms) mit ±40 %
Jitter. Der Thread kostet pro Prüfung je nach Profil 1–40 ms (der
Timing-Check ist der teuerste; mit `config.timing_sleep_ms = 0` entfällt er).

## 4. Zusatz-Signaturen ohne Neukompilieren der Tabelle

```bash
python3 tools/aegis_tool.py gen-blob --input tools/data/meine_tools.txt \
                                    --output generated/meine_tools.hpp
```

`tools/data/meine_tools.txt`:

```
process<tab>mein_analysetool
window_title<tab>MeinAnalyseFenster
module<tab>mein_hook
file<tab>C:\Tools\mein_tool.exe
```

```cpp
#include "generated/meine_tools.hpp"
guard.add_dataset(aegis::data::kDataset);
```

Der Blob ist ChaCha20-verschlüsselt und HMAC-authentifiziert. Wird er
manipuliert, liefert `Guard::evaluate()` `dataset_invalid = true` (und die
Policy blockiert).

## 5. Build-Details

### MSVC

* C++17 (`/std:c++17`), Linkung gegen `advapi32.lib`, `iphlpapi.lib`
  (erledigt `CMakeLists.txt` automatisch).
* Empfehlung Release: `/O2 /GL` (LTO) ist unkritisch, weil die
  Entschlüsselung in einer eigenen Übersetzungseinheit liegt und durch
  Assembler-Barrieren geschützt ist.
* Als GUI-Anwendung ohne Konsole: `set_target_properties(app PROPERTIES
  WIN32_EXECUTABLE TRUE)`; die Reaktion `MessageThenExit` nutzt dann
  `MessageBoxA`.
* `/GS`, `/DYNAMICBASE`, `/NXCOMPAT` können aktiv bleiben.

### MinGW / Clang-Cross

```
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Iinclude -Isrc src/**/*.cpp \
    src/platform/platform_win.cpp app.cpp -o app.exe -ladvapi32 -liphlpapi
```

### Linux

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j && ctest --test-dir build
```

## 6. Reihenfolge im Programmstart

1. `Guard` konstruieren (vor `main`, wenn möglich in `main` ganz oben).
2. `add_dataset(...)`, falls verwendet.
3. `protect()` – **vor** dem Laden von Konfiguration/Lizenzen.
4. Erst danach Anwendungslogik.
5. `start_watchdog()` nach der Initialisierung.

Ein früher Aufruf ist wichtig: läuft bereits ein Debugger, soll das Programm
gar nicht erst Initialisierungscode ausführen.

## 7. Typische Fehlalarme

| Symptom | Ursache | Lösung |
|---|---|---|
| Blockade auf Windows 11 | VBS/Credential Guard setzt das Hypervisor-Bit | `config.hypervisor_allowlist = {"Microsoft Hv"}` |
| Blockade im Firmennetz | EDR patcht ntdll | `check_api_hooks = false` (Standard) |
| Blockade auf Build-Servern | Container/CI erkannt | `check_container = false` |
| Blockade beim Entwickler | Wireshark/IDA/x64dbg läuft | `process_allowlist` oder Profil `relaxed` |
| Blockade in WSL2 | Hypervisor-Bit + Container | `hypervisor_allowlist` + `check_container = false` |
| Start dauert ~1,2 s | Timing-Check (`timing_sleep_ms`) | `timing_sleep_ms = 0` oder `1200` beibehalten |

## 8. Debugging während der Entwicklung

```cpp
aegis::Config config = aegis::Config::relaxed();
config.action = aegis::Action::None;      // nur Bericht
config.check_debugger = false;
```

Oder als Umgebungsvariable im eigenen Code:

```cpp
if (std::getenv("MEINEAPP_NO_AEGIS") != nullptr) return run_application();
```

**Achtung:** Ein solcher Schalter ist im ausgelieferten Binary ein
Bypass-Vektor. Nur in Debug-Builds (`#ifndef NDEBUG`) einbauen.

## 9. Selbsttest der Integration

```bash
./app --aegis-report          # eigener Schalter, der report.summary() ausgibt
```

Unter Linux lässt sich die Erkennung gut mit einer VM (KVM/QEMU) testen;
unter Windows mit Hyper-V, VMware oder VirtualBox. Für die Werkzeug-Erkennung
genügt es, während der Laufzeit z. B. den Process Monitor zu starten.
