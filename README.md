# AEGIS Guard

Anti-Analyse-Schutzmodul für C++-Anwendungen (Windows und Linux).

Das Modul prüft beim Start (und optional zyklisch im Hintergrund), ob das
Programm in einer **virtuellen Maschine**, einer **Sandbox** oder unter einem
**Debugger / Reverse-Engineering-Werkzeug** läuft – und beendet dann den
eigenen Prozess. Alle Prüf-Muster (Werkzeugnamen, VM-Artefakte, Pfade,
Fenstertitel) liegen **verschlüsselt bzw. gehasht** im Binary.

```
AEGIS Guard 1.0.0  Score: 97  Ergebnis: BLOCKIERT (decisives Finding)
  [critical + 60] vm.cpuid.vendor       Hypervisor-Vendor: KVMKVMKVM
  [medium   + 25] vm.cpuinfo_hypervisor CPU-Flags enthalten 'hypervisor'
  [low      + 12] hw.disk               20 GB Datenträger (< 40)
  Begründung: decisives Finding
```

---

## 1. Features

| Bereich | Umsetzung |
|---|---|
| **VM-Erkennung** | CPUID-Hypervisor-Bit + Vendor (VMware, VirtualBox, KVM, Hyper-V, Xen, QEMU/TCG, bhyve, Parallels, ACRN), CPU-Marken-String, SMBIOS/DMI, Registry-Schlüssel/-Werte, PCI-Geräte-IDs, MAC-OUIs, Gast-Treiber/-Dateien |
| **Sandbox-Erkennung** | Sandbox-DLLs (SbieDll, cmdvrt32, api_log …), Benutzer-/Rechnernamen, Prozessanzahl, Container (Docker/Kubernetes/LXC), CI-Variablen, optionale Interaktionsprüfung |
| **Reverse-Engineering-Werkzeuge** | Prozess-Scan gegen ~166 Signaturen (Namens-Hashes), Fensterklassen/-titel, geladene Module im eigenen Prozess, Kommandozeilen von Host-Prozessen (python/java/node), Frida-Thread-Namen |
| **Debugger** | PEB\->BeingDebugged, NtGlobalFlag, Heap-Flags, CheckRemoteDebuggerPresent, NtQueryInformationProcess (DebugPort/DebugObject/DebugFlags), Hardware-Breakpoints, RDTSC-Timing, `TracerPid`/Elternprozess (Linux) |
| **Anti-Timing** | Sleep-Dilatation, eingefrorene System-Uptime |
| **Integrität** | Inline-Hooks in ntdll (optional), authentifizierte Konfigurations-Blobs, LD_PRELOAD/LD_AUDIT |
| **Verschlüsselung** | Compile-Zeit-verschlüsselte String-Literale (`AEGIS_STR`), maskierte FNV-Hash-Tabellen, XOR-Chiffrat-Tabellen, ChaCha20 + HMAC-SHA-256 für Zusatz-Datasets |
| **Reaktion** | `None` (nur Bericht), `ExitClean`, `ExitCode`, `Terminate` (hart), `MessageThenExit` |
| **Watchdog** | Hintergrund-Thread mit Zufalls-Jitter; beendet den Prozess, wenn **später** ein Werkzeug startet |

Erkannt werden u. a. IDA Pro, x64dbg/x32dbg, Ghidra, radare2, Rizin, Cutter,
Binary Ninja, Hopper, RetDec, WinDbg/WinDbg Preview/cdb/kd, GDB/gdbserver,
LLDB, rr, Frida, dnSpy, dnSpyEx, ILSpy, dotPeek, JustDecompile, .NET Reflector,
ILDASM/monodis, angr, Wireshark/tshark/dumpcap, HTTP Debugger, Fiddler,
mitmproxy, Charles, Burp Suite, API Monitor, OllyDbg, Immunity Debugger,
HyperDbg, msvsmon/vsjitdebugger, Cheat Engine, Process Hacker/System Informer,
Process Monitor/Explorer, Scylla, PE-bear, CFF Explorer, Detect It Easy, PEiD,
MegaDumper, ExtremeDumper, ReClass.NET, HxD/010 Editor, ScyllaHide, SharpOD,
Valgrind, strace/ltrace, edb, objdump, Intel Pin/DynamoRIO, Qiling, Speakeasy …

Die vollständige, automatisch generierte Liste steht in
[docs/DETECTIONS.md](docs/DETECTIONS.md).

---

## 2. Quickstart

```cpp
#include "aegis/aegis.hpp"

int main() {
    aegis::Config config = aegis::Config::balanced();
    config.action = aegis::Action::Terminate;   // Standard

    aegis::Guard guard(config);
    guard.protect();          // kehrt nur zurück, wenn alles sauber ist

    guard.start_watchdog();   // prüft weiter (Standard: alle ~4 s, mit Jitter)

    // ... eigene Anwendung ...
}
```

Bauen:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/aegis_demo            # Bericht (beendet nichts)
./build/aegis_demo --protect  # Schutzmodus (beendet sich bei Verdacht)
./build/aegis_demo --ignore-vm --watchdog 10 --interval 500   # Watchdog-Test
```

Einbinden in ein bestehendes CMake-Projekt:

```cmake
add_subdirectory(external/aegis)
target_link_libraries(MeineApp PRIVATE aegis)          # statische Bibliothek
target_include_directories(MeineApp PRIVATE external/aegis/include)
```

Ohne CMake: alle `src/**/*.cpp` der passenden Plattform
(`platform_win.cpp` bzw. `platform_posix.cpp`) mitkompilieren,
`include/` und `src/` in den Include-Pfad aufnehmen, unter Windows
`advapi32.lib` und `iphlpapi.lib` linken.

---

## 3. Wie es funktioniert

```
                    ┌──────────────────────────────────────────┐
   Config ─────────▶│  Guard::evaluate()                       │
                    │                                          │
                    │  debugger ─┐                             │
                    │  hypervisor├─▶ Findings (ID, Kategorie,  │
                    │  tools     │   Schwere, Gewicht, Beweis) │
                    │  windows   │                             │
                    │  modules   ├─▶ evaluate_policy()         │
                    │  artifacts │      Score ≥ Schwelle?      │
                    │  sandbox   │      decisive-Finding?      │
                    │  hardware  │            │                 │
                    │  timing    │            ▼                 │
                    │  hooks    ─┘        Report.blocked       │
                    └──────────────────────────────────────────┘
                                                 │
                                                 ▼
                                     response::apply() → Terminate
```

* Jeder Detektor liefert **Findings** mit Gewicht und Beweistext.
* Die Policy summiert die Gewichte und blockiert ab `score_threshold`
  (Standard 55) oder sofort bei einem **decisiven** Finding
  (laufendes Werkzeug, Debugger, bekannter Hypervisor).
* Fehler in einem Detektor werden – wenn `fail_closed` aktiv ist – als
  (schwaches) Integritäts-Finding gewertet und nie als „alles in Ordnung“.

Details: [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md),
Integration: [docs/INTEGRATION.md](docs/INTEGRATION.md).

### Detektoren einzeln schalten

```cpp
aegis::Config config;
config.check_api_hooks = true;         // ntdll-Hooks (AV/EDR-Fehlalarme möglich!)
config.check_user_interaction = true;  // Maus/Tastatur (Server-Fehlalarm!)
config.check_container = false;        // Container gelten als normal
config.hypervisor_allowlist = {"Microsoft Hv"};  // VBS/Credential Guard erlauben
config.process_allowlist = {"obs64"};            // nie als Werkzeug werten
config.extra_processes  = {"mein_analyse_tool"}; // eigene Signaturen
config.score_threshold = 70;
config.action = aegis::Action::MessageThenExit;
config.timing_sleep_ms = 0;            // Startzeit sparen
```

Profile: `Config::relaxed()` (nur eindeutige Treffer), `Config::balanced()`
(Standard), `Config::aggressive()` (maximal streng, mehr Fehlalarme).

---

## 4. Verschlüsselung der Prüfungen

Vier Ebenen, damit im Binary kein Klartext mehr steht:

1. **`AEGIS_STR("…")`** – Compile-Zeit-XOR mit per-Verwendungsstelle
   verschiedenem Schlüssel (`__LINE__`/`__COUNTER__`). Vergleiche laufen
   byteweise in Register; es entsteht kein Klartextpuffer.
   Die Entschlüsselung liegt bewusst in einer **eigenen Übersetzungseinheit**
   mit Assembler-Barriere, weil GCC bei `-O3` sonst Chiffrat und Schlüssel
   faltet und den Klartext wieder ins Binary schreibt.
2. **Maskierte FNV-1a-64-Hash-Tabellen** – alle Prozess-, Modul- und
   Fensterklassennamen. Gespeichert wird `hash ^ splitmix64(mask + index)`,
   zurückgerechnet erst zur Laufzeit. Ein `strings`-Scan findet nichts, ein
   Signatur-Scan auf Namen ebenfalls nicht.
3. **XOR-Chiffrat-Tabellen** – Dateipfade, Registry-Schlüssel, Fenstertitel,
   VM-/Sandbox-Marker, Tracer- und Thread-Namen. Sie werden pro Prüfung in
   einen flüchtigen Stack-Puffer entschlüsselt und danach genullt.
4. **ChaCha20 + HMAC-SHA-256 (Encrypt-then-MAC)** – optionale Zusatz-Datasets,
   die zur Build-Zeit erzeugt werden. Manipulation am Chiffrat oder falscher
   Kontext führt zu `dataset_invalid` und damit zur Blockade.

```bash
# Signaturen aus tools/data/blacklist.json neu erzeugen
python3 tools/aegis_tool.py gen-tables

# eigenes verschlüsseltes Zusatz-Dataset
python3 tools/aegis_tool.py gen-blob --input meine_liste.txt --output generated/blob.hpp
```

```cpp
#include "generated/blob.hpp"
guard.add_dataset(aegis::data::kDataset);   // vor protect() aufrufen
```

Verifiziert durch `tools/check_no_plaintext.py` (läuft als CTest mit):
das gebaute Beispiel enthält **keine** der Signaturen als ASCII-Klartext –
weder Prozessnamen (166) noch Fenstertitel (54) noch die 213 Text-Artefakte
(VM-Kennungen, Hypervisor-Vendoren, Container-Marker, Tracer-Namen) – unter
Linux und Windows geprüft.

> **Wichtig:** Das ist Verschleierung, keine Kryptographie gegen einen
> Angreifer, der den Schlüssel aus dem Binary extrahiert. Wer den Prozess
> debuggen kann, kann jeden lokalen Check aushebeln. Der Aufwand wird erhöht,
> nicht unendlich gemacht.

---

## 5. Reaktionen

| Aktion | Wirkung |
|---|---|
| `Action::None` | nur `Report` (für Tests, Protokollierung) |
| `Action::ExitClean` | `ExitProcess(0)` / `_exit(0)` – unauffällig |
| `Action::ExitCode` | `ExitProcess(exit_code)` |
| `Action::Terminate` | `TerminateProcess(GetCurrentProcess(), …)` bzw. `SIGKILL` – kein `atexit`, kein Cleanup |
| `Action::MessageThenExit` | Hinweisfenster (Windows) bzw. `stderr` + Exit |

Es werden **nur eigene Prozesse** beendet. Keine fremden Prozesse, keine
Datei-Löschung, keine Systemänderungen.

---

## 6. Tests

```bash
ctest --test-dir build --output-on-failure
```

* 36 Unit-Tests: SHA-256/HMAC/ChaCha20/AEAD gegen Referenzwerte,
  String-Verschlüsselung, Namens-Normalisierung, Hash-Tabellen,
  Fenstertitel-Matching, Policy-/Score-Logik, JSON-Ausgabe,
  Dataset-Parser, Python↔C++-Interoperabilität, Manipulationserkennung,
  echter Prozess-Scan (findet den Testprozess über die Zusatzliste),
  Allowlist, Detektoren „alles aus“ ⇒ keine Findings.
* `aegis_tables_up_to_date` – erkennt vergessene Regenerierung der Tabellen.
* `aegis_no_plaintext` – scannt das gebaute Beispiel nach Klartext-Signaturen.
* CI (`.github/workflows/build.yml`): Linux (GCC **und** Clang, `-Werror`),
  Windows (MSVC) inkl. Lauf der Tests, Demo und Artifact-Upload.

---

## 7. Fehlalarme vermeiden

| Check | Risiko | Empfehlung |
|---|---|---|
| Hypervisor-Bit | Windows 11 mit VBS/Credential Guard, WSL2, Hyper-V-Hosts | `hypervisor_allowlist = {"Microsoft Hv"}` |
| `check_api_hooks` | AV/EDR patcht ntdll legitim | standardmäßig aus |
| `check_user_interaction` | Server/Headless | standardmäßig aus |
| Sandbox-Benutzernamen | „test“, „user1“ | niedrig gewichtet, abschaltbar |
| Werkzeug-Erkennung | Entwickler-Rechner mit Wireshark/IDA | `process_allowlist`, oder Profil `relaxed` |

Auf einem Entwickler-Rechner mit installierten Analyse-Werkzeugen schlägt der
Schutz **bestimmungsgemäß** an. Vor dem Ausliefern testen:

```bash
./build/aegis_demo --profile balanced --action none   # Bericht ohne Reaktion
```

---

## 8. Grenzen und Rechtliches

* Anti-Analyse ist **dual-use**. Dieses Modul ist für Software-Schutz
  gedacht (Lizenz-/Tamper-Schutz, Verhinderung von Analyse auf
  Nicht-Zielsystemen). Es darf **nicht** dazu verwendet werden, Malware zu
  tarnen oder Analyse durch Sicherheitsforscher/AV-Hersteller zu behindern.
* Lokale Checks sind grundsätzlich umgehbar (Patch, Hook, Emulation). Wer
  echten Kopierschutz braucht, kommt um Server-Validierung nicht herum.
* Prozess-Scans lesen Kommandozeilen anderer Prozesse. Das ist lokal, aber
  datenschutzrechtlich relevant – siehe [docs/RECHTLICHES.md](docs/RECHTLICHES.md).
* Manche AV-Produkte stufen Anti-VM-/Anti-Debug-Code als verdächtig ein
  („HackTool“/„AntiVM“). Das ist bei signierter, dokumentierter Software
  meist über eine False-Positive-Meldung beim Hersteller lösbar.

Lizenz: [MIT](LICENSE)
