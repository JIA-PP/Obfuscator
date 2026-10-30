# Architektur

## Überblick

```
include/aegis/          öffentliche API (nur Header)
  guard.hpp             Guard-Klasse: evaluate / protect / watchdog
  config.hpp            Konfiguration, Profile, Aktionen
  finding.hpp           Finding, Severity, Category
  report.hpp            Report, Policy-Auswertung, JSON
  blob.hpp              verschlüsselte Zusatz-Datasets
  detect.hpp            die einzelnen Detektoren
  response.hpp          Beenden/Hinweis
  crypto/               fnv, xorstr, sha256, chacha20
src/
  core/                 Guard, Policy, Config, Response, Blob
  crypto/               Implementierungen (sha256, chacha20, xorstr_runtime)
  detect/               Detektoren
  data/                 generierte Signaturtabellen + Suchfunktionen
  platform/             Betriebssystem-Abstraktion (win / posix)
tools/
  aegis_tool.py         Tabellen- und Blob-Generator
  check_no_plaintext.py Klartext-Scanner für Build-Artefakte
  data/blacklist.json   Quelle aller Signaturen
examples/demo.cpp       CLI-Demo
tests/                  Unit-Tests
```

## Ablauf einer Prüfung

1. `Guard::evaluate()` kopiert die Konfiguration, entschlüsselt – falls
   vorhanden – das Zusatz-Dataset (AEAD) und mischt dessen Einträge ein.
2. Die Detektorliste wird der Reihe nach ausgeführt (günstige und eindeutige
   Checks zuerst). Jeder Detektor prüft selbst, ob er aktiviert ist, und hängt
   `Finding`s an. Ausnahmen werden abgefangen und – bei `fail_closed` – als
   schwaches Integritäts-Finding gewertet.
3. `evaluate_policy()` summiert die Gewichte, merkt sich die höchste Schwere
   und entscheidet:
   * `blocked = decisive_hit && block_on_decisive` **oder**
   * `blocked = score >= score_threshold`
4. `Guard::protect()` wertet aus und ruft bei Blockade
   `response::apply(action)` auf (beendet den Prozess, `noreturn`).
5. `Guard::start_watchdog()` wiederholt die Auswertung in einem
   Hintergrund-Thread mit zufälligem Jitter (±40 %) und beendet den Prozess,
   sobald ein Werkzeug **nach** dem Start auftaucht.

## Detektoren

| Datei | ID-Präfix | Inhalt |
|---|---|---|
| `detect/debugger.cpp` | `dbg.*` | PEB, NtGlobalFlag, Heap-Flags, DebugPort/-Object/-Flags, DRx, RDTSC, TracerPid, Elternprozess, LD_PRELOAD/AUDIT |
| `detect/hypervisor.cpp` | `vm.cpuid.*` | CPUID-Bit, Vendor-Leaf, Interface-Signatur, CPU-Marke |
| `detect/analysis_tools.cpp` | `tool.process`, `vm.process` | Prozess-Scan, Kommandozeilen, VM-Gastprozesse |
| `detect/windows_enum.cpp` | `tool.window_*` | Fensterklassen und -titel |
| `detect/injected_modules.cpp` | `tool.module_*`, `tool.thread_name` | geladene Module, Thread-Namen |
| `detect/artifacts.cpp` | `vm.file`, `vm.registry_*`, `vm.pci_device`, `vm.mac_oui`, `vm.smbios`, `sandbox.file` | Dateien, Registry, PCI, MAC, Firmware |
| `detect/sandbox_env.cpp` | `sandbox.*` | Namen, Prozessanzahl, Container, Interaktion |
| `detect/hardware.cpp` | `hw.*` | Kerne, RAM, Uptime, Platte, Auflösung |
| `detect/timing.cpp` | `time.*` | Sleep-Dilatation, eingefrorene Uptime |
| `detect/api_hooks.cpp` | `integrity.*` | Inline-Hooks in ntdll, kernel32-Thunk |

## Gewichtung

| Schwere | Standardgewicht | Typische Verwendung |
|---|---|---|
| Info | 5 | Kontext (Allowlist, kein Input) |
| Low | 12 | schwache Heuristik (Namen, Kerne, Platte) |
| Medium | 22 | wahrscheinliche Analyseumgebung |
| High | 35 | deutliche Indizien (Registry, Firmware, MAC) |
| Critical | 60 | laufendes Werkzeug, Debugger, Hypervisor |

Ein `decisive`-Finding blockiert unabhängig vom Score. Das ist für
Werkzeug- und Debugger-Treffer richtig – dort gibt es keine sinnvollen
Fehlalarme (abgesehen von absichtlich laufenden Analyse-Tools auf dem
Entwickler-Rechner, die per `process_allowlist` ausgenommen werden).

## Plattform-Abstraktion

`src/platform/platform.hpp` deklariert alles Betriebssystem-Abhängige:
Prozessliste, eigener Prozess (Module, Threads, Pfad), Dateisystem,
Benutzer/Rechner, MAC-Adressen, Hardwarewerte, Zeit, letzte Eingabe,
Registry, SMBIOS, `/sys` und `/proc`.

Zwei Implementierungen:

* `platform_win.cpp` – Toolhelp-Snapshots, `QueryFullProcessImageNameW`,
  `NtQueryInformationProcess(ProcessCommandLineInformation)`,
  `GetThreadDescription`, `GetAdaptersAddresses`, `GetSystemFirmwareTable`
  (SMBIOS ohne WMI), `RegOpenKeyExW`/`RegEnumKeyExW`.
* `platform_posix.cpp` – `/proc/<pid>/{comm,cmdline,exe}`,
  `/proc/self/{status,maps,task,cgroup}`, `/sys/class/dmi/id/*`,
  `/sys/class/net/*/address`, `sysconf`, `statvfs`.

Dadurch sind die Detektoren plattformunabhängig und lassen sich unter Linux
testen, auch wenn das Ziel Windows ist.

## Signaturtabellen

Quelle ist `tools/data/blacklist.json`. `tools/aegis_tool.py gen-tables`
erzeugt daraus:

* `src/data/tables_generated.inc` – die eigentlichen Tabellen (kein Klartext)
* `docs/DETECTIONS.md` – menschenlesbare Dokumentation

Die CI prüft mit `gen-tables --check`, ob die generierten Dateien zum JSON
passen. Nach jeder Änderung an der JSON-Datei also:

```bash
python3 tools/aegis_tool.py gen-tables
```

### Hash-Tabellen

```cpp
// gespeichert:  hash ^ splitmix64(kHashMaskKey + index)
{0x7CA2E10CB43DA565ULL, ToolCategory::Instrumentation},
```

Verglichen wird mit `crypto::normalize_name_hash(name)`: Kleinschreibung,
Pfadanteil entfernen, bekannte Endungen (`.exe`, `.dll`, `.so`, …) entfernen,
alles ab `#`/`:` abschneiden. Dieselbe Funktion existiert im Python-Tool
(`normalize_hash`), was durch einen Test abgesichert ist.

### Text-Tabellen

```cpp
static const std::uint8_t kText_vm_identifiers_0[] = { 0x… };  // XOR-Chiffrat
static const TextEntry kTable_vm_identifiers[] = { { kText…, 6, 0x…ULL } };
```

`data::DecodedText` entschlüsselt in einen Stack-Puffer und nullt ihn im
Destruktor. `data::contains_any()` / `equals_any()` suchen darin.

## Krypto

* `crypto/fnv.hpp` – FNV-1a 64, SplitMix64, Namens-Normalisierung (`constexpr`,
  identisch in Python implementiert).
* `crypto/xorstr.hpp` + `src/crypto/xorstr_runtime.cpp` – compile-zeit
  verschlüsselte Literale.
* `crypto/sha256.cpp` – SHA-256 und HMAC-SHA-256 (FIPS 180-4, RFC 2104).
* `crypto/chacha20.cpp` – ChaCha20 (RFC 8439) und Encrypt-then-MAC:
  `enc_key = SHA256(key ‖ "aegis/aead/v1/enc")`, `mac_key = SHA256(key ‖ …/mac")`,
  `tag = HMAC-SHA256(mac_key, SHA256(ad ‖ nonce ‖ ciphertext))[0..15]`.
  Getestet gegen Referenzwerte; die Python-Seite erzeugt kompatible Blobs
  (Interoperabilitätstest in `tests/test_blob.cpp`).

### Warum die eigene Übersetzungseinheit für `decrypt_byte`?

GCC faltet bei `-O2`/`-O3` über Funktions- und Dateigrenzen hinweg
(IPA-Konstantenpropagierung) und ersetzt die Entschlüsselung durch einen
Vergleich mit dem Klartext – der Klartext landet dann doch im Binary. Deshalb:

* Implementierung in eigener `.cpp` (ohne LTO sichtbar getrennt),
* `__attribute__((noipa))` (GCC ≥ 9), `noinline`,
* `volatile` für Chiffrat und Zwischenwert,
* leere Assembler-Barriere `asm volatile("" : "+r"(x))`.

Verifiziert durch `tools/check_no_plaintext.py` in der CI.

## Erweiterung

Neuer Detektor:

1. Funktion in `include/aegis/detect.hpp` deklarieren.
2. In `src/detect/…cpp` implementieren (`add(out, present, "id", …)`).
3. In `src/core/guard.cpp` in `kDetectors` eintragen.
4. Wenn eigene Signaturen nötig sind: in `tools/data/blacklist.json`
   ergänzen und `gen-tables` ausführen.

Neue Signatur-Kategorie: JSON-Schlüssel anlegen und in
`tools/aegis_tool.py` (Liste `TEXT_LIST_KEYS`) sowie in
`src/data/tables.hpp/.cpp` ergänzen.
