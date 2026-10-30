# Rechtliche und ethische Hinweise

Diese Datei ist keine Rechtsberatung. Sie beschreibt die Grenzen, die beim
Einsatz eines Anti-Analyse-Moduls beachtet werden sollten.

## 1. Dual-Use

Techniken zur Erkennung von virtuellen Maschinen, Sandboxes, Debuggern und
Analyse-Werkzeugen sind **dual-use**: Sie stecken in kommerziellen
Schutzprodukten (VMProtect, Themida, Enigma Protector, Denuvo) und in Malware.

**Zulässige Anwendungsfälle**

* Schutz eigener Software vor Analyse/Manipulation auf Nicht-Zielsystemen.
* Lizenz-/Kopierschutz (z. B. Laufzeit nur auf freigegebener Hardware).
* Verhinderung von Cheating/Botting in Online-Spielen gegenüber
  automatisierten Analyseumgebungen.
* Demonstration und Lehre (Reverse-Engineering-Kurse, CTFs mit Zustimmung).

**Nicht zulässig**

* Tarnung von Schadsoftware gegenüber Analyse und Sicherheitsforschung.
* Behinderung von Antiviren-Herstellern, Forensik oder Strafverfolgung.
* Umgehung von Lizenz- oder Nutzungsbedingungen fremder Software.
* Kombination mit Datendiebstahl, Verschlüsselungstrojanern, Persistenz- oder
  Verbreitungsmechanismen. Dieses Modul enthält bewusst **keine** solchen
  Funktionen: es beendet ausschließlich den eigenen Prozess.

Wer das Modul in Schadsoftware einsetzt, handelt rechtswidrig – die
MIT-Lizenz gewährt keine Erlaubnis zur Rechtsverletzung.

## 2. Datenschutz

Der Prozess-Scan liest:

* Namen laufender Prozesse (`/proc/<pid>/comm`, Toolhelp-Snapshot),
* bei generischen Host-Prozessen (python, java, node …) die **Kommandozeile**
  über `NtQueryInformationProcess`, auf Linux `/proc/<pid>/cmdline`,
* Benutzername und Rechnername,
* MAC-Adressen und Hardware-Eckdaten.

Alles bleibt **lokal**: Es gibt keine Netzwerkkommunikation, keine
Telemetrie, kein Logging an Dritte. Wenn Sie `Report::to_json()` an einen
Server senden, werden Rechnername, Benutzername und Pfade potenziell
personenbezogen – dann greifen DSGVO-Pflichten (Information, Rechtsgrundlage,
Datenminimierung). Empfehlung: nur `id` und `score` übertragen, keine
`evidence`-Texte.

## 3. Transparenz gegenüber Nutzern

Wenn Ihre Software in einer VM nicht startet, sollte das für Nutzer
nachvollziehbar sein. Bewährt:

* klare Fehlermeldung (`Action::MessageThenExit`) statt stillem Abbruch,
* Support-Kanal mit der Bitte, den `Report` (ohne personenbezogene Daten)
  einzusenden,
* Dokumentation der Prüfungen in den eigenen AGB/Datenschutzhinweisen.

## 4. Antivirus-False-Positives

Anti-VM-, Anti-Debug- und Prozess-Scan-Code ist ein häufiges Signalmuster für
Heuristiken (Kategorie „AntiVM“, „HackTool“, „PUA“). Realistisch ist:

* signierte Binaries verwenden,
* Verhalten dokumentieren und beim AV-Hersteller als False Positive melden,
* keine Verschleierung *des Schutzes* selbst übertreiben (das wiederum sieht
  wie ein Packer aus).

Die in diesem Projekt verwendete XOR-/Hash-Verschleierung ist bewusst
einfach und offen dokumentiert – kein „Crypter“.

## 5. Wirksamkeit und Grenzen

* Jede lokale Prüfung ist umgehbar: Patch der Verzweigung, Hooking,
  Emulation, Entfernen des Moduls. Das ist eine Eigenschaft von
  Client-Software, keine Schwäche dieser Implementierung.
* „Sicher“ ist nur, was serverseitig geprüft wird. Wenn Ihr Schutz
  wirtschaftlich relevant ist, kombinieren Sie ihn mit Server-Validierung,
  Code-Signatur und Lizenzprüfung.
* Die CPUID-/SMBIOS-Erkennung lässt sich durch konsistente Konfiguration des
  Hypervisors (z. B. SMBIOS-Strings, MAC-Präfixe) teilweise verschleiern;
  deshalb arbeitet das Modul mit mehreren unabhängigen Indizien.

## 6. Meldung von Missbrauch

Wenn Sie dieses Projekt in schädlicher Software finden, informieren Sie die
Projektverantwortlichen und gegebenenfalls die zuständige CERT-Stelle.
