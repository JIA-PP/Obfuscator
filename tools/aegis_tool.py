#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
AEGIS Guard - Build-Werkzeug.

Unterbefehle:
  gen-tables   tools/data/blacklist.json  ->  src/data/tables_generated.inc
                                              docs/DETECTIONS.md
  gen-blob     Zusatzliste (Text/JSON)    ->  Header mit verschluesseltem Dataset
  hash         Namen normalisieren und hashen (Debugging)

Beispiele:
  python3 tools/aegis_tool.py gen-tables --check
  python3 tools/aegis_tool.py gen-tables
  python3 tools/aegis_tool.py gen-blob --input extra.txt --output generated/extra_blob.hpp
  python3 tools/aegis_tool.py hash x64dbg.exe

Das Skript benoetigt ausschliesslich die Python-Standardbibliothek.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Mit C++ geteilte Konstanten (mussen identisch sein!)
# ---------------------------------------------------------------------------

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1
HASH_MASK_KEY = 0x9E3779B97F4A7C15           # == aegis::data::kHashMaskKey
KNOWN_EXTENSIONS = (".exe", ".bin", ".dll", ".so", ".app", ".py", ".jar", ".bat", ".cmd")

CATEGORY_MAP = {
    "disassembler": "Disassembler",
    "debugger": "Debugger",
    "decompiler": "Decompiler",
    "dotnet-decompiler": "DotnetDecompiler",
    "instrumentation": "Instrumentation",
    "network-sniffer": "NetworkSniffer",
    "memory-scanner": "MemoryScanner",
    "packer-detector": "PackerDetector",
    "pe-tool": "PeTool",
    "hex-editor": "HexEditor",
    "hypervisor-tool": "HypervisorTool",
    "runtime-hook": "RuntimeHook",
    "unknown": "Unknown",
}

CATEGORY_LABELS = {
    "disassembler": "Disassembler",
    "debugger": "Debugger",
    "decompiler": "Decompiler",
    "dotnet-decompiler": ".NET-Decompiler",
    "instrumentation": "Instrumentierung",
    "network-sniffer": "Netzwerk-Sniffer",
    "memory-scanner": "Memory-Scanner",
    "packer-detector": "Packer-Detektor",
    "pe-tool": "PE-Werkzeug",
    "hex-editor": "Hex-Editor",
    "hypervisor-tool": "Hypervisor-Werkzeug",
    "runtime-hook": "Runtime-Hook",
    "unknown": "Unbekannt",
}


def splitmix64(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK64
    return x ^ (x >> 31)


def hash_mask(index: int) -> int:
    return splitmix64((HASH_MASK_KEY + index) & MASK64)


def normalize_name(raw: str) -> str:
    """Muss aegis::crypto::normalize_name_hash entsprechen."""
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    for sep in ("#", ":"):
        if sep in name:
            name = name.split(sep, 1)[0]
    lowered = name.lower()
    for ext in KNOWN_EXTENSIONS:
        if lowered.endswith(ext) and len(lowered) > len(ext):
            lowered = lowered[: -len(ext)]
            break
    return lowered


def normalize_hash(raw: str) -> int:
    h = FNV_OFFSET
    for ch in normalize_name(raw).encode("utf-8"):
        h ^= ch
        h = (h * FNV_PRIME) & MASK64
    return h


# ---------------------------------------------------------------------------
# ChaCha20 / AEAD (identisch zu src/crypto/chacha20.cpp)
# ---------------------------------------------------------------------------

def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[(work[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        stream = chacha20_block(key, nonce, counter + offset // 64)
        chunk = data[offset:offset + 64]
        out.extend(bytes(a ^ b for a, b in zip(chunk, stream)))
    return bytes(out)


def derive_keys(key: bytes) -> tuple[bytes, bytes]:
    enc = hashlib.sha256(key + b"aegis/aead/v1/enc").digest()
    mac = hashlib.sha256(key + b"aegis/aead/v1/mac").digest()
    return enc, mac


def aead_seal(plaintext: bytes, key: bytes, nonce: bytes, associated: bytes = b"") -> tuple[bytes, bytes]:
    enc_key, mac_key = derive_keys(key)
    ciphertext = chacha20_xor(plaintext, enc_key, nonce, 0)
    digest = hashlib.sha256(associated + nonce + ciphertext).digest()
    tag = hmac.new(mac_key, digest, hashlib.sha256).digest()[:16]
    return ciphertext, tag


# ---------------------------------------------------------------------------
# Tabellen-Generator
# ---------------------------------------------------------------------------

def cpp_bytes_literal(data: bytes, indent: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in data[i:i + 12])
        lines.append(indent + chunk + ",")
    return "\n".join(lines)


def xor_encrypt(text: str, key: int) -> bytes:
    """XOR-Verschluesselung passend zu aegis::crypto::literal_byte_key."""
    raw = text.encode("utf-8")
    out = bytearray()
    for index, byte in enumerate(raw):
        k = splitmix64((key ^ ((index * 0x2545F4914F6CDD1D) & MASK64)) & MASK64)
        out.append(byte ^ ((k >> 24) & 0xFF))
    return bytes(out)


@dataclass
class TextBlob:
    ident: str
    text: str
    key: int


@dataclass
class Tables:
    name_tables: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    title_table: list[tuple[TextBlob, str]] = field(default_factory=list)
    text_tables: dict[str, list[TextBlob]] = field(default_factory=dict)
    registry_values: list[tuple[TextBlob, TextBlob, str]] = field(default_factory=list)
    mac_table: list[str] = field(default_factory=list)


def add_name(tables: Tables, table: str, raw: str, category: str) -> None:
    tables.name_tables.setdefault(table, [])
    tables.name_tables[table].append((normalize_hash(raw), category))


def build_tables(data: dict) -> Tables:
    tables = Tables()
    key_counter = 0

    def next_key() -> int:
        nonlocal key_counter
        key_counter += 1
        return splitmix64(0xA5A5A5A5A5A5A5A5 ^ key_counter) | 1

    for tool in data.get("tools", []):
        category = tool.get("category", "unknown")
        if category not in CATEGORY_MAP:
            raise SystemExit(f"Unbekannte Kategorie: {category} (Werkzeug {tool.get('tool')!r})")
        for name in tool.get("processes", []):
            add_name(tables, "analysis_processes", name, category)
        for name in tool.get("modules", []):
            add_name(tables, "analysis_modules", name, category)
        for name in tool.get("window_classes", []):
            add_name(tables, "analysis_window_classes", name, category)
        for pattern in tool.get("window_titles", []):
            blob = TextBlob(f"kTitle{len(tables.title_table)}", pattern, next_key())
            tables.title_table.append((blob, category))

    vm = data.get("vm", {})
    for name in vm.get("processes", []):
        add_name(tables, "vm_processes", name, "unknown")
    for name in vm.get("modules", []):
        add_name(tables, "vm_modules", name, "unknown")
    for path in vm.get("files", []):
        blob = TextBlob(f"kVmFile{len(tables.text_tables.get('vm_files', []))}", path, next_key())
        tables.text_tables.setdefault("vm_files", []).append(blob)
    for key in vm.get("registry_keys", []):
        idx = len(tables.text_tables.get("vm_registry_keys", []))
        blob = TextBlob(f"kVmRegKey{idx}", key, next_key())
        tables.text_tables.setdefault("vm_registry_keys", []).append(blob)
    for entry in vm.get("registry_values", []):
        idx = len(tables.registry_values)
        key_blob = TextBlob(f"kVmRegValKey{idx}", entry["key"], next_key())
        needle_blob = TextBlob(f"kVmRegValNeedle{idx}", entry["needle"], next_key())
        tables.registry_values.append((key_blob, needle_blob, entry["value"]))
    for prefix in vm.get("mac_prefixes", []):
        tables.mac_table.append(prefix)

    # Alle uebrigen Text-Muster (Virtualisierer, Container, Tracer, Threads ...).
    for list_name in TEXT_LIST_KEYS:
        for value in data.get(list_name, []):
            entries = tables.text_tables.setdefault(list_name, [])
            blob = TextBlob(f"kText_{list_name}_{len(entries)}", value, next_key())
            entries.append(blob)

    sandbox = data.get("sandbox", {})
    for path in sandbox.get("files", []):
        blob = TextBlob(f"kSandboxFile{len(tables.text_tables.get('sandbox_files', []))}", path, next_key())
        tables.text_tables.setdefault("sandbox_files", []).append(blob)
    for name in sandbox.get("users", []):
        blob = TextBlob(f"kSandboxUser{len(tables.text_tables.get('sandbox_users', []))}", name, next_key())
        tables.text_tables.setdefault("sandbox_users", []).append(blob)
    for name in sandbox.get("computers", []):
        blob = TextBlob(f"kSandboxComputer{len(tables.text_tables.get('sandbox_computers', []))}", name, next_key())
        tables.text_tables.setdefault("sandbox_computers", []).append(blob)
    for name in sandbox.get("modules", []):
        add_name(tables, "sandbox_modules", name, "unknown")

    # Duplikate entfernen (z. B. dnSpy/dnSpyEx teilen sich binaernamen)
    for table_name, entries in tables.name_tables.items():
        seen = {}
        for h, category in entries:
            seen.setdefault(h, category)
        tables.name_tables[table_name] = sorted(seen.items())

    return tables


def generate_inc(tables: Tables) -> str:
    out = []
    out.append("// ===========================================================================")
    out.append("// GENERIERT von tools/aegis_tool.py (gen-tables) - NICHT HAENDISCH EDITIEREN.")
    out.append("// Quelle: tools/data/blacklist.json")
    out.append("//")
    out.append("// Alle Namen liegen als maskierte FNV-1a-64-Hashes vor, alle Texte als")
    out.append("// XOR-Chiffrat. Es befindet sich kein Klartext in dieser Datei.")
    out.append("// ===========================================================================")
    out.append("")

    for table_name in sorted(tables.name_tables):
        entries = tables.name_tables[table_name]
        out.append(f"static const NameEntry kTable_{table_name}[] = {{")
        for index, (h, category) in enumerate(entries):
            masked = h ^ hash_mask(index)
            out.append(f"    {{0x{masked:016X}ULL, ToolCategory::{CATEGORY_MAP[category]}}},")
        out.append("};")
        out.append("")

    for blob, category in tables.title_table:
        out.append(f"static const std::uint8_t {blob.ident}[] = {{")
        out.append(cpp_bytes_literal(xor_encrypt(blob.text, blob.key)))
        out.append("};")
    if tables.title_table:
        out.append("")
        out.append("static const TitleEntry analysis_titles_table[] = {")
        for blob, category in tables.title_table:
            text = blob.text.encode("utf-8")
            out.append(
                f"    {{{{ {blob.ident}, {len(text)}, 0x{blob.key:016X}ULL }}, ToolCategory::{CATEGORY_MAP[category]}}},")
        out.append("};")
        out.append("")

    for table_name in sorted(tables.text_tables):
        blobs = tables.text_tables[table_name]
        for blob in blobs:
            out.append(f"static const std::uint8_t {blob.ident}[] = {{")
            out.append(cpp_bytes_literal(xor_encrypt(blob.text, blob.key)))
            out.append("};")
        out.append(f"static const TextEntry kTable_{table_name}[] = {{")
        for blob in blobs:
            text = blob.text.encode("utf-8")
            out.append(f"    {{ {blob.ident}, {len(text)}, 0x{blob.key:016X}ULL }},")
        out.append("};")
        out.append("")

    if tables.registry_values:
        for index, (key_blob, needle_blob, _value) in enumerate(tables.registry_values):
            out.append(f"static const std::uint8_t {key_blob.ident}[] = {{")
            out.append(cpp_bytes_literal(xor_encrypt(key_blob.text, key_blob.key)))
            out.append("};")
            out.append(f"static const std::uint8_t {needle_blob.ident}[] = {{")
            out.append(cpp_bytes_literal(xor_encrypt(needle_blob.text, needle_blob.key)))
            out.append("};")
            # Reg-Wert-Name als TextEntry, damit die Laufzeit ihn entschluesseln kann
            value_name = f"kVmRegValueName{index}"
            value_key = splitmix64(0xDEADBEEF ^ (index + 1)) | 1
            out.append(f"static const std::uint8_t {value_name}[] = {{")
            out.append(cpp_bytes_literal(xor_encrypt(_value, value_key)))
            out.append("};")
        out.append("static const RegistryValueEntry vm_registry_values_table[] = {")
        for index, (key_blob, needle_blob, value) in enumerate(tables.registry_values):
            key_text = key_blob.text.encode("utf-8")
            needle_text = needle_blob.text.encode("utf-8")
            value_key = splitmix64(0xDEADBEEF ^ (index + 1)) | 1
            out.append(
                f"    {{ {{ {key_blob.ident}, {len(key_text)}, 0x{key_blob.key:016X}ULL }}, "
                f"{{ {needle_blob.ident}, {len(needle_text)}, 0x{needle_blob.key:016X}ULL }}, "
                f"{{ kVmRegValueName{index}, {len(value.encode('utf-8'))}, 0x{value_key:016X}ULL }} }},")
        out.append("};")
        out.append("")

    if tables.mac_table:
        out.append("static const MacEntry vm_mac_table[] = {")
        for prefix in tables.mac_table:
            cleaned = prefix.replace(":", "").replace("-", "").upper()
            if len(cleaned) != 6:
                raise SystemExit(f"MAC-Prefix muss 6 Hex-Zeichen haben: {prefix!r}")
            b = bytes.fromhex(cleaned)
            out.append(f"    {{ {{0x{b[0]:02X}, 0x{b[1]:02X}, 0x{b[2]:02X}}} }},")
        out.append("};")
        out.append("")

    return "\n".join(out)


TABLE_ACCESSORS = [
    "analysis_processes",
    "analysis_modules",
    "analysis_window_classes",
    "vm_processes",
    "vm_modules",
    "sandbox_modules",
]


def generate_accessors(tables: Tables) -> str:
    out = ["// GENERIERT von tools/aegis_tool.py - Zugriffsfunktionen", ""]
    for table_name in TABLE_ACCESSORS:
        count = len(tables.name_tables.get(table_name, []))
        out.append(f"static_assert(sizeof(kTable_{table_name}) / sizeof(NameEntry) == {count}, \"Tabellengroesse\");")
    out.append("")
    for table_name in TABLE_ACCESSORS:
        if table_name in tables.name_tables:
            out.append(f"const NameEntry* {table_name}(std::size_t& count) noexcept {{")
            out.append(f"    count = sizeof(kTable_{table_name}) / sizeof(NameEntry);")
            out.append(f"    return kTable_{table_name};")
            out.append("}")
        else:
            out.append(f"const NameEntry* {table_name}(std::size_t& count) noexcept {{")
            out.append("    count = 0;")
            out.append("    return nullptr;")
            out.append("}")
        out.append("")

    if tables.title_table:
        out.append("const TitleEntry* analysis_titles(std::size_t& count) noexcept {")
        out.append("    count = sizeof(analysis_titles_table) / sizeof(TitleEntry);")
        out.append("    return analysis_titles_table;")
        out.append("}")
    else:
        out.append("const TitleEntry* analysis_titles(std::size_t& count) noexcept { count = 0; return nullptr; }")
    out.append("")

    for table_name in ("vm_files", "vm_registry_keys", "sandbox_files", "sandbox_users",
                       "sandbox_computers", *TEXT_LIST_KEYS):
        if table_name in tables.text_tables:
            out.append(f"const TextEntry* {table_name}(std::size_t& count) noexcept {{")
            out.append(f"    count = sizeof(kTable_{table_name}) / sizeof(TextEntry);")
            out.append(f"    return kTable_{table_name};")
            out.append("}")
        else:
            out.append(f"const TextEntry* {table_name}(std::size_t& count) noexcept {{ count = 0; return nullptr; }}")
        out.append("")

    if tables.registry_values:
        out.append("const RegistryValueEntry* vm_registry_values(std::size_t& count) noexcept {")
        out.append("    count = sizeof(vm_registry_values_table) / sizeof(RegistryValueEntry);")
        out.append("    return vm_registry_values_table;")
        out.append("}")
    else:
        out.append("const RegistryValueEntry* vm_registry_values(std::size_t& count) noexcept { count = 0; return nullptr; }")
    out.append("")

    if tables.mac_table:
        out.append("const MacEntry* vm_mac_prefixes(std::size_t& count) noexcept {")
        out.append("    count = sizeof(vm_mac_table) / sizeof(MacEntry);")
        out.append("    return vm_mac_table;")
        out.append("}")
    else:
        out.append("const MacEntry* vm_mac_prefixes(std::size_t& count) noexcept { count = 0; return nullptr; }")
    out.append("")
    return "\n".join(out)


def generate_doc(data: dict) -> str:
    lines = ["# Erkannte Werkzeuge und Artefakte", "",
             "> Diese Datei wird automatisch aus `tools/data/blacklist.json` erzeugt.",
             "> Aenderungen gehoeren in die JSON-Datei, danach `python3 tools/aegis_tool.py gen-tables`.", "",
             "## Reverse-Engineering-Werkzeuge", "",
             "| Werkzeug | Kategorie | Prozessnamen (normalisiert) | Fenster |",
             "|---|---|---|---|"]
    for tool in data.get("tools", []):
        procs = ", ".join(f"`{normalize_name(p)}`" for p in tool.get("processes", []))
        if tool.get("modules"):
            mods = ", ".join(f"`{normalize_name(m)}`" for m in tool["modules"])
            procs = (procs + " / Module: " + mods).strip(" /")
        titles = ", ".join(tool.get("window_titles", []))
        classes = tool.get("window_classes", [])
        if classes:
            titles = (titles + (" / Klassen: " if titles else "Klassen: ") +
                      ", ".join(f"`{c}`" for c in classes))
        lines.append(f"| {tool['tool']} | {CATEGORY_LABELS.get(tool.get('category','unknown'), '?')} | "
                     f"{procs or '—'} | {titles or '—'} |")

    vm = data.get("vm", {})
    sb = data.get("sandbox", {})
    lines += ["", "## VM-/Hypervisor-Artefakte", "",
              f"* Prozesse: {len(vm.get('processes', []))}",
              f"* Module: {len(vm.get('modules', []))}",
              f"* Dateien: {len(vm.get('files', []))}",
              f"* Registry-Schluessel: {len(vm.get('registry_keys', []))}",
              f"* Registry-Werte: {len(vm.get('registry_values', []))}",
              f"* MAC-Prefixe: {len(vm.get('mac_prefixes', []))}",
              f"* PCI-Vendor-Prefixe: {len(vm.get('pci_prefixes', []))}",
              "", "## Sandbox-Artefakte", "",
              f"* Dateien: {len(sb.get('files', []))}",
              f"* Benutzernamen: {len(sb.get('users', []))}",
              f"* Rechnernamen: {len(sb.get('computers', []))}",
              f"* Module: {len(sb.get('modules', []))}",
              ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Blob-Generator
# ---------------------------------------------------------------------------

# JSON-Schluessel, deren Werte als verschluesselte Text-Tabelle erzeugt werden.
TEXT_LIST_KEYS = [
    "command_line_markers",
    "vm_identifiers",
    "hypervisor_vendor_strings",
    "cpu_brand_markers",
    "container_markers",
    "container_files",
    "tracer_names",
    "instrumentation_threads",
]

KIND_PREFIXES = {
    "process": "process",
    "processes": "process",
    "module": "module",
    "modules": "module",
    "window_class": "window_class",
    "window_title": "window_title",
    "title": "window_title",
    "file": "file",
    "files": "file",
}


def collect_extra_entries(path: str) -> list[str]:
    """Liest Eintraege aus einer Text- oder JSON-Datei und normalisiert sie
    in das Zeilenformat 'kind<TAB>value'."""
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()

    entries: list[str] = []
    if path.lower().endswith(".json"):
        data = json.loads(raw)
        for key, value in data.items():
            if key.startswith("$"):
                continue
            kind = KIND_PREFIXES.get(key.lower())
            if kind is None:
                continue
            if isinstance(value, str):
                value = [value]
            for item in value:
                entries.append(f"{kind}\t{item}")
    else:
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                entries.append(line)
            else:
                entries.append(f"process\t{line}")
    if not entries:
        raise SystemExit(f"Keine Eintraege in {path} gefunden")
    return entries


def cmd_gen_blob(args: argparse.Namespace) -> int:
    entries = collect_extra_entries(args.input)
    plaintext = ("\n".join(entries) + "\n").encode("utf-8")

    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(32)
    if len(key) != 32:
        raise SystemExit("--key muss 32 Byte (64 Hex-Zeichen) haben")
    if args.nonce:
        nonce = bytes.fromhex(args.nonce)
        if len(nonce) != 12:
            raise SystemExit("--nonce muss 12 Byte (24 Hex-Zeichen) haben")
    else:
        nonce = secrets.token_bytes(12)
    associated = args.context.encode("utf-8") if args.context else b""
    ciphertext, tag = aead_seal(plaintext, key, nonce, associated)

    words = list(struct.unpack("<4Q", key))
    mask = int(args.mask, 16) if args.mask else secrets.randbits(64)
    masked_words = [w ^ splitmix64((mask + i) & MASK64) for i, w in enumerate(words)]

    lines = [
        "// ===========================================================================",
        "// GENERIERT von tools/aegis_tool.py (gen-blob) - NICHT HAENDISCH EDITIEREN.",
        "//",
        "// Verschluesseltes Zusatz-Dataset (ChaCha20 + HMAC-SHA-256).",
        "// Einbindung:",
        "//     #include \"extra_blob.hpp\"",
        "//     aegis::Guard guard;",
        "//     guard.add_dataset(aegis::data::kDataset);",
        "//     guard.protect();",
        "// ===========================================================================",
        "#pragma once",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "#include \"aegis/blob.hpp\"",
        "",
        "namespace aegis::data {",
        "",
        f"inline constexpr std::uint8_t kDatasetCiphertext[] = {{",
        cpp_bytes_literal(ciphertext),
        "};",
        "",
        f"inline constexpr std::uint8_t kDatasetContext[] = {{",
        cpp_bytes_literal(associated) if associated else "    0x00,",
        "};",
        "",
        "inline constexpr aegis::EncryptedDataset kDataset = {",
        "    kDatasetCiphertext,",
        "    sizeof(kDatasetCiphertext),",
        "    {" + ", ".join(f"0x{b:02X}" for b in nonce) + "},",
        "    {" + ", ".join(f"0x{b:02X}" for b in tag) + "},",
        "    {" + ", ".join(f"0x{w:016X}ULL" for w in masked_words) + "},",
        f"    0x{mask:016X}ULL,",
        f"    kDatasetContext,",
        f"    {len(associated)}",
        "};",
        "",
        "}  // namespace aegis::data",
        "",
    ]

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print(f"{len(entries)} Eintraege -> {args.output} ({len(ciphertext)} Byte Chiffrat)")
    print("Hinweis: Der Schluessel steckt maskiert im Header. Das ist Verschleierung,")
    print("         keine Geheimhaltung - wer den Header hat, kann ihn extrahieren.")
    return 0


# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------

def cmd_gen_tables(args: argparse.Namespace) -> int:
    with open(args.json, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    tables = build_tables(data)
    inc_content = generate_inc(tables) + "\n" + generate_accessors(tables)
    doc_content = generate_doc(data)

    if args.check:
        problems = []
        for path, expected in ((args.output, inc_content), (args.doc, doc_content)):
            if not os.path.exists(path):
                problems.append(f"{path} fehlt")
                continue
            with open(path, "r", encoding="utf-8") as handle:
                if handle.read() != expected:
                    problems.append(f"{path} ist veraltet")
        if problems:
            print("FEHLER: " + "; ".join(problems), file=sys.stderr)
            print("Bitte 'python3 tools/aegis_tool.py gen-tables' ausfuehren.", file=sys.stderr)
            return 1
        print("Tabellen sind aktuell.")
        return 0

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.doc)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(inc_content)
    with open(args.doc, "w", encoding="utf-8") as handle:
        handle.write(doc_content)

    total_processes = len(tables.name_tables.get("analysis_processes", []))
    print(f"{total_processes} Prozess-Signaturen, {len(tables.title_table)} Titelmuster, "
          f"{sum(len(v) for v in tables.text_tables.values())} Text-Artefakte")
    print(f"-> {args.output}")
    print(f"-> {args.doc}")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    for name in args.names:
        print(f"{name!r:35} normalisiert={normalize_name(name)!r:25} "
              f"hash=0x{normalize_hash(name):016X}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AEGIS Guard Build-Werkzeug")
    sub = parser.add_subparsers(dest="command", required=True)

    p_tables = sub.add_parser("gen-tables", help="C++-Tabellen aus blacklist.json erzeugen")
    p_tables.add_argument("--json", default="tools/data/blacklist.json")
    p_tables.add_argument("--output", default="src/data/tables_generated.inc")
    p_tables.add_argument("--doc", default="docs/DETECTIONS.md")
    p_tables.add_argument("--check", action="store_true", help="nur pruefen, ob die Dateien aktuell sind")
    p_tables.set_defaults(func=cmd_gen_tables)

    p_blob = sub.add_parser("gen-blob", help="verschluesseltes Zusatz-Dataset erzeugen")
    p_blob.add_argument("--input", required=True, help="Text- (.txt) oder JSON-Datei mit Eintraegen")
    p_blob.add_argument("--output", required=True, help="Ziel-Header (.hpp)")
    p_blob.add_argument("--key", default="", help="32 Byte Hex (sonst zufaellig)")
    p_blob.add_argument("--nonce", default="", help="12 Byte Hex (sonst zufaellig)")
    p_blob.add_argument("--mask", default="", help="64-Bit-Maske fuer die Schluesselwoerter (Hex)")
    p_blob.add_argument("--context", default="aegis-dataset-v1", help="AEAD-Kontext")
    p_blob.set_defaults(func=cmd_gen_blob)

    p_hash = sub.add_parser("hash", help="Namen normalisieren und hashen")
    p_hash.add_argument("names", nargs="+")
    p_hash.set_defaults(func=cmd_hash)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
