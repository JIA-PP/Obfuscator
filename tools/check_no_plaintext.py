#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Prueft, ob in einem (oder mehreren) Binaerartefakten unerwuenschte
Klartext-Signaturen stecken.

Hintergrund: AEGIS_STR() und die generierten Tabellen sollen dafuer sorgen,
dass Werkzeugnamen und VM-Artefakte nur als Chiffrat im Binary liegen. Dieser
Scanner verifiziert das an den gebauten Dateien.

Aufruf:
    python3 tools/check_no_plaintext.py build/aegis_demo [weitere Dateien ...]

Exit-Code 0 = sauber, 1 = Klartext gefunden.
"""

from __future__ import annotations

import argparse
import re
import sys

# Tokens, die im Binary nicht als ASCII-Klartext vorkommen duerfen.
# Mindestens 5 Zeichen, damit keine Zufallstreffer entstehen.
DENYLIST = [
    # Disassembler / Debugger / Decompiler
    "x64dbg", "x32dbg", "x96dbg", "ida64", "idapro", "ida64.exe",
    "ghidra", "radare2", "rizin", "cutter", "binaryninja", "binary ninja",
    "windbg", "windbgx", "ollydbg", "immunitydebugger", "hyperdbg",
    "dnspy", "ilspy", "dotpeek", "justdecompile", "simpleassembly",
    "retdec", "hopper disassembler", "class-dump",
    # Netzwerk / Monitoring
    "wireshark", "dumpcap", "httpdebugger", "fiddler", "mitmproxy",
    "charles proxy",
    # Instrumentierung / Memory
    "frida", "angr", "scyllahide", "sharpod", "cheatengine",
    "processhacker", "systeminformer", "megadumper", "extremedumper",
    "apimonitor", "pe-bear", "detect it easy",
    # VM-/Sandbox-Artefakte
    "vboxguest", "vboxservice", "vboxtray", "vboxmouse", "vboxsf",
    "vboxhook", "vboxdisp", "vmhgfs", "vmmouse", "vmtoolsd", "vmacthlp",
    "vmware", "virtualbox", "vmci.sys", "vmrawdsk",
    "qemu-ga", "qemuh", "qemu virtual", "viostor", "vioscsi", "netkvm",
    "sbiedll", "sandedrv", "sandboxie", "cuckoomon", "cuckoo",
    "prl_tools", "prl_fs", "xenbus", "xenvbd", "xenservice",
    # Weitere Hersteller-/Werkzeugnamen
    "bochs", "parallels", "openstack", "innotek", "seabios", "ovmf",
    "acrn", "bhyve", "qnx", "qemu", "vbox", "scylla", "procmon", "procexp",
    "peid", "ildasm", "monodis", "reflector", "hopper", "charles",
    "qiling", "speakeasy", "pydbg", "uncompyle", "docker", "kubepods",
    "scyllahide.exe",
]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Klartext-Scanner fuer AEGIS-Artefakte")
    parser.add_argument("files", nargs="+", help="zu pruefende Dateien")
    parser.add_argument("--extra", action="append", default=[],
                        help="zusaetzliche Tokens (mehrfach angebbar)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    tokens = [token for token in DENYLIST + args.extra if len(token) >= 5]
    failures = 0

    for path in args.files:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as error:
            print(f"FEHLER: {path}: {error}", file=sys.stderr)
            return 2

        lowered = data.lower()
        hits = []
        for token in tokens:
            needle = token.lower().encode("ascii")
            offset = lowered.find(needle)
            if offset >= 0:
                hits.append((token, offset))

        if hits:
            failures += 1
            print(f"[!] {path}: {len(hits)} Klartext-Treffer")
            for token, offset in hits:
                context = data[max(0, offset - 16):offset + len(token) + 16]
                printable = re.sub(rb"[^\x20-\x7e]", b".", context).decode("ascii", "replace")
                print(f"      {token!r:28} @ 0x{offset:X}   ...{printable}...")
        else:
            size = len(data)
            print(f"[ok] {path}: keine Klartext-Signaturen ({size} Byte geprueft)")

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
