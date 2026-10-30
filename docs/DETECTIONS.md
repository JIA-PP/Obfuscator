# Erkannte Werkzeuge und Artefakte

> Diese Datei wird automatisch aus `tools/data/blacklist.json` erzeugt.
> Aenderungen gehoeren in die JSON-Datei, danach `python3 tools/aegis_tool.py gen-tables`.

## Reverse-Engineering-Werkzeuge

| Werkzeug | Kategorie | Prozessnamen (normalisiert) | Fenster |
|---|---|---|---|
| IDA Pro / IDA Free | Disassembler | `ida`, `ida64`, `idaq`, `idaq64`, `idat`, `idat64`, `idapyswitch`, `idapython` | IDA Pro, IDA Free, IDA Educational,  - IDA , IDA:  |
| x64dbg / x32dbg | Debugger | `x64dbg`, `x32dbg`, `x96dbg` | x64dbg, x32dbg, x96dbg / Klassen: `x64dbg`, `x32dbg` |
| Ghidra | Disassembler | `ghidrarun`, `ghidra` | Ghidra, CodeBrowser |
| Radare2 | Disassembler | `radare2`, `r2`, `rabin2`, `rasm2`, `rahash2`, `radiff2`, `rafind2`, `ragg2`, `rarun2`, `rax2`, `ravc2`, `r2pm` | radare2,  r2  |
| Rizin | Disassembler | `rizin`, `rz-bin`, `rz-asm`, `rz-ax`, `rz-diff`, `rz-find`, `rz-gg`, `rz-hash`, `rz-run`, `rz-pipe`, `rz-sign` | rizin |
| Cutter | Disassembler | `cutter` | Cutter |
| Binary Ninja | Disassembler | `binaryninja`, `binaryninja_headless`, `bn` | Binary Ninja |
| Hopper Disassembler (macOS) | Disassembler | `hopper`, `hopper disassembler`, `hopperdisassembler` | Hopper |
| RetDec | Decompiler | `retdec-decompiler`, `retdec-decompiler`, `retdec-decompiler`, `retdec` | RetDec |
| WinDbg / WinDbg Preview / cdb / kd / ntsd | Debugger | `windbg`, `windbgx`, `dbgx.shell`, `cdb`, `kd`, `ntsd` | WinDbg / Klassen: `WinDbgFrameClass` |
| GDB / gdbserver | Debugger | `gdb`, `gdb`, `gdbserver`, `gdb-multiarch`, `gdb-add-index`, `arm-none-eabi-gdb`, `aarch64-linux-gnu-gdb`, `x86_64-w64-mingw32-gdb`, `i686-w64-mingw32-gdb` | — |
| LLDB | Debugger | `lldb`, `lldb`, `lldb-server`, `lldb-mi` | — |
| rr (record & replay) | Debugger | `rr`, `rr` | — |
| Frida | Instrumentierung | `frida`, `frida-server`, `frida-server`, `frida-helper-32`, `frida-helper-64`, `frida-inject`, `frida-trace`, `frida-ps`, `frida-ls-devices`, `frida-kill`, `frida-discover`, `frida-apk`, `frida-push`, `frida-pull` / Module: `frida-agent`, `frida-agent-32`, `frida-agent-64`, `frida-gadget`, `frida-gadget-32`, `frida-gadget-64`, `frida_helper`, `frida-helper` | Frida |
| dnSpy | .NET-Decompiler | `dnspy`, `dnspy.console`, `dnspy-x86` | dnSpy |
| dnSpyEx (Fork) | .NET-Decompiler | `dnspy`, `dnspy.console`, `dnspy-x86`, `dnspyex` | dnSpyEx, dnSpy |
| ILSpy | .NET-Decompiler | `ilspy`, `ilspy`, `ilspycmd`, `ilspycmd` | ILSpy |
| dotPeek | .NET-Decompiler | `dotpeek`, `dotpeek32`, `dotpeek64` | dotPeek |
| JustDecompile | .NET-Decompiler | `justdecompile` | JustDecompile |
| .NET Reflector | .NET-Decompiler | `reflector` | .NET Reflector |
| Simple Assembly Explorer | .NET-Decompiler | `simpleassemblyexplorer` | — |
| ILDASM / monodis | .NET-Decompiler | `ildasm`, `monodis`, `ikdasm` | — |
| angr | Instrumentierung | `angr-management`, `angr-management`, `angr` | angr management, Angr Management |
| Wireshark / tshark / dumpcap | Netzwerk-Sniffer | `wireshark`, `tshark`, `dumpcap`, `sharkd`, `wireshark-gtk` | Wireshark, The Wireshark Network Analyzer |
| HTTP Debugger | Netzwerk-Sniffer | `httpdebuggerui`, `httpdebuggersvc`, `httpdebuggerproxy`, `httpdebugger` | HTTP Debugger |
| Fiddler | Netzwerk-Sniffer | `fiddler`, `fiddler everywhere`, `progress telerik fiddler` | Fiddler |
| mitmproxy | Netzwerk-Sniffer | `mitmproxy`, `mitmdump`, `mitmweb`, `mitmproxy`, `mitmdump`, `mitmweb` | — |
| Charles Proxy | Netzwerk-Sniffer | `charles`, `charles` | Charles |
| Burp Suite | Netzwerk-Sniffer | — | Burp Suite, Burp Project |
| API Monitor | Instrumentierung | `apimonitor`, `apimonitor-x64`, `apimonitor-x86` | API Monitor |
| OllyDbg | Debugger | `ollydbg`, `ollydbg110`, `ollydbg2` | OllyDbg / Klassen: `OLLYDBG` |
| Immunity Debugger | Debugger | `immunitydebugger` | Immunity Debugger |
| HyperDbg | Debugger | `hyperdbg`, `hyperdbgdebugger`, `hd` | HyperDbg |
| Visual Studio Remote Debugger / JIT Debugger | Debugger | `msvsmon`, `vsjitdebugger` | — |
| Cheat Engine | Memory-Scanner | `cheatengine-x86_64`, `cheatengine-i386`, `cheatengine`, `cheatengine-x86_64-sse4-avx2`, `cheat engine` | Cheat Engine |
| Process Hacker / System Informer | Memory-Scanner | `processhacker`, `systeminformer` | Process Hacker, System Informer |
| Process Monitor | Instrumentierung | `procmon`, `procmon64`, `procmon32` | Process Monitor |
| Process Explorer | Instrumentierung | `procexp`, `procexp64`, `procexp32` | Process Explorer |
| Scylla (Import-Rebuilder) | PE-Werkzeug | `scylla`, `scylla_x64`, `scylla_x86` | Scylla |
| PE-bear | PE-Werkzeug | `pe-bear`, `pebear` | PE-bear |
| CFF Explorer | PE-Werkzeug | `cff explorer` | CFF Explorer |
| Detect It Easy | Packer-Detektor | `die`, `diec`, `die64`, `diec64` | Detect It Easy |
| PEiD | Packer-Detektor | `peid` | PEiD |
| MegaDumper / ExtremeDumper | Memory-Scanner | `megadumper`, `extremedumper`, `extremedumper-x86` | MegaDumper, ExtremeDumper |
| ReClass.NET | Memory-Scanner | `reclass.net`, `reclass` | ReClass.NET |
| HxD / 010 Editor (Hex-Editoren) | Hex-Editor | `hxd`, `010editor` | HxD, 010 Editor |
| ScyllaHide (Anti-Anti-Debug-Plugin) | Runtime-Hook | Module: `scyllahide`, `scyllahidevt`, `scyllahidex64`, `scyllahide64`, `scyllahide32`, `scyllahide-dll` | — |
| SharpOD (Anti-Anti-Debug-Plugin) | Runtime-Hook | Module: `sharpod` | — |
| Valgrind | Instrumentierung | `valgrind`, `valgrind` | — |
| strace / ltrace | Instrumentierung | `strace`, `ltrace` | — |
| edb-debugger | Debugger | `edb`, `edb-debugger` | — |
| objdump (binutils) | Disassembler | `objdump` | — |
| class-dump / jtool (macOS) | Decompiler | `class-dump`, `jtool`, `jtool2` | — |
| Intel Pin / DynamoRIO | Instrumentierung | `pin`, `drrun`, `drcov`, `drrun` / Module: `pinvm`, `dynamorio` | — |
| Speakeasy / Qiling / Unicorn-basierte Emulatoren | Instrumentierung | `speakeasy`, `qiling` | — |

## VM-/Hypervisor-Artefakte

* Prozesse: 14
* Module: 10
* Dateien: 40
* Registry-Schluessel: 18
* Registry-Werte: 18
* MAC-Prefixe: 14
* PCI-Vendor-Prefixe: 7

## Sandbox-Artefakte

* Dateien: 22
* Benutzernamen: 18
* Rechnernamen: 25
* Module: 13
