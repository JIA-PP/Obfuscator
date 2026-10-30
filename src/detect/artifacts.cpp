// SPDX-License-Identifier: MIT
// Artefakt-Erkennung: Dateien, Registry, Geraete, MAC-Adressen, SMBIOS/DMI.
//
// Alle Vergleichswerte liegen verschluesselt in den generierten Tabellen
// (siehe src/data/tables_generated.inc) bzw. als AEGIS_STR-Literale vor.
// Sie werden erst im Moment der Pruefung in einen fluechtigen Puffer
// entschluesselt und danach genullt.

#include "aegis/detect.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {
namespace {

/// Prueft Firmware-/CPU-Texte gegen Virtualisierer-Kennungen.
/// Die Muster stehen in einer generierten, verschluesselten Tabelle; als
/// Beweis dient der Laufzeit-Text selbst.
bool has_vm_vendor(const std::string& text) {
    if (text.empty()) return false;
    std::size_t count = 0;
    const data::TextEntry* markers = data::vm_identifiers(count);
    return data::contains_any(markers, count, text.c_str());
}

/// Fasst Firmware-Texte fuer die Beweisfuehrung zusammen.
std::string firmware_excerpt(const std::string& text, std::size_t limit = 160) {
    std::string excerpt;
    excerpt.reserve(limit);
    for (char c : text) {
        if (excerpt.size() >= limit) {
            excerpt += "...";
            break;
        }
        excerpt.push_back((c == '\n' || c == '\r' || c == '\t') ? ' ' : c);
    }
    return excerpt;
}

/// Formatiert eine OUI (erste drei Bytes) als Text - reine Laufzeitdaten.
std::string format_oui(const std::array<std::uint8_t, 6>& mac) {
    char text[16];
    std::snprintf(text, sizeof(text), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
    return std::string(text);
}

/// Prueft die MAC-Adressen gegen die generierte OUI-Tabelle.
bool mac_matches_table(const std::array<std::uint8_t, 6>& mac) {
    std::size_t count = 0;
    const data::MacEntry* table = data::vm_mac_prefixes(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (table[i].prefix[0] == mac[0] && table[i].prefix[1] == mac[1] &&
            table[i].prefix[2] == mac[2]) {
            return true;
        }
    }
    return false;
}

std::string join_paths(const std::vector<std::string>& paths, std::size_t max_items = 3) {
    std::string text;
    for (std::size_t i = 0; i < paths.size() && i < max_items; ++i) {
        if (i > 0) text += "; ";
        text += paths[i];
    }
    if (paths.size() > max_items) text += "; ...";
    return text;
}

void check_files(const Config& config, Findings& out) {
    std::vector<std::string> vm_hits;
    std::vector<std::string> sandbox_hits;

    std::size_t vm_count = 0;
    const data::TextEntry* vm_files = data::vm_files(vm_count);
    for (std::size_t i = 0; i < vm_count; ++i) {
        const data::DecodedText path(vm_files[i]);
        if (path.valid() && platform::file_exists(path.c_str())) vm_hits.emplace_back(path.c_str());
    }

    std::size_t sandbox_count = 0;
    const data::TextEntry* sandbox_files = data::sandbox_files(sandbox_count);
    for (std::size_t i = 0; i < sandbox_count; ++i) {
        const data::DecodedText path(sandbox_files[i]);
        if (!path.valid()) continue;
        if (platform::file_exists(path.c_str()) || platform::dir_exists(path.c_str())) {
            sandbox_hits.emplace_back(path.c_str());
        }
    }

    for (const std::string& configured : config.extra_files) {
        if (!configured.empty() && (platform::file_exists(configured.c_str()) ||
                                    platform::dir_exists(configured.c_str()))) {
            sandbox_hits.push_back(configured);
        }
    }

    if (!vm_hits.empty()) {
        const int weight = 25 + static_cast<int>(std::min<std::size_t>(vm_hits.size(), 4) * 5);
        add(out, true, "vm.file", Category::Virtualization, Severity::High, weight,
            "VM-Gast-Datei vorhanden: " + join_paths(vm_hits));
    }
    if (!sandbox_hits.empty()) {
        const int weight = 28 + static_cast<int>(std::min<std::size_t>(sandbox_hits.size(), 4) * 5);
        add(out, true, "sandbox.file", Category::Sandbox, Severity::High, weight,
            "Sandbox-Artefakt vorhanden: " + join_paths(sandbox_hits));
    }
}

#if defined(_WIN32)
/// Prueft eine PCI-Geraete-ID. Der Praefix wird erst hier entschluesselt.
template <std::size_t N>
void probe_pci(const crypto::EncryptedLiteral<N>& prefix, const char* root, Findings& out) {
    char buffer[N];
    prefix.copy_to(buffer);
    if (platform::registry_subkey_prefix_exists(root, buffer)) {
        add(out, true, "vm.pci_device", Category::Virtualization, Severity::High, 32,
            platform::format("PCI-Geraet %s im System", buffer));
    }
    crypto::secure_zero(buffer, sizeof(buffer));
}

void check_registry(Findings& out) {
    std::vector<std::string> key_hits;
    std::size_t key_count = 0;
    const data::TextEntry* keys = data::vm_registry_keys(key_count);
    for (std::size_t i = 0; i < key_count; ++i) {
        const data::DecodedText key(keys[i]);
        if (key.valid() && platform::registry_key_exists(key.c_str())) key_hits.emplace_back(key.c_str());
    }
    if (!key_hits.empty()) {
        add(out, true, "vm.registry_key", Category::Virtualization, Severity::High,
            28 + static_cast<int>(std::min<std::size_t>(key_hits.size(), 3) * 4),
            "VM-Registry-Schluessel vorhanden: " + join_paths(key_hits));
    }

    std::vector<std::string> value_hits;
    std::size_t value_count = 0;
    const data::RegistryValueEntry* values = data::vm_registry_values(value_count);
    for (std::size_t i = 0; i < value_count; ++i) {
        const data::DecodedText key(values[i].key);
        const data::DecodedText needle(values[i].needle);
        const data::DecodedText name(values[i].value_name);
        if (!key.valid() || !needle.valid() || !name.valid()) continue;
        if (platform::registry_value_contains(key.c_str(), name.c_str(), needle.c_str())) {
            value_hits.emplace_back(std::string(key.c_str()) + " [" + name.c_str() + " ~ " +
                                    needle.c_str() + "]");
        }
    }
    if (!value_hits.empty()) {
        add(out, true, "vm.registry_value", Category::Virtualization, Severity::High, 35,
            "VM-Registry-Wert: " + join_paths(value_hits));
    }

    // PCI-Geraete-IDs (VEN_80EE = VirtualBox, VEN_15AD = VMware, ...)
    static constexpr const char* kPciRoot = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI";
    probe_pci(AEGIS_STR("VEN_80EE"), kPciRoot, out);
    probe_pci(AEGIS_STR("VEN_15AD"), kPciRoot, out);
    probe_pci(AEGIS_STR("VEN_1AF4"), kPciRoot, out);
    probe_pci(AEGIS_STR("VEN_1234"), kPciRoot, out);
    probe_pci(AEGIS_STR("VEN_1B36"), kPciRoot, out);
    probe_pci(AEGIS_STR("VEN_1414"), kPciRoot, out);
}
#endif

void check_mac(Findings& out) {
    std::vector<std::array<std::uint8_t, 6>> addresses;
    if (!platform::get_mac_addresses(addresses)) return;

    std::vector<std::string> hits;
    for (const auto& mac : addresses) {
        if (mac_matches_table(mac)) hits.push_back(format_oui(mac));
    }
    if (hits.empty()) return;

    std::string label;
    for (const std::string& hit : hits) {
        if (label.find(hit) == std::string::npos) {
            if (!label.empty()) label += ", ";
            label += hit;
        }
    }
    add(out, true, "vm.mac_oui", Category::Virtualization, Severity::High, 32,
        "MAC-Adresse eines Virtualisierers (" + label + ")");
}

void check_firmware(Findings& out) {
    const std::string identifiers = platform::smbios_strings();
    if (!identifiers.empty() && has_vm_vendor(identifiers)) {
        add(out, true, "vm.smbios", Category::Virtualization, Severity::High, 35,
            "SMBIOS/DMI-Feld: " + firmware_excerpt(identifiers));
    }

#if !defined(_WIN32)
    const std::string hypervisor_type = platform::read_sysfs("/sys/hypervisor/type");
    if (!hypervisor_type.empty()) {
        add(out, true, "vm.sysfs_hypervisor", Category::Virtualization, Severity::High, 30,
            "Kernel meldet Hypervisor: " + hypervisor_type);
    }

    const std::string info = platform::cpuinfo();
    if (!info.empty()) {
        if (AEGIS_STR("hypervisor").contained_in_ci(info.c_str())) {
            add(out, true, "vm.cpuinfo_hypervisor", Category::Virtualization, Severity::Medium, 25,
                "CPU-Flags enthalten 'hypervisor'");
        }
        if (has_vm_vendor(info)) {
            add(out, true, "vm.cpuinfo_vendor", Category::Virtualization, Severity::High, 30,
                "CPU-Information: " + firmware_excerpt(info, 120));
        }
    }
#endif
}

}  // namespace

void artifacts(const Config& config, Findings& out) {
    if (!config.check_artifacts) return;

    check_files(config, out);
#if defined(_WIN32)
    check_registry(out);
#endif
    check_mac(out);
    check_firmware(out);
}

}  // namespace aegis::detect
