// SPDX-License-Identifier: MIT
// CPUID-basierte Hypervisor-Erkennung.
//
// Technik:
//   1. CPUID.1:ECX[31] ist das offizielle "Hypervisor present"-Bit.
//   2. CPUID.40000000h liefert eine 12-Byte-Vendor-Kennung.
//   3. CPUID.40000001h enthaelt die Hypervisor-Schnittstellen-Signatur
//      (z. B. "Hv#1" fuer Hyper-V).
//   4. Der Marken-String (CPUID.80000002h-80000004h) enthaelt bei vielen
//      Virtualisierern Hinweise wie "QEMU Virtual CPU".
//
// Das Bit allein ist kein Beweis: Windows 11 mit VBS/Credential Guard,
// WSL2 oder Hyper-V auf einem echten Rechner setzt es ebenfalls. Deshalb
// werden bekannte Vendoren unterschieden und die Allowlist respektiert.

#include "aegis/detect.hpp"

#include <cstring>
#include <string>

#include "aegis/crypto/xorstr.hpp"
#include "data/tables.hpp"
#include "platform/platform.hpp"

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
#define AEGIS_HAS_CPUID 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace aegis::detect {
namespace {

#if defined(AEGIS_HAS_CPUID)
struct CpuidResult {
    std::uint32_t eax;
    std::uint32_t ebx;
    std::uint32_t ecx;
    std::uint32_t edx;
};

/// Fuehrt CPUID aus. Wichtig: __get_cpuid_count() aus <cpuid.h> verweigert
/// Blatt 0x40000000, weil es nur gegen das hoechste BASIC-Blatt prueft - und
/// damit ausgerechnet die Hypervisor-Blaetter. Deshalb direkter Assemblercode.
bool cpuid(std::uint32_t leaf, std::uint32_t subleaf, CpuidResult& out) noexcept {
#if defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    out.eax = static_cast<std::uint32_t>(regs[0]);
    out.ebx = static_cast<std::uint32_t>(regs[1]);
    out.ecx = static_cast<std::uint32_t>(regs[2]);
    out.edx = static_cast<std::uint32_t>(regs[3]);
    return true;
#elif defined(__x86_64__)
    std::uint32_t a = 0, b = 0, c = 0, d = 0;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
    out.eax = a;
    out.ebx = b;
    out.ecx = c;
    out.edx = d;
    return true;
#else
    std::uint32_t a = 0, b = 0, c = 0, d = 0;
    __asm__ __volatile__("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
                         : "=a"(a), "+r"(b), "=c"(c), "=d"(d)
                         : "a"(leaf), "c"(subleaf));
    out.eax = a;
    out.ebx = b;
    out.ecx = c;
    out.edx = d;
    return true;
#endif
}

/// Vendor-String aus CPUID.40000000h (12 Zeichen, nicht nullterminiert).
bool hypervisor_vendor(char out[13]) noexcept {
    CpuidResult regs{};
    if (!cpuid(0x40000000u, 0, regs)) return false;
    std::memcpy(out + 0, &regs.ebx, 4);
    std::memcpy(out + 4, &regs.ecx, 4);
    std::memcpy(out + 8, &regs.edx, 4);
    out[12] = '\0';
    return true;
}

std::string cpu_brand() {
    CpuidResult max_ext{};
    if (!cpuid(0x80000000u, 0, max_ext)) return std::string();
    if (max_ext.eax < 0x80000004u) return std::string();

    char brand[49] = {};
    for (std::uint32_t index = 0; index < 3; ++index) {
        CpuidResult regs{};
        if (!cpuid(0x80000002u + index, 0, regs)) break;
        std::memcpy(brand + index * 16 + 0, &regs.eax, 4);
        std::memcpy(brand + index * 16 + 4, &regs.ebx, 4);
        std::memcpy(brand + index * 16 + 8, &regs.ecx, 4);
        std::memcpy(brand + index * 16 + 12, &regs.edx, 4);
    }
    brand[48] = '\0';
    return platform::trim(brand);
}

/// Bekannte Hypervisor-Vendoren. Die 12-Byte-CPUID-Kennungen liegen als
/// Chiffrat in der generierten Tabelle (kein Klartext im Binary).
bool is_known_vendor(const char* vendor) {
    std::size_t count = 0;
    const auto* table = ::aegis::data::hypervisor_vendor_strings(count);
    return ::aegis::data::equals_any(table, count, vendor);
}

bool brand_is_virtual(const char* brand) {
    std::size_t count = 0;
    const auto* table = ::aegis::data::cpu_brand_markers(count);
    return ::aegis::data::contains_any(table, count, brand);
}

bool vendor_allowlisted(const Config& config, const char* vendor) noexcept {
    for (const std::string& allowed : config.hypervisor_allowlist) {
        if (platform::iequals(allowed, vendor)) return true;
        // Erlaubt auch Praefix-Angaben wie "Microsoft" fuer "Microsoft Hv".
        if (allowed.size() <= 12 && platform::icontains(vendor, allowed)) return true;
    }
    return false;
}

#endif  // AEGIS_HAS_CPUID

}  // namespace

void hypervisor(const Config& config, Findings& out) {
    if (!config.check_hypervisor) return;

#if !defined(AEGIS_HAS_CPUID)
    (void)config;
    (void)out;
    return;
#else
    CpuidResult leaf1{};
    if (!cpuid(1, 0, leaf1)) return;

    const bool hypervisor_present = ((leaf1.ecx >> 31) & 1u) != 0;
    if (!hypervisor_present) return;

    char vendor[13] = {};
    const bool has_vendor = hypervisor_vendor(vendor);
    const std::string vendor_text = has_vendor ? platform::trim(vendor) : std::string("(unbekannt)");
    const bool known = has_vendor && is_known_vendor(vendor);

    // Hypervisor-Schnittstellensignatur (z. B. "Hv#1")
    std::string interface_signature;
    if (has_vendor) {
        CpuidResult leaf40000001{};
        if (cpuid(0x40000001u, 0, leaf40000001)) {
            char signature[5] = {};
            std::memcpy(signature + 0, &leaf40000001.eax, 4);
            signature[4] = '\0';
            // Nur druckbare Zeichen uebernehmen (bei KVM steht hier Binaermuell).
            for (std::size_t i = 0; i < 4; ++i) {
                const unsigned char c = static_cast<unsigned char>(signature[i]);
                if (c < 0x20 || c > 0x7E) signature[i] = '\0';
            }
            interface_signature = std::string(signature);
        }
    }

    if (known && vendor_allowlisted(config, vendor)) {
        add(out, true, "vm.cpuid.vendor_allowed", Category::Virtualization, Severity::Info, 5,
            platform::format("Hypervisor '%s' steht auf der Allowlist", vendor_text.c_str()));
    } else if (known) {
        std::string evidence = platform::format("Hypervisor-Vendor: %s", vendor_text.c_str());
        if (!interface_signature.empty()) {
            evidence += platform::format(" (Signatur '%s')", interface_signature.c_str());
        }
        add(out, true, "vm.cpuid.vendor", Category::Virtualization, Severity::Critical, 60,
            std::move(evidence), /*decisive=*/true);
    } else {
        // Bit gesetzt, Vendor unbekannt: kann VBS/Hyper-V auf echter Hardware sein.
        add(out, true, "vm.cpuid.bit_unknown_vendor", Category::Virtualization, Severity::Medium, 25,
            platform::format("Hypervisor-Bit gesetzt, Vendor '%s' unbekannt", vendor_text.c_str()));
    }

    // Marken-String
    const std::string brand = cpu_brand();
    if (!brand.empty()) {
        if (brand_is_virtual(brand.c_str())) {
            add(out, true, "vm.cpuid.brand", Category::Virtualization, Severity::High, 35,
                platform::format("CPU-Marke deutet auf Virtualisierung: %s", brand.c_str()));
        }
    }

    // VMware-Backdoor-Port (0x5658 "VX") - nur als Zusatzindiz, wenn Vendor passt.
#endif
}

}  // namespace aegis::detect
