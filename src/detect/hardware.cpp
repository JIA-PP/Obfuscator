// SPDX-License-Identifier: MIT
// Hardware-/Ressourcen-Heuristiken.
//
// Analyse-VMs sind meist minimal ausgestattet (1-2 Kerne, 2 GB RAM, 40 GB
// Platte, frisch gebootet). Diese Heuristik ist allein schwach - sie liefert
// aber zusammen mit anderen Checks ein deutliches Bild und kostet nichts.

#include "aegis/detect.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {

void hardware(const Config& config, Findings& out) {
    if (!config.check_hardware) return;

    const unsigned cores = platform::cpu_cores();
    if (cores > 0 && cores < config.min_cpu_cores) {
        add(out, true, "hw.cpu_cores", Category::Hardware, Severity::Low, 12,
            platform::format("%u logische Kerne (< %u)", cores, config.min_cpu_cores));
    }

    const unsigned long long ram = platform::ram_mb();
    if (ram > 0 && ram < config.min_ram_mb) {
        add(out, true, "hw.ram", Category::Hardware, Severity::Low, 14,
            platform::format("%llu MiB RAM (< %u)", ram, config.min_ram_mb));
    }

    const unsigned long long uptime = platform::uptime_seconds();
    if (uptime > 0 && uptime < config.min_uptime_seconds) {
        add(out, true, "hw.uptime", Category::Hardware, Severity::Medium, 16,
            platform::format("System laeuft seit %llu s (< %u)", uptime, config.min_uptime_seconds));
    }

    const unsigned long long disk = platform::disk_size_gb(
#if defined(_WIN32)
        "C:\\"
#else
        "/"
#endif
    );
    if (disk > 0 && disk < config.min_disk_gb) {
        add(out, true, "hw.disk", Category::Hardware, Severity::Low, 12,
            platform::format("%llu GB Datentraeger (< %llu)", disk, config.min_disk_gb));
    }

    const unsigned width = platform::screen_width();
    const unsigned height = platform::screen_height();
    if (width > 0 && height > 0 && (width < 1024 || height < 768)) {
        add(out, true, "hw.screen", Category::Hardware, Severity::Low, 8,
            platform::format("Aufloesung %ux%u", width, height));
    }
}

}  // namespace aegis::detect
