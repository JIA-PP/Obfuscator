// SPDX-License-Identifier: MIT
// Zeit-basierte Erkennung von Sandboxes und Zeitraffer.
//
// Viele Analyse-Sandboxes beschleunigen Sleep-Aufrufe, damit Malware ihre
// Verzoegerungen "abwartet". Wenn ein 1,5-s-Sleep in 200 ms zurueckkehrt,
// stimmt etwas mit der Uhr nicht.

#include "aegis/detect.hpp"
#include "platform/platform.hpp"

namespace aegis::detect {

void timing(const Config& config, Findings& out) {
    if (!config.check_timing) return;

    const unsigned kRequestedSleepMs = config.timing_sleep_ms;
    if (kRequestedSleepMs == 0) return;

    const std::uint64_t before = platform::monotonic_ms();
    const unsigned long long uptime_before = platform::uptime_seconds();
    platform::sleep_ms(kRequestedSleepMs);
    const std::uint64_t after = platform::monotonic_ms();
    const unsigned long long uptime_after = platform::uptime_seconds();

    const std::uint64_t elapsed = after - before;
    const std::uint64_t tolerance = kRequestedSleepMs / 4;  // 25 %

    if (elapsed + tolerance < kRequestedSleepMs) {
        add(out, true, "time.sleep_dilation", Category::Timing, Severity::High, 30,
            platform::format("Sleep(%u ms) dauerte nur %llu ms", kRequestedSleepMs,
                             static_cast<unsigned long long>(elapsed)));
    } else if (elapsed > kRequestedSleepMs * 4) {
        add(out, true, "time.sleep_stall", Category::Timing, Severity::Info, 6,
            platform::format("Sleep(%u ms) dauerte %llu ms", kRequestedSleepMs,
                             static_cast<unsigned long long>(elapsed)));
    }

    // Systemzeit muss waehrend des Sleeps mindestens einmal fortschreiten.
    if (uptime_after > 0 && uptime_before > 0 && uptime_after <= uptime_before &&
        kRequestedSleepMs >= 1200) {
        add(out, true, "time.uptime_frozen", Category::Timing, Severity::Medium, 18,
            "System-Uptime steht waehrend des Sleeps still");
    }
}

}  // namespace aegis::detect
