// SPDX-License-Identifier: MIT
#include "aegis/config.hpp"

namespace aegis {

void Config::apply_profile() {
    if (!strict_mode) {
        score_threshold = 55;
        min_cpu_cores = 2;
        min_ram_mb = 2048;
        min_uptime_seconds = 420;
        min_process_count = 22;
        min_disk_gb = 40;
        check_api_hooks = false;
        check_user_interaction = false;
        timing_sleep_ms = 1200;
        return;
    }

    // Aggressiv: alles an, hoehere Schwellen fuer Ressourcen, niedrigerer Score.
    score_threshold = 35;
    min_cpu_cores = 4;
    min_ram_mb = 4096;
    min_uptime_seconds = 900;
    min_process_count = 40;
    min_disk_gb = 80;
    check_api_hooks = true;
    check_user_interaction = true;
    timing_sleep_ms = 1500;
}

Config Config::relaxed() {
    Config config;
    config.score_threshold = 90;
    config.action = Action::ExitClean;
    config.check_hardware = false;
    config.check_timing = false;
    config.check_sandbox_env = false;
    config.check_container = false;
    config.check_api_hooks = false;
    config.check_user_interaction = false;
    config.min_process_count = 0;
    config.timing_sleep_ms = 0;
    return config;
}

Config Config::balanced() {
    Config config;
    config.apply_profile();
    return config;
}

Config Config::aggressive() {
    Config config;
    config.strict_mode = true;
    config.apply_profile();
    return config;
}

}  // namespace aegis
