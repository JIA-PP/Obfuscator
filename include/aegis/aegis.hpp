// SPDX-License-Identifier: MIT
// AEGIS Guard - Sammelheader.
//
//     #include "aegis/aegis.hpp"
//
//     int main() {
//         aegis::Guard guard(aegis::Config::balanced());
//         guard.protect();          // beendet sich bei Analyseumgebung
//         guard.start_watchdog();   // ueberwacht weiter
//         ...
//     }

#ifndef AEGIS_AEGIS_HPP
#define AEGIS_AEGIS_HPP

#include "aegis/blob.hpp"
#include "aegis/config.hpp"
#include "aegis/crypto/chacha20.hpp"
#include "aegis/crypto/fnv.hpp"
#include "aegis/crypto/sha256.hpp"
#include "aegis/crypto/xorstr.hpp"
#include "aegis/detect.hpp"
#include "aegis/finding.hpp"
#include "aegis/guard.hpp"
#include "aegis/report.hpp"
#include "aegis/response.hpp"
#include "aegis/version.hpp"

#endif  // AEGIS_AEGIS_HPP
