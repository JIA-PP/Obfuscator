// SPDX-License-Identifier: MIT
#include <cstring>
#include <exception>
#include <string>

#include "test_framework.hpp"

int main(int argc, char** argv) {
    const char* filter = (argc > 1) ? argv[1] : nullptr;

    std::size_t passed = 0;
    std::size_t failed = 0;

    for (const aegis::test::TestCase& test : aegis::test::registry()) {
        if (filter != nullptr && std::strstr(test.name, filter) == nullptr) continue;
        try {
            test.function();
            ++passed;
            std::printf("  [ok]   %s\n", test.name);
        } catch (const std::exception& error) {
            ++failed;
            std::printf("  [FAIL] %s\n         %s\n", test.name, error.what());
        } catch (...) {
            ++failed;
            std::printf("  [FAIL] %s (unbekannte Ausnahme)\n", test.name);
        }
    }

    std::printf("\n%zu bestanden, %zu fehlgeschlagen\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
