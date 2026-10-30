cmake_minimum_required(VERSION 3.16)
project(aegis_guard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AEGIS_BUILD_TESTS "Tests bauen" ON)
option(AEGIS_BUILD_EXAMPLES "Beispielprogramme bauen" ON)
option(AEGIS_GENERATE_TABLES "Signaturtabellen beim Build aus blacklist.json erzeugen" OFF)
option(AEGIS_WARNINGS_AS_ERRORS "Warnungen als Fehler behandeln" OFF)

find_package(Threads REQUIRED)

set(AEGIS_SOURCES
    src/core/blob.cpp
    src/core/config.cpp
    src/core/finding.cpp
    src/core/guard.cpp
    src/core/policy.cpp
    src/core/response.cpp
    src/crypto/chacha20.cpp
    src/crypto/sha256.cpp
    src/crypto/xorstr_runtime.cpp
    src/data/tables.cpp
    src/detect/analysis_tools.cpp
    src/detect/api_hooks.cpp
    src/detect/artifacts.cpp
    src/detect/debugger.cpp
    src/detect/hardware.cpp
    src/detect/hypervisor.cpp
    src/detect/injected_modules.cpp
    src/detect/sandbox_env.cpp
    src/detect/timing.cpp
    src/detect/windows_enum.cpp
)

if(WIN32)
    list(APPEND AEGIS_SOURCES src/platform/platform_win.cpp)
else()
    list(APPEND AEGIS_SOURCES src/platform/platform_posix.cpp)
endif()

add_library(aegis STATIC ${AEGIS_SOURCES})
add_library(aegis::guard ALIAS aegis)

target_include_directories(aegis
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(aegis PUBLIC cxx_std_17)
target_link_libraries(aegis PUBLIC Threads::Threads)

if(WIN32)
    target_link_libraries(aegis PUBLIC advapi32 iphlpapi)
    target_compile_definitions(aegis PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

if(MSVC)
    target_compile_options(aegis PRIVATE /W4 /permissive- /Zc:__cplusplus)
    if(AEGIS_WARNINGS_AS_ERRORS)
        target_compile_options(aegis PRIVATE /WX)
    endif()
else()
    target_compile_options(aegis PRIVATE -Wall -Wextra -Wpedantic)
    if(AEGIS_WARNINGS_AS_ERRORS)
        target_compile_options(aegis PRIVATE -Werror)
    endif()
endif()

# ---------------------------------------------------------------------------
# Optionale Neuerzeugung der Signaturtabellen (benoetigt Python 3)
# ---------------------------------------------------------------------------
if(AEGIS_GENERATE_TABLES)
    find_package(Python3 COMPONENTS Interpreter)
    if(NOT Python3_Interpreter_FOUND)
        message(FATAL_ERROR "AEGIS_GENERATE_TABLES=ON benoetigt Python 3")
    endif()
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/data/tables_generated.inc
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/aegis_tool.py gen-tables
                --json ${CMAKE_CURRENT_SOURCE_DIR}/tools/data/blacklist.json
                --output ${CMAKE_CURRENT_SOURCE_DIR}/src/data/tables_generated.inc
                --doc ${CMAKE_CURRENT_SOURCE_DIR}/docs/DETECTIONS.md
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/data/blacklist.json
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/aegis_tool.py
        COMMENT "Erzeuge Signaturtabellen aus blacklist.json"
        VERBATIM)
    add_custom_target(aegis_tables DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/data/tables_generated.inc)
    add_dependencies(aegis aegis_tables)
endif()

# ---------------------------------------------------------------------------
# Beispiel
# ---------------------------------------------------------------------------
if(AEGIS_BUILD_EXAMPLES)
    add_executable(aegis_demo examples/demo.cpp)
    target_link_libraries(aegis_demo PRIVATE aegis)
    set_target_properties(aegis_demo PROPERTIES OUTPUT_NAME "aegis_demo")

    if(WIN32)
        # Als Windows-GUI-Anwendung ohne Konsolenfenster?
        # (auskommentieren fuer eine reine GUI-Anwendung)
        # set_target_properties(aegis_demo PROPERTIES WIN32_EXECUTABLE TRUE)
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(AEGIS_BUILD_TESTS)
    enable_testing()
    add_executable(aegis_tests
        tests/test_main.cpp
        tests/test_crypto.cpp
        tests/test_policy.cpp
        tests/test_detection.cpp
        tests/test_blob.cpp)
    target_link_libraries(aegis_tests PRIVATE aegis)
    target_include_directories(aegis_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    if(NOT MSVC)
        target_compile_options(aegis_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME aegis_tests COMMAND aegis_tests)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME aegis_tables_up_to_date
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/aegis_tool.py
                         gen-tables --check)
        set_tests_properties(aegis_tables_up_to_date PROPERTIES
                             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

        if(AEGIS_BUILD_EXAMPLES)
            add_test(NAME aegis_no_plaintext
                     COMMAND ${Python3_EXECUTABLE}
                             ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_no_plaintext.py
                             $<TARGET_FILE:aegis_demo>)
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS aegis ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
