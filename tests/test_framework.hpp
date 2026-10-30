// SPDX-License-Identifier: MIT
// Minimalistisches Test-Framework (keine externen Abhaengigkeiten).

#ifndef AEGIS_TEST_FRAMEWORK_HPP
#define AEGIS_TEST_FRAMEWORK_HPP

#include <cstdio>
#include <exception>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace aegis::test {

struct TestCase {
    const char* name;
    void (*function)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, void (*function)()) { registry().push_back({name, function}); }
};

class Failure : public std::exception {
public:
    explicit Failure(std::string message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return message_.c_str(); }

private:
    std::string message_;
};

inline void fail(const char* file, int line, const std::string& message) {
    std::ostringstream stream;
    stream << file << ":" << line << ": " << message;
    throw Failure(stream.str());
}

template <typename T, typename = void>
struct is_streamable : std::false_type {};

template <typename T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <typename T>
inline std::string to_text(const T& value) {
    if constexpr (is_streamable<T>::value) {
        std::ostringstream stream;
        stream << value;
        return stream.str();
    } else {
        return std::to_string(static_cast<long long>(value));
    }
}

template <typename A, typename B>
inline void check_equal(const char* file, int line, const A& actual, const B& expected,
                        const char* actual_text, const char* expected_text) {
    if (!(actual == expected)) {
        std::ostringstream stream;
        stream << actual_text << " != " << expected_text << "  (" << to_text(actual) << " vs "
               << to_text(expected) << ")";
        fail(file, line, stream.str());
    }
}

inline void check_true(const char* file, int line, bool value, const char* text) {
    if (!value) fail(file, line, std::string(text) + " ist false");
}

}  // namespace aegis::test

#define TEST_CASE(name)                                                            \
    static void name();                                                            \
    static ::aegis::test::Registrar aegis_test_registrar_##name(#name, &name);     \
    static void name()

#define CHECK(condition) ::aegis::test::check_true(__FILE__, __LINE__, (condition), #condition)

#define CHECK_EQ(actual, expected)                                                 \
    ::aegis::test::check_equal(__FILE__, __LINE__, (actual), (expected), #actual,  \
                               #expected)

#define CHECK_NEAR(actual, expected, tolerance)                                    \
    ::aegis::test::check_true(__FILE__, __LINE__,                                  \
                              ((actual) > (expected) - (tolerance) &&              \
                               (actual) < (expected) + (tolerance)),               \
                              #actual " ~= " #expected)

#define REQUIRE(condition)                                                         \
    do {                                                                           \
        if (!(condition)) ::aegis::test::fail(__FILE__, __LINE__, #condition);     \
    } while (false)

#endif  // AEGIS_TEST_FRAMEWORK_HPP
