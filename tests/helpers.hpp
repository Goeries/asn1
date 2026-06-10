#pragma once

#include <cstddef>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <asn1/asn1.hpp>

// Hex string ("30 0A 16 05 ...", whitespace ignored) -> bytes.
inline std::vector<std::byte> H(std::string_view hex) {
    std::vector<std::byte> out;
    int hi = -1;
    for (char c : hex) {
        int v;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else
            continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<std::byte>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

inline std::string hexstr(std::span<const std::byte> s) {
    std::string out;
    for (auto b : s)
        out += std::format("{:02X}", std::to_integer<unsigned>(b));
    return out;
}
inline std::string hexstr(const std::vector<std::byte> & v) {
    return hexstr(std::span<const std::byte>(v));
}

// CHECK that an encode result matches expected hex, with readable failures.
#define CHECK_HEX(expr, expected)                                                                                      \
    do {                                                                                                               \
        auto _r = (expr);                                                                                              \
        REQUIRE(_r.has_value());                                                                                       \
        CHECK_EQ(hexstr(*_r), hexstr(H(expected)));                                                                    \
    } while (0)

// CHECK that a result is an error with the given code.
#define CHECK_ERR(expr, expected_errc)                                                                                 \
    do {                                                                                                               \
        auto _r = (expr);                                                                                              \
        REQUIRE_FALSE(_r.has_value());                                                                                 \
        CHECK_EQ(_r.error().code, expected_errc);                                                                      \
    } while (0)
