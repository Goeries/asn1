// asn1/core.hpp — fundamental vocabulary types: tag, errors, results, options.
//
// Reference: ITU-T X.690 (02/2021) | ISO/IEC 8825-1:2021.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace asn1 {

// --- tags -------------------------------------------------------------- //

// X.690 §8.1.2.2: bits 8-7 of the identifier octet.
enum class tag_class : std::uint8_t {
    universal = 0,
    application = 1,
    context_specific = 2,
    private_ = 3, // NOLINT(readability-identifier-naming) -- 'private' is a keyword
};

// A tag is (class, number). The primitive/constructed bit is a property of a
// particular encoding, not of the tag, and is carried separately (§8.1.2.5).
struct tag {
    tag_class cls{tag_class::universal};
    std::uint32_t number{0};

    friend constexpr bool operator==(const tag &, const tag &) = default;
    friend constexpr auto operator<=>(const tag &, const tag &) = default;
};

// Universal tag numbers (X.680 §8.6).
namespace tags {
inline constexpr tag boolean{tag_class::universal, 1};
inline constexpr tag integer{tag_class::universal, 2};
inline constexpr tag bit_string{tag_class::universal, 3};
inline constexpr tag octet_string{tag_class::universal, 4};
inline constexpr tag null{tag_class::universal, 5};
inline constexpr tag object_identifier{tag_class::universal, 6};
inline constexpr tag object_descriptor{tag_class::universal, 7};
inline constexpr tag external{tag_class::universal, 8};
inline constexpr tag real{tag_class::universal, 9};
inline constexpr tag enumerated{tag_class::universal, 10};
inline constexpr tag embedded_pdv{tag_class::universal, 11};
inline constexpr tag utf8_string{tag_class::universal, 12};
inline constexpr tag relative_oid{tag_class::universal, 13};
inline constexpr tag time{tag_class::universal, 14};
inline constexpr tag sequence{tag_class::universal, 16};
inline constexpr tag set{tag_class::universal, 17};
inline constexpr tag numeric_string{tag_class::universal, 18};
inline constexpr tag printable_string{tag_class::universal, 19};
inline constexpr tag teletex_string{tag_class::universal, 20};
inline constexpr tag videotex_string{tag_class::universal, 21};
inline constexpr tag ia5_string{tag_class::universal, 22};
inline constexpr tag utc_time{tag_class::universal, 23};
inline constexpr tag generalized_time{tag_class::universal, 24};
inline constexpr tag graphic_string{tag_class::universal, 25};
inline constexpr tag visible_string{tag_class::universal, 26};
inline constexpr tag general_string{tag_class::universal, 27};
inline constexpr tag universal_string{tag_class::universal, 28};
inline constexpr tag character_string{tag_class::universal, 29};
inline constexpr tag bmp_string{tag_class::universal, 30};
inline constexpr tag date{tag_class::universal, 31};
inline constexpr tag time_of_day{tag_class::universal, 32};
inline constexpr tag date_time{tag_class::universal, 33};
inline constexpr tag duration{tag_class::universal, 34};
inline constexpr tag oid_iri{tag_class::universal, 35};
inline constexpr tag relative_oid_iri{tag_class::universal, 36};

constexpr tag context(std::uint32_t n) noexcept {
    return {tag_class::context_specific, n};
}
constexpr tag application(std::uint32_t n) noexcept {
    return {tag_class::application, n};
}
constexpr tag private_(std::uint32_t n) noexcept { // NOLINT(readability-identifier-naming)
    return {tag_class::private_, n};
}
} // namespace tags

// --- errors ------------------------------------------------------------ //

enum class errc : std::uint8_t {
    ok = 0,
    // syntax: the bytes are not valid BER
    truncated,              // input ended inside identifier, length or value
    invalid_tag,            // malformed identifier octets / tag number overflow
    invalid_length,         // reserved 0xFF prefix, or length > uint64
    length_overflow,        // declared length exceeds remaining input
    indefinite_not_allowed, // indefinite on primitive, or forbidden by rules
    non_minimal_length,     // DER: long form where short would do, etc.
    unbalanced_eoc,         // EOC without an open indefinite frame, or bad EOC
    // structure: valid BER, but not the shape that was requested
    tag_mismatch,           // carries expected + actual
    unexpected_constructed, // primitive/constructed bit contradicts the type
    value_out_of_range,     // e.g. INTEGER does not fit the target type
    invalid_value,          // malformed contents (OID arc, charset, UTF-8, ...)
    non_canonical,          // DER: a BER freedom was exercised
    trailing_data,          // bytes left over after the requested element
    // resource limits
    depth_exceeded,
};

constexpr std::string_view message(errc c) noexcept {
    switch (c) {
    case errc::ok:
        return "ok";
    case errc::truncated:
        return "truncated input";
    case errc::invalid_tag:
        return "invalid identifier octets";
    case errc::invalid_length:
        return "invalid length octets";
    case errc::length_overflow:
        return "length exceeds remaining input";
    case errc::indefinite_not_allowed:
        return "indefinite length not allowed";
    case errc::non_minimal_length:
        return "non-minimal length octets";
    case errc::unbalanced_eoc:
        return "unbalanced end-of-contents";
    case errc::tag_mismatch:
        return "tag mismatch";
    case errc::unexpected_constructed:
        return "wrong primitive/constructed form";
    case errc::value_out_of_range:
        return "value out of range";
    case errc::invalid_value:
        return "invalid value contents";
    case errc::non_canonical:
        return "non-canonical encoding";
    case errc::trailing_data:
        return "trailing data";
    case errc::depth_exceeded:
        return "nesting depth exceeded";
    }
    return "unknown";
}

struct error {
    errc code{errc::ok};
    std::size_t offset{0}; // absolute byte offset in the original input
    tag expected{};        // meaningful for tag_mismatch
    tag actual{};          // meaningful for tag_mismatch

    friend constexpr bool operator==(const error &, const error &) = default;
};

template<class T>
using result = std::expected<T, error>;

namespace detail {
template<class T = void>
constexpr std::unexpected<error> fail(errc c, std::size_t offset) {
    return std::unexpected(error{c, offset});
}
constexpr std::unexpected<error> fail_tag(std::size_t offset, tag expected, tag actual) {
    return std::unexpected(error{errc::tag_mismatch, offset, expected, actual});
}
} // namespace detail

// --- options ------------------------------------------------------------ //

struct decode_options {
    // Maximum nesting depth of constructed / indefinite-length encodings.
    // Guards against stack exhaustion (cf. CVE-2018-0739, CVE-2010-3445).
    std::uint32_t max_depth = 64;
};

// --- byte helpers -------------------------------------------------------- //

using bytes_view = std::span<const std::byte>;

// View any contiguous range of 1-byte elements (char, unsigned char,
// uint8_t, std::byte) as bytes_view.
template<class R>
    requires requires(const R & r) {
        { std::data(r) };
        { std::size(r) };
        requires sizeof(*std::data(std::declval<const R &>())) == 1;
    }
constexpr bytes_view buffer_view(const R & r) noexcept {
    return std::as_bytes(std::span(std::data(r), std::size(r)));
}

} // namespace asn1
