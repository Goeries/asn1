// asn1/traits.hpp — codec_traits: the mapping between C++ types and ASN.1
// types, written once per type and shared by every encoding-rules set.
//
// A specialization provides:
//   static constexpr tag type_tag;                      // absent for untagged
//   static constexpr bool accepts(tag, bool constructed);
//   template<encoding_rules R> static result<T> decode(decoder<R>&, tag = type_tag);
//   template<encoding_rules R> static result<void> encode(encoder<R>&, const T&, tag = type_tag);
//
// The tag parameter implements IMPLICIT tagging (§8.14.3): a wrapper simply
// re-invokes the base type's codec with replaced identifier octets.
//
// Aggregate structs (see reflect.hpp) are mapped to SEQUENCE automatically,
// member-by-member in declaration order.
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "core.hpp"
#include "decoder.hpp"
#include "encoder.hpp"
#include "reflect.hpp"
#include "rules.hpp"
#include "types.hpp"

namespace asn1 {

namespace detail {

// --- character set validation (§8.23, X.680 §41) --- //

constexpr bool printable_char(char c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '\'' ||
           c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' ||
           c == '?';
}
constexpr bool numeric_char(char c) noexcept {
    return (c >= '0' && c <= '9') || c == ' ';
}
constexpr bool ia5_char(char c) noexcept {
    return static_cast<unsigned char>(c) <= 0x7F;
}
constexpr bool visible_char(char c) noexcept {
    return static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) <= 0x7E;
}

template<std::uint32_t TagNumber>
constexpr bool charset_ok(std::string_view s) noexcept {
    auto all = [&](auto pred) {
        for (const char c : s)
            if (!pred(c))
                return false;
        return true;
    };
    if constexpr (TagNumber == 18)
        return all(numeric_char);
    else if constexpr (TagNumber == 19)
        return all(printable_char);
    else if constexpr (TagNumber == 22)
        return all(ia5_char);
    else if constexpr (TagNumber == 26)
        return all(visible_char);
    else
        return true; // Teletex/Videotex/Graphic/General: ISO 2022, not policed
}

// §8.23.10: each UTF-8 character in the fewest octets (no overlongs, no
// surrogates, max U+10FFFF).
constexpr bool utf8_ok(std::string_view s) noexcept {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto b0 = static_cast<unsigned char>(s[i]);
        std::size_t n;
        std::uint32_t cp;
        if (b0 < 0x80) {
            n = 0;
            cp = b0;
        } else if ((b0 & 0xE0) == 0xC0) {
            n = 1;
            cp = b0 & 0x1F;
        } else if ((b0 & 0xF0) == 0xE0) {
            n = 2;
            cp = b0 & 0x0F;
        } else if ((b0 & 0xF8) == 0xF0) {
            n = 3;
            cp = b0 & 0x07;
        } else
            return false;
        for (std::size_t k = 1; k <= n; ++k) {
            if (i + k >= s.size())
                return false;
            const auto bk = static_cast<unsigned char>(s[i + k]);
            if ((bk & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (bk & 0x3F);
        }
        if (n == 1 && cp < 0x80)
            return false;
        if (n == 2 && cp < 0x800)
            return false;
        if (n == 3 && cp < 0x10000)
            return false;
        if (cp > 0x10FFFF)
            return false;
        if (cp >= 0xD800 && cp <= 0xDFFF)
            return false;
        i += n + 1;
    }
    return true;
}

// --- time parsing / formatting (X.680 §46/§47, X.690 §11.7/§11.8) --- //

constexpr bool all_digits(std::string_view s) noexcept {
    for (const char c : s)
        if (c < '0' || c > '9')
            return false;
    return !s.empty();
}
constexpr int digits2(std::string_view s, std::size_t i) noexcept {
    return (s[i] - '0') * 10 + (s[i + 1] - '0');
}

struct time_fields {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    std::int64_t frac_ms = 0;
    bool local = false;
    int offset_min = 0; // zone offset, subtracted to normalize to UTC
};

inline std::optional<std::chrono::sys_time<std::chrono::milliseconds>> fields_to_time(const time_fields & f) {
    using namespace std::chrono;
    const year_month_day ymd{year{f.year}, month{static_cast<unsigned>(f.month)}, day{static_cast<unsigned>(f.day)}};
    if (!ymd.ok() || f.hour > 23 || f.minute > 59 || f.second > 59)
        return std::nullopt;
    return sys_days{ymd} + hours{f.hour} + minutes{f.minute} + seconds{f.second} + milliseconds{f.frac_ms} -
           minutes{f.offset_min};
}

// UTCTime (X.680 §47): YYMMDDhhmm[ss] followed by Z or +-hhmm.
// DER (§11.8): seconds present, Z only.
inline result<utc_time> parse_utc_time(std::string_view s, std::size_t off, bool canonical) {
    bool has_seconds = false;
    std::string_view body, zone;
    if (s.size() >= 1 && s.back() == 'Z') {
        body = s.substr(0, s.size() - 1);
        zone = "Z";
    } else if (s.size() >= 5 && (s[s.size() - 5] == '+' || s[s.size() - 5] == '-')) {
        body = s.substr(0, s.size() - 5);
        zone = s.substr(s.size() - 5);
    } else {
        return detail::fail(errc::invalid_value, off);
    }
    if (body.size() == 12)
        has_seconds = true;
    else if (body.size() != 10)
        return detail::fail(errc::invalid_value, off);
    if (!all_digits(body))
        return detail::fail(errc::invalid_value, off);
    if (canonical && !(has_seconds && zone == "Z"))
        return detail::fail(errc::non_canonical, off);

    time_fields f;
    const int yy = digits2(body, 0);
    f.year = yy >= 50 ? 1900 + yy : 2000 + yy; // RFC 5280 convention
    f.month = digits2(body, 2);
    f.day = digits2(body, 4);
    f.hour = digits2(body, 6);
    f.minute = digits2(body, 8);
    if (has_seconds)
        f.second = digits2(body, 10);
    if (zone != "Z") {
        if (!all_digits(zone.substr(1)))
            return detail::fail(errc::invalid_value, off);
        const int zh = digits2(zone, 1), zm = digits2(zone, 3);
        if (zh > 23 || zm > 59)
            return detail::fail(errc::invalid_value, off);
        const int om = zh * 60 + zm;
        f.offset_min = zone[0] == '-' ? -om : om;
    }
    auto t = fields_to_time(f);
    if (!t)
        return detail::fail(errc::invalid_value, off);
    return utc_time{std::chrono::time_point_cast<std::chrono::seconds>(*t), false};
}

// GeneralizedTime (X.680 §46): YYYYMMDDHH[MM[SS]][(.|,)frac][Z|+-HH[MM]].
// DER (§11.7): seconds present, Z, '.' separator, no trailing zeros.
inline result<generalized_time> parse_generalized_time(std::string_view s, std::size_t off, bool canonical) {
    std::string_view zone;
    if (!s.empty() && s.back() == 'Z') {
        zone = "Z";
        s.remove_suffix(1);
    } else {
        for (const std::size_t k : {std::size_t{5}, std::size_t{3}}) {
            if (s.size() > k && (s[s.size() - k] == '+' || s[s.size() - k] == '-')) {
                zone = s.substr(s.size() - k);
                s.remove_suffix(k);
                break;
            }
        }
    }
    std::string_view frac;
    char frac_sep = 0;
    if (auto p = s.find_first_of(".,"); p != std::string_view::npos) {
        frac_sep = s[p];
        frac = s.substr(p + 1);
        s = s.substr(0, p);
        if (frac.empty() || !all_digits(frac))
            return detail::fail(errc::invalid_value, off);
    }
    if (!all_digits(s))
        return detail::fail(errc::invalid_value, off);
    if (s.size() != 10 && s.size() != 12 && s.size() != 14)
        return detail::fail(errc::invalid_value, off);

    if (canonical) {
        // §11.7: UTC (Z), seconds always present, '.' only, no trailing zeros.
        if (zone != "Z" || s.size() != 14)
            return detail::fail(errc::non_canonical, off);
        if (!frac.empty() && (frac_sep != '.' || frac.back() == '0'))
            return detail::fail(errc::non_canonical, off);
    }

    time_fields f;
    f.year = digits2(s, 0) * 100 + digits2(s, 2);
    f.month = digits2(s, 4);
    f.day = digits2(s, 6);
    f.hour = digits2(s, 8);
    if (s.size() >= 12)
        f.minute = digits2(s, 10);
    if (s.size() >= 14)
        f.second = digits2(s, 12);

    if (!frac.empty()) {
        // The fraction applies to the smallest unit present.
        double v = 0, scale = 1;
        for (std::size_t i = 0; i < frac.size() && i < 9; ++i) {
            v = v * 10 + (frac[i] - '0');
            scale *= 10;
        }
        const double unit_ms = s.size() == 10 ? 3'600'000.0 : (s.size() == 12 ? 60'000.0 : 1'000.0);
        f.frac_ms = std::llround(v / scale * unit_ms);
    }
    if (!zone.empty() && zone != "Z") {
        auto digits = zone.substr(1);
        if (!all_digits(digits) || (digits.size() != 2 && digits.size() != 4))
            return detail::fail(errc::invalid_value, off);
        const int zh = digits2(zone, 1);
        const int zm = digits.size() == 4 ? digits2(zone, 3) : 0;
        if (zh > 23 || zm > 59)
            return detail::fail(errc::invalid_value, off);
        const int om = zh * 60 + zm;
        f.offset_min = zone[0] == '-' ? -om : om;
    }
    f.local = zone.empty();
    auto t = fields_to_time(f);
    if (!t)
        return detail::fail(errc::invalid_value, off);
    return generalized_time{*t, f.local};
}

inline result<std::string> format_utc_time(const utc_time & v) {
    using namespace std::chrono;
    const auto dp = floor<days>(v.value);
    const year_month_day ymd{dp};
    const hh_mm_ss hms{v.value - dp};
    const int y = static_cast<int>(ymd.year());
    if (y < 1950 || y > 2049)
        return detail::fail(errc::value_out_of_range, 0);
    return std::format("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, static_cast<unsigned>(ymd.month()),
                       static_cast<unsigned>(ymd.day()), hms.hours().count(), hms.minutes().count(),
                       hms.seconds().count());
}

inline result<std::string> format_generalized_time(const generalized_time & v) {
    using namespace std::chrono;
    const auto dp = floor<days>(v.value);
    const year_month_day ymd{dp};
    const hh_mm_ss hms{v.value - dp};
    const int y = static_cast<int>(ymd.year());
    if (y < 0 || y > 9999)
        return detail::fail(errc::value_out_of_range, 0);
    auto out = std::format("{:04}{:02}{:02}{:02}{:02}{:02}", y, static_cast<unsigned>(ymd.month()),
                           static_cast<unsigned>(ymd.day()), hms.hours().count(), hms.minutes().count(),
                           hms.seconds().count());
    const auto ms = hms.subseconds().count();
    if (ms != 0) {
        auto fs = std::format("{:03}", ms);
        while (fs.back() == '0')
            fs.pop_back();
        out += '.';
        out += fs;
    }
    out += 'Z';
    return out;
}

// Element offset for error reporting on the value about to be read.
template<encoding_rules R>
std::size_t next_offset(decoder<R> & d) {
    auto h = d.peek();
    return h ? h->offset : d.offset();
}

template<class T>
constexpr bool is_char_like = std::is_same_v<T, char> || std::is_same_v<T, wchar_t> || std::is_same_v<T, char8_t> ||
                              std::is_same_v<T, char16_t> || std::is_same_v<T, char32_t>;

} // namespace detail

// ---- BOOLEAN ---------------------------------------------------------- //

template<>
struct codec_traits<bool> {
    static constexpr tag type_tag = tags::boolean;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<bool> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_bool(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, bool v, tag t = type_tag) {
        return e.write_bool(v, t);
    }
};

// ---- INTEGER ---------------------------------------------------------- //

template<class I>
    requires std::integral<I> && (!std::same_as<I, bool>) && (!detail::is_char_like<I>)
struct codec_traits<I> {
    static constexpr tag type_tag = tags::integer;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<I> decode(decoder<R> & d, tag t = type_tag) {
        return d.template read_integer<I>(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, I v, tag t = type_tag) {
        return e.write_integer(v, t);
    }
};

// ---- ENUMERATED ------------------------------------------------------- //

template<class E>
    requires std::is_enum_v<E> && (!std::same_as<E, std::byte>)
struct codec_traits<E> {
    static constexpr tag type_tag = tags::enumerated;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<E> decode(decoder<R> & d, tag t = type_tag) {
        auto r = d.template read_integer<std::underlying_type_t<E>>(t);
        if (!r)
            return std::unexpected(r.error());
        return static_cast<E>(*r);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, E v, tag t = type_tag) {
        return e.write_integer(std::to_underlying(v), t);
    }
};

// ---- REAL ------------------------------------------------------------- //

namespace detail {
template<class F>
struct real_traits {
    static constexpr tag type_tag = tags::real;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<F> decode(decoder<R> & d, tag t = type_tag) {
        auto r = d.read_real(t);
        if (!r)
            return std::unexpected(r.error());
        return static_cast<F>(*r);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, F v, tag t = type_tag) {
        return e.write_real(static_cast<double>(v), t);
    }
};
} // namespace detail

template<>
struct codec_traits<double> : detail::real_traits<double> {};
template<>
struct codec_traits<float> : detail::real_traits<float> {};

// ---- NULL ------------------------------------------------------------- //

template<>
struct codec_traits<null_t> {
    static constexpr tag type_tag = tags::null;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<null_t> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_null(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, null_t, tag t = type_tag) {
        return e.write_null(t);
    }
};

// ---- OCTET STRING ------------------------------------------------------ //

template<>
struct codec_traits<bytes> {
    static constexpr tag type_tag = tags::octet_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<bytes> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_octet_string(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const bytes & v, tag t = type_tag) {
        return e.write_octet_string(v.span(), t);
    }
};

template<>
struct codec_traits<std::vector<std::byte>> {
    static constexpr tag type_tag = tags::octet_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<std::vector<std::byte>> decode(decoder<R> & d, tag t = type_tag) {
        auto r = d.read_octet_string(t);
        if (!r)
            return std::unexpected(r.error());
        auto s = r->span();
        return std::vector<std::byte>(s.begin(), s.end());
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::vector<std::byte> & v, tag t = type_tag) {
        return e.write_octet_string(v, t);
    }
};

template<>
struct codec_traits<std::vector<std::uint8_t>> {
    static constexpr tag type_tag = tags::octet_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<std::vector<std::uint8_t>> decode(decoder<R> & d, tag t = type_tag) {
        auto r = d.read_octet_string(t);
        if (!r)
            return std::unexpected(r.error());
        auto s = r->span();
        std::vector<std::uint8_t> out(s.size());
        for (std::size_t i = 0; i < s.size(); ++i)
            out[i] = std::to_integer<std::uint8_t>(s[i]);
        return out;
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::vector<std::uint8_t> & v, tag t = type_tag) {
        return e.write_octet_string(buffer_view(v), t);
    }
};

// ---- BIT STRING --------------------------------------------------------- //

template<>
struct codec_traits<bit_string> {
    static constexpr tag type_tag = tags::bit_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<bit_string> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_bit_string(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const bit_string & v, tag t = type_tag) {
        return e.write_bit_string(v, t);
    }
};

// ---- OBJECT IDENTIFIER / RELATIVE-OID ------------------------------------ //

template<>
struct codec_traits<oid> {
    static constexpr tag type_tag = tags::object_identifier;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<oid> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_object_identifier(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const oid & v, tag t = type_tag) {
        return e.write_object_identifier(v, t);
    }
};

template<>
struct codec_traits<relative_oid> {
    static constexpr tag type_tag = tags::relative_oid;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && !c;
    }
    template<encoding_rules R>
    static result<relative_oid> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_relative_oid(t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const relative_oid & v, tag t = type_tag) {
        return e.write_relative_oid(v, t);
    }
};

// ---- character strings ---------------------------------------------------//

template<>
struct codec_traits<std::string> { // UTF8String
    static constexpr tag type_tag = tags::utf8_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<std::string> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_character_string(t);
        if (!r)
            return std::unexpected(r.error());
        if (!detail::utf8_ok(*r))
            return detail::fail(errc::invalid_value, off);
        return r;
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::string & v, tag t = type_tag) {
        if (!detail::utf8_ok(v))
            return detail::fail(errc::invalid_value, 0);
        return e.write_character_string(v, t);
    }
};

template<std::uint32_t N>
struct codec_traits<restricted_string<N>> {
    static constexpr tag type_tag = restricted_string<N>::type_tag;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<restricted_string<N>> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_character_string(t);
        if (!r)
            return std::unexpected(r.error());
        if (!detail::charset_ok<N>(*r))
            return detail::fail(errc::invalid_value, off);
        return restricted_string<N>{std::move(*r)};
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const restricted_string<N> & v, tag t = type_tag) {
        if (!detail::charset_ok<N>(v.value))
            return detail::fail(errc::invalid_value, 0);
        return e.write_character_string(v.value, t);
    }
};

template<>
struct codec_traits<bmp_string> { // UCS-2 big-endian (§8.23.8)
    static constexpr tag type_tag = tags::bmp_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<bmp_string> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_octet_string(t);
        if (!r)
            return std::unexpected(r.error());
        auto s = r->span();
        if (s.size() % 2 != 0)
            return detail::fail(errc::invalid_value, off);
        bmp_string out;
        out.value.reserve(s.size() / 2);
        for (std::size_t i = 0; i < s.size(); i += 2) {
            const auto u =
                static_cast<char16_t>((std::to_integer<unsigned>(s[i]) << 8) | std::to_integer<unsigned>(s[i + 1]));
            if (u >= 0xD800 && u <= 0xDFFF)
                return detail::fail(errc::invalid_value, off);
            out.value.push_back(u);
        }
        return out;
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const bmp_string & v, tag t = type_tag) {
        std::vector<std::byte> c;
        c.reserve(v.value.size() * 2);
        for (const char16_t u : v.value) {
            if (u >= 0xD800 && u <= 0xDFFF)
                return detail::fail(errc::invalid_value, 0);
            c.push_back(static_cast<std::byte>(u >> 8));
            c.push_back(static_cast<std::byte>(u & 0xFF));
        }
        return e.write_octet_string(c, t);
    }
};

template<>
struct codec_traits<universal_string> { // UCS-4 big-endian (§8.23.7)
    static constexpr tag type_tag = tags::universal_string;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<universal_string> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_octet_string(t);
        if (!r)
            return std::unexpected(r.error());
        auto s = r->span();
        if (s.size() % 4 != 0)
            return detail::fail(errc::invalid_value, off);
        universal_string out;
        out.value.reserve(s.size() / 4);
        for (std::size_t i = 0; i < s.size(); i += 4) {
            std::uint32_t u = 0;
            for (std::size_t k = 0; k < 4; ++k)
                u = (u << 8) | std::to_integer<std::uint32_t>(s[i + k]);
            if (u > 0x10FFFF || (u >= 0xD800 && u <= 0xDFFF))
                return detail::fail(errc::invalid_value, off);
            out.value.push_back(static_cast<char32_t>(u));
        }
        return out;
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const universal_string & v, tag t = type_tag) {
        std::vector<std::byte> c;
        c.reserve(v.value.size() * 4);
        for (const char32_t u : v.value) {
            const auto x = static_cast<std::uint32_t>(u);
            if (x > 0x10FFFF || (x >= 0xD800 && x <= 0xDFFF))
                return detail::fail(errc::invalid_value, 0);
            for (int k = 3; k >= 0; --k)
                c.push_back(static_cast<std::byte>((x >> (8 * k)) & 0xFF));
        }
        return e.write_octet_string(c, t);
    }
};

// ---- time types ----------------------------------------------------------//

template<>
struct codec_traits<utc_time> {
    static constexpr tag type_tag = tags::utc_time;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<utc_time> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_character_string(t);
        if (!r)
            return std::unexpected(r.error());
        return detail::parse_utc_time(*r, off, R::require_canonical);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const utc_time & v, tag t = type_tag) {
        auto s = detail::format_utc_time(v);
        if (!s)
            return std::unexpected(s.error());
        return e.write_character_string(*s, t);
    }
};

template<>
struct codec_traits<generalized_time> {
    static constexpr tag type_tag = tags::generalized_time;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<generalized_time> decode(decoder<R> & d, tag t = type_tag) {
        const auto off = detail::next_offset(d);
        auto r = d.read_character_string(t);
        if (!r)
            return std::unexpected(r.error());
        return detail::parse_generalized_time(*r, off, R::require_canonical);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const generalized_time & v, tag t = type_tag) {
        auto s = detail::format_generalized_time(v);
        if (!s)
            return std::unexpected(s.error());
        return e.write_character_string(*s, t);
    }
};

// ---- ANY ------------------------------------------------------------------//

template<>
struct codec_traits<any> {
    // No type_tag: ANY matches every element.
    static constexpr bool accepts(tag, bool) noexcept {
        return true;
    }
    template<encoding_rules R>
    static result<any> decode(decoder<R> & d) {
        return d.read_any();
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const any & v) {
        return e.write_any(v);
    }
};

// ---- OPTIONAL ---------------------------------------------------------- //

template<class T>
struct codec_traits<std::optional<T>> {
    static constexpr bool accepts(tag t, bool c) noexcept {
        return codec_traits<T>::accepts(t, c);
    }
    template<encoding_rules R>
    static result<std::optional<T>> decode(decoder<R> & d) {
        if (d.at_end())
            return std::optional<T>{};
        auto h = d.peek();
        if (!h)
            return std::unexpected(h.error());
        if (!codec_traits<T>::accepts(h->tag, h->constructed))
            return std::optional<T>{};
        auto r = codec_traits<T>::decode(d);
        if (!r)
            return std::unexpected(r.error());
        return std::optional<T>(std::move(*r));
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::optional<T> & v) {
        if (!v)
            return {};
        return codec_traits<T>::encode(e, *v);
    }
};

// ---- CHOICE (std::variant) ----------------------------------------------- //

namespace detail {
template<class T>
constexpr std::optional<tag> tag_of() noexcept {
    if constexpr (requires { codec_traits<T>::type_tag; })
        return codec_traits<T>::type_tag;
    else
        return std::nullopt;
}
template<class... Ts>
constexpr bool all_tagged() noexcept {
    return (tag_of<Ts>().has_value() && ...);
}
template<class... Ts>
constexpr bool tags_distinct() noexcept {
    const std::array<std::optional<tag>, sizeof...(Ts)> arr = {tag_of<Ts>()...};
    for (std::size_t i = 0; i < sizeof...(Ts); ++i)
        for (std::size_t j = i + 1; j < sizeof...(Ts); ++j)
            if (arr[i] && arr[i] == arr[j])
                return false;
    return true;
}

template<class T>
struct optional_inner {
    static constexpr bool is_opt = false;
    using type = T;
};
template<class U>
struct optional_inner<std::optional<U>> {
    static constexpr bool is_opt = true;
    using type = U;
};

// X.680 §25.7: an OPTIONAL component's tag must differ from the tag of
// the component that follows it, or absence is undecidable. Checked for
// adjacent pairs where both tags are statically known.
template<class Tuple>
struct seq_components_unambiguous;
template<class... Ms>
struct seq_components_unambiguous<std::tuple<Ms...>> {
    static constexpr bool value() noexcept {
        constexpr std::size_t n = sizeof...(Ms);
        if constexpr (n < 2) {
            return true;
        } else {
            const std::array<bool, n> opts = {optional_inner<std::remove_cvref_t<Ms>>::is_opt...};
            const std::array<std::optional<tag>, n> tags = {
                tag_of<typename optional_inner<std::remove_cvref_t<Ms>>::type>()...};
            for (std::size_t i = 0; i + 1 < n; ++i)
                if (opts[i] && tags[i] && tags[i] == tags[i + 1])
                    return false;
            return true;
        }
    }
};
} // namespace detail

template<class... Ts>
struct codec_traits<std::variant<Ts...>> {
    static_assert(detail::all_tagged<Ts...>(), "asn1: every CHOICE alternative must have a statically known "
                                               "tag (X.680 §29.2). ANY, OPTIONAL and nested CHOICE cannot "
                                               "be alternatives; wrap them in asn1::explicit_<N, T>");
    static_assert(detail::tags_distinct<Ts...>(), "asn1: CHOICE alternatives must have distinct tags; "
                                                  "wrap duplicates in asn1::implicit<N, T>");
    static constexpr bool accepts(tag t, bool c) noexcept {
        return (codec_traits<Ts>::accepts(t, c) || ...);
    }
    template<encoding_rules R>
    static result<std::variant<Ts...>> decode(decoder<R> & d) {
        auto h = d.peek();
        if (!h)
            return std::unexpected(h.error());
        result<std::variant<Ts...>> out = std::unexpected(error{errc::tag_mismatch, h->offset, {}, h->tag});
        bool done = false;
        auto try_one = [&]<class T>(std::type_identity<T>) {
            if (done || !codec_traits<T>::accepts(h->tag, h->constructed))
                return;
            done = true;
            auto r = codec_traits<T>::decode(d);
            if (r)
                out = std::variant<Ts...>(std::in_place_type<T>, std::move(*r));
            else
                out = std::unexpected(r.error());
        };
        (try_one(std::type_identity<Ts>{}), ...);
        return out;
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::variant<Ts...> & v) {
        return std::visit(
            [&](const auto & alt) { return codec_traits<std::remove_cvref_t<decltype(alt)>>::encode(e, alt); }, v);
    }
};

// ---- SEQUENCE OF (std::vector) -------------------------------------------- //

template<class T>
struct codec_traits<std::vector<T>> {
    static_assert(!detail::optional_inner<T>::is_opt, "asn1: OPTIONAL cannot be the element of SEQUENCE OF");
    static constexpr tag type_tag = tags::sequence;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<std::vector<T>> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_constructed(t, [](decoder<R> & s) -> result<std::vector<T>> {
            std::vector<T> out;
            while (!s.at_end()) {
                const auto before = s.offset();
                auto r = s.template read<T>();
                if (!r)
                    return std::unexpected(r.error());
                if (s.offset() == before) // non-consuming decode: never loop
                    return detail::fail(errc::invalid_value, before);
                out.push_back(std::move(*r));
            }
            return out;
        });
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::vector<T> & v, tag t = type_tag) {
        return e.write_constructed(t, [&](encoder<R> & s) -> result<void> {
            for (const auto & item : v) {
                auto r = codec_traits<T>::encode(s, item);
                if (!r)
                    return r;
            }
            return {};
        });
    }
};

// ---- SET OF ---------------------------------------------------------------- //

template<class T>
struct codec_traits<set_of<T>> {
    static_assert(!detail::optional_inner<T>::is_opt, "asn1: OPTIONAL cannot be the element of SET OF");
    static constexpr tag type_tag = tags::set;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<set_of<T>> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_constructed(t, [](decoder<R> & s) -> result<set_of<T>> {
            set_of<T> out;
            bytes_view prev{};
            while (!s.at_end()) {
                auto h = s.peek();
                if (!h)
                    return std::unexpected(h.error());
                if constexpr (R::require_canonical) {
                    // §11.6: elements must appear in canonical order.
                    if (!prev.empty() && detail::der_set_of_less(h->full, prev))
                        return detail::fail<set_of<T>>(errc::non_canonical, h->offset);
                }
                prev = h->full;
                const auto before = s.offset();
                auto r = s.template read<T>();
                if (!r)
                    return std::unexpected(r.error());
                if (s.offset() == before) // non-consuming decode: never loop
                    return detail::fail<set_of<T>>(errc::invalid_value, before);
                out.items.push_back(std::move(*r));
            }
            return out;
        });
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const set_of<T> & v, tag t = type_tag) {
        if constexpr (!R::require_canonical) {
            return e.write_constructed(t, [&](encoder<R> & s) -> result<void> {
                for (const auto & item : v.items) {
                    auto r = codec_traits<T>::encode(s, item);
                    if (!r)
                        return r;
                }
                return {};
            });
        } else {
            std::vector<std::vector<std::byte>> encoded;
            encoded.reserve(v.items.size());
            for (const auto & item : v.items) {
                auto r = e.encode_detached([&](encoder<R> & s) { return codec_traits<T>::encode(s, item); });
                if (!r)
                    return std::unexpected(r.error());
                encoded.push_back(std::move(*r));
            }
            std::ranges::sort(encoded, [](const auto & a, const auto & b) { return detail::der_set_of_less(a, b); });
            return e.write_constructed(t, [&](encoder<R> & s) -> result<void> {
                for (const auto & item : encoded)
                    s.write_raw(item);
                return {};
            });
        }
    }
};

// ---- IMPLICIT / EXPLICIT tagging wrappers ----------------------------------//

template<std::uint32_t N, class T, tag_class C>
struct codec_traits<implicit<N, T, C>> {
    static_assert(
        requires { codec_traits<T>::type_tag; }, "asn1: IMPLICIT cannot retag an untagged type "
                                                 "(CHOICE / OPTIONAL / ANY); use asn1::explicit_ instead");
    static constexpr tag type_tag = implicit<N, T, C>::type_tag;
    static constexpr bool accepts(tag t, bool) noexcept {
        return t == type_tag;
    }
    template<encoding_rules R>
    static result<implicit<N, T, C>> decode(decoder<R> & d, tag t = type_tag) {
        auto r = codec_traits<T>::decode(d, t);
        if (!r)
            return std::unexpected(r.error());
        return implicit<N, T, C>{std::move(*r)};
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const implicit<N, T, C> & v, tag t = type_tag) {
        return codec_traits<T>::encode(e, v.value, t);
    }
};

template<std::uint32_t N, class T, tag_class C>
struct codec_traits<explicit_<N, T, C>> {
    static constexpr tag type_tag = explicit_<N, T, C>::type_tag;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<explicit_<N, T, C>> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_constructed(t, [](decoder<R> & s) -> result<explicit_<N, T, C>> {
            auto r = codec_traits<T>::decode(s);
            if (!r)
                return std::unexpected(r.error());
            return explicit_<N, T, C>{std::move(*r)};
        });
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const explicit_<N, T, C> & v, tag t = type_tag) {
        return e.write_constructed(t, [&](encoder<R> & s) { return codec_traits<T>::encode(s, v.value); });
    }
};

// ---- SEQUENCE: std::tuple / std::pair --------------------------------------//

namespace detail {
template<class Tuple, encoding_rules R>
result<Tuple> decode_tuple_like(decoder<R> & d, tag t) {
    return d.read_constructed(t, [](decoder<R> & s) -> result<Tuple> {
        Tuple out{};
        error err{};
        bool ok = true;
        std::apply(
            [&](auto &... m) {
                [[maybe_unused]] auto one = [&](auto & member) {
                    if (!ok)
                        return;
                    auto r = s.template read<std::remove_cvref_t<decltype(member)>>();
                    if (r)
                        member = std::move(*r);
                    else {
                        err = r.error();
                        ok = false;
                    }
                };
                (one(m), ...);
            },
            out);
        if (!ok)
            return std::unexpected(err);
        return out;
    });
}

template<class Tuple, encoding_rules R>
result<void> encode_tuple_like(encoder<R> & e, const Tuple & v, tag t) {
    return e.write_constructed(t, [&](encoder<R> & s) -> result<void> {
        result<void> rc{};
        std::apply(
            [&](const auto &... m) {
                [[maybe_unused]] auto one = [&](const auto & member) {
                    if (!rc)
                        return;
                    rc = codec_traits<std::remove_cvref_t<decltype(member)>>::encode(s, member);
                };
                (one(m), ...);
            },
            v);
        return rc;
    });
}
} // namespace detail

template<class... Ts>
struct codec_traits<std::tuple<Ts...>> {
    static constexpr tag type_tag = tags::sequence;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<std::tuple<Ts...>> decode(decoder<R> & d, tag t = type_tag) {
        return detail::decode_tuple_like<std::tuple<Ts...>>(d, t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::tuple<Ts...> & v, tag t = type_tag) {
        return detail::encode_tuple_like(e, v, t);
    }
};

template<class A, class B>
struct codec_traits<std::pair<A, B>> {
    static constexpr tag type_tag = tags::sequence;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<std::pair<A, B>> decode(decoder<R> & d, tag t = type_tag) {
        return detail::decode_tuple_like<std::pair<A, B>>(d, t);
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const std::pair<A, B> & v, tag t = type_tag) {
        return detail::encode_tuple_like(e, v, t);
    }
};

// ---- SEQUENCE: aggregate structs (the PFR auto-codec) ----------------------//

template<class T>
    requires reflect::reflectable<T> && (!std::is_enum_v<T>)
struct codec_traits<T> {
    static_assert(detail::seq_components_unambiguous<
                      std::remove_cvref_t<decltype(reflect::tie_members(std::declval<T &>()))>>::value(),
                  "asn1: an OPTIONAL member is followed by a member with the same tag "
                  "(X.680 §25.7) — absence would be undecidable; retag one of them "
                  "with asn1::implicit<N, T>");
    static constexpr tag type_tag = tags::sequence;
    static constexpr bool accepts(tag t, bool c) noexcept {
        return t == type_tag && c;
    }
    template<encoding_rules R>
    static result<T> decode(decoder<R> & d, tag t = type_tag) {
        return d.read_constructed(t, [](decoder<R> & s) -> result<T> {
            T out{};
            error err{};
            bool ok = true;
            std::apply(
                [&](auto &... m) {
                    [[maybe_unused]] auto one = [&](auto & member) {
                        if (!ok)
                            return;
                        auto r = s.template read<std::remove_cvref_t<decltype(member)>>();
                        if (r)
                            member = std::move(*r);
                        else {
                            err = r.error();
                            ok = false;
                        }
                    };
                    (one(m), ...);
                },
                reflect::tie_members(out));
            if (!ok)
                return std::unexpected(err);
            return out;
        });
    }
    template<encoding_rules R>
    static result<void> encode(encoder<R> & e, const T & v, tag t = type_tag) {
        return e.write_constructed(t, [&](encoder<R> & s) -> result<void> {
            result<void> rc{};
            std::apply(
                [&](const auto &... m) {
                    [[maybe_unused]] auto one = [&](const auto & member) {
                        if (!rc)
                            return;
                        rc = codec_traits<std::remove_cvref_t<decltype(member)>>::encode(s, member);
                    };
                    (one(m), ...);
                },
                reflect::tie_members(v));
            return rc;
        });
    }
};

} // namespace asn1
