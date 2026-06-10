// asn1/encoder.hpp — L1: typed encoding.
//
// Nested definite lengths are produced with a buffer stack: each open
// constructed scope accumulates its contents in its own buffer; on close,
// the identifier and (now known) length are emitted into the parent.
//
// The encoder always emits definite minimal lengths, minimal-octet
// integers and TRUE = 0xFF — output that is valid BER and, for types
// without BER-only freedoms, already DER-canonical. Under rules with
// require_canonical (DER), SET OF elements are additionally sorted per
// §11.6 (see codec_traits<set_of<T>>).
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <concepts>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "core.hpp"
#include "reader.hpp"
#include "rules.hpp"
#include "types.hpp"

namespace asn1 {

template<class T>
struct codec_traits;

namespace detail {

inline void put_u8(std::vector<std::byte> & out, std::uint8_t b) {
    out.push_back(static_cast<std::byte>(b));
}

inline void put_base128(std::vector<std::byte> & out, std::uint64_t v) {
    std::array<std::byte, 10> tmp;
    std::size_t n = 0;
    do {
        tmp[n++] = static_cast<std::byte>(v & 0x7F);
        v >>= 7;
    } while (v != 0);
    while (n-- > 1)
        out.push_back(tmp[n] | std::byte{0x80});
    out.push_back(tmp[0]);
}

inline void put_identifier(std::vector<std::byte> & out, tag t, bool constructed) {
    const auto lead = static_cast<std::uint8_t>((static_cast<std::uint8_t>(t.cls) << 6) | (constructed ? 0x20 : 0x00));
    if (t.number < 31) {
        put_u8(out, lead | static_cast<std::uint8_t>(t.number));
    } else {
        put_u8(out, lead | 0x1F);
        put_base128(out, t.number);
    }
}

inline void put_length(std::vector<std::byte> & out, std::uint64_t n) {
    if (n < 0x80) {
        put_u8(out, static_cast<std::uint8_t>(n));
        return;
    }
    std::array<std::byte, 8> tmp;
    std::size_t k = 0;
    while (n != 0) {
        tmp[k++] = static_cast<std::byte>(n & 0xFF);
        n >>= 8;
    }
    put_u8(out, static_cast<std::uint8_t>(0x80 | k));
    while (k-- > 0)
        out.push_back(tmp[k]);
}

// Minimal two's-complement contents octets of an INTEGER (§8.3).
inline void put_integer_contents(std::vector<std::byte> & out, std::int64_t v) {
    std::array<std::byte, 8> b;
    const auto u = std::bit_cast<std::uint64_t>(v);
    for (std::size_t i = 0; i < 8; ++i)
        b[i] = static_cast<std::byte>((u >> (8 * (7 - i))) & 0xFF);
    std::size_t i = 0;
    while (i + 1 < 8 && ((b[i] == std::byte{0x00} && (b[i + 1] & std::byte{0x80}) == std::byte{0x00}) ||
                         (b[i] == std::byte{0xFF} && (b[i + 1] & std::byte{0x80}) == std::byte{0x80})))
        ++i;
    out.insert(out.end(), b.data() + i, b.data() + 8);
}

inline void put_unsigned_contents(std::vector<std::byte> & out, std::uint64_t v) {
    std::array<std::byte, 9> b;
    b[0] = std::byte{0x00};
    for (std::size_t i = 0; i < 8; ++i)
        b[i + 1] = static_cast<std::byte>((v >> (8 * (7 - i))) & 0xFF);
    std::size_t i = 0;
    while (i + 1 < 9 && b[i] == std::byte{0x00} && (b[i + 1] & std::byte{0x80}) == std::byte{0x00})
        ++i;
    out.insert(out.end(), b.data() + i, b.data() + 9);
}

// §11.6 canonical SET OF ordering: compare encodings as octet strings,
// the shorter treated as padded at the end with 0x00.
inline bool der_set_of_less(bytes_view a, bytes_view b) noexcept {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    if (a.size() == b.size())
        return false;
    const auto & longer = a.size() > b.size() ? a : b;
    bool tail_nonzero = false;
    for (std::size_t i = n; i < longer.size(); ++i)
        if (longer[i] != std::byte{0x00})
            tail_nonzero = true;
    if (!tail_nonzero)
        return false;           // equal under padding
    return a.size() < b.size(); // the shorter one sorts first
}

} // namespace detail

template<encoding_rules R>
class encoder {
public:
    encoder() {
        stack_.emplace_back();
    }

    // --- primitives --- //

    result<void> write_bool(bool v, tag t = tags::boolean) {
        write_header(t, false, 1);
        detail::put_u8(buf(), v ? 0xFF : 0x00);
        return {};
    }

    template<class I>
        requires std::integral<I> && (!std::same_as<I, bool>)
    result<void> write_integer(I v, tag t = tags::integer) {
        std::vector<std::byte> c;
        if constexpr (std::unsigned_integral<I>) {
            detail::put_unsigned_contents(c, static_cast<std::uint64_t>(v));
        } else {
            detail::put_integer_contents(c, static_cast<std::int64_t>(v));
        }
        write_primitive(t, c);
        return {};
    }

    result<void> write_null(tag t = tags::null) {
        write_header(t, false, 0);
        return {};
    }

    result<void> write_octet_string(bytes_view v, tag t = tags::octet_string) {
        write_header(t, false, v.size());
        buf().insert(buf().end(), v.begin(), v.end());
        return {};
    }

    result<void> write_character_string(std::string_view v, tag t) {
        return write_octet_string(buffer_view(v), t);
    }

    result<void> write_bit_string(const bit_string & v, tag t = tags::bit_string) {
        if (v.unused_bits > 7 || (v.unused_bits > 0 && v.data.empty()))
            return detail::fail(errc::invalid_value, 0);
        auto s = v.data.span();
        write_header(t, false, s.size() + 1);
        detail::put_u8(buf(), v.unused_bits);
        if (!s.empty()) {
            buf().insert(buf().end(), s.begin(), s.end());
            if (v.unused_bits > 0) {
                // §11.2.1 (and harmless under BER): zero the unused padding bits.
                auto & last = buf().back();
                last &= static_cast<std::byte>(0xFF << v.unused_bits);
            }
        }
        return {};
    }

    result<void> write_object_identifier(const oid & v, tag t = tags::object_identifier) {
        if (!v.valid())
            return detail::fail(errc::invalid_value, 0);
        const auto arcs = v.arcs();
        // §8.19.4: first subidentifier = 40·X + Y.
        if (arcs[0] == 2 && arcs[1] > ~std::uint64_t{0} - 80)
            return detail::fail(errc::value_out_of_range, 0);
        std::vector<std::byte> c;
        detail::put_base128(c, arcs[0] * 40 + arcs[1]);
        for (std::size_t i = 2; i < arcs.size(); ++i)
            detail::put_base128(c, arcs[i]);
        write_primitive(t, c);
        return {};
    }

    result<void> write_relative_oid(const relative_oid & v, tag t = tags::relative_oid) {
        if (v.arcs().empty())
            return detail::fail(errc::invalid_value, 0);
        std::vector<std::byte> c;
        for (auto a : v.arcs())
            detail::put_base128(c, a);
        write_primitive(t, c);
        return {};
    }

    // REAL: emits the base-2 binary form (§8.5.7) with scale factor 0 and an
    // odd mantissa — canonical under DER (§11.3.1) and valid BER.
    result<void> write_real(double v, tag t = tags::real) {
        std::vector<std::byte> c;
        if (std::isnan(v)) {
            c.push_back(std::byte{0x42});
        } else if (std::isinf(v)) {
            c.push_back(v > 0 ? std::byte{0x40} : std::byte{0x41});
        } else if (v == 0.0) {
            if (std::signbit(v))
                c.push_back(std::byte{0x43});
            // +0.0: no contents octets (§8.5.2)
        } else {
            const bool negative = std::signbit(v);
            int e2 = 0;
            const double m = std::frexp(std::fabs(v), &e2); // m in [0.5, 1)
            auto mantissa = static_cast<std::uint64_t>(std::ldexp(m, std::numeric_limits<double>::digits));
            std::int64_t exponent = e2 - std::numeric_limits<double>::digits;
            while ((mantissa & 1) == 0) {
                mantissa >>= 1;
                ++exponent;
            }
            std::vector<std::byte> exp_octets;
            detail::put_integer_contents(exp_octets, exponent);
            // Exponent fits 1..3 octets for any double.
            const auto exp_len = static_cast<std::uint8_t>(exp_octets.size());
            detail::put_u8(c, static_cast<std::uint8_t>(0x80 | (negative ? 0x40 : 0x00) | (exp_len - 1)));
            c.insert(c.end(), exp_octets.begin(), exp_octets.end());
            std::array<std::byte, 8> mb;
            std::size_t k = 0;
            while (mantissa != 0) {
                mb[k++] = static_cast<std::byte>(mantissa & 0xFF);
                mantissa >>= 8;
            }
            while (k-- > 0)
                c.push_back(mb[k]);
        }
        write_primitive(t, c);
        return {};
    }

    // ANY / open type: re-emit a captured TLV verbatim. Under canonical
    // rules the captured bytes are structurally validated first (definite
    // minimal lengths, recursively) so BER freedoms captured from a lenient
    // decode cannot silently leak into DER output. Value-level canonicality
    // of the contents is the producer's responsibility (no schema here).
    result<void> write_any(const any & v) {
        if (v.full.empty())
            return detail::fail(errc::invalid_value, 0);
        if constexpr (R::require_canonical) {
            if (auto chk = check_strict(v.full.span()); !chk)
                return chk;
        }
        auto s = v.full.span();
        buf().insert(buf().end(), s.begin(), s.end());
        return {};
    }

    // --- constructed scope --- //

    template<class F>
        requires std::invocable<F &, encoder &>
    result<void> write_constructed(tag t, F && f) {
        stack_.emplace_back();
        result<void> r = f(*this);
        std::vector<std::byte> content = std::move(stack_.back());
        stack_.pop_back();
        if (!r)
            return r;
        write_header(t, true, content.size());
        buf().insert(buf().end(), content.begin(), content.end());
        return {};
    }

    // Encode a value into a detached buffer (used for §11.6 SET OF sorting).
    template<class F>
        requires std::invocable<F &, encoder &>
    result<std::vector<std::byte>> encode_detached(F && f) {
        stack_.emplace_back();
        result<void> r = f(*this);
        std::vector<std::byte> content = std::move(stack_.back());
        stack_.pop_back();
        if (!r)
            return std::unexpected(r.error());
        return content;
    }

    void write_raw(bytes_view v) {
        buf().insert(buf().end(), v.begin(), v.end());
    }

    // --- codec_traits dispatch --- //

    template<class T>
    result<void> write(const T & v) {
        return codec_traits<std::remove_cvref_t<T>>::encode(*this, v);
    }

    std::vector<std::byte> finish() && {
        return std::move(stack_.front());
    }

private:
    std::vector<std::byte> & buf() {
        return stack_.back();
    }

    static result<void> check_strict(bytes_view in) {
        reader<R> rd(in, decode_options{}.max_depth);
        auto el = rd.next();
        if (!el)
            return std::unexpected(el.error());
        if (!rd.empty())
            return detail::fail(errc::trailing_data, rd.offset());
        return check_strict_children(*el, decode_options{}.max_depth);
    }
    static result<void> check_strict_children(const element & el, std::uint32_t depth) {
        if (!el.constructed)
            return {};
        if (depth == 0)
            return detail::fail(errc::depth_exceeded, el.offset);
        reader<R> rd(el.content, depth);
        while (!rd.empty()) {
            auto child = rd.next();
            if (!child)
                return std::unexpected(child.error());
            if (auto r = check_strict_children(*child, depth - 1); !r)
                return r;
        }
        return {};
    }

    void write_header(tag t, bool constructed, std::uint64_t len) {
        detail::put_identifier(buf(), t, constructed);
        detail::put_length(buf(), len);
    }

    void write_primitive(tag t, const std::vector<std::byte> & content) {
        write_header(t, false, content.size());
        buf().insert(buf().end(), content.begin(), content.end());
    }

    std::vector<std::vector<std::byte>> stack_;
};

} // namespace asn1
