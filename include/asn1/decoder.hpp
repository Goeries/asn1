// asn1/decoder.hpp — L1: typed decoding against the X.690 engine.
//
// Closure-scoped constructed types: read_constructed(tag, f) hands `f` a
// sub-decoder over the contents and verifies on return that the scope was
// fully consumed — balanced nesting and end-of-contents checks are
// structural, not a calling discipline.
//
// After any method returns an error the decoder's position is unspecified;
// callers must stop (results propagate errors naturally).
#pragma once

#include <bit>
#include <charconv>
#include <cmath>
#include <concepts>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "core.hpp"
#include "reader.hpp"
#include "rules.hpp"
#include "types.hpp"

namespace asn1 {

template<class T>
struct codec_traits; // defined per type in traits.hpp

template<encoding_rules R>
class decoder {
public:
    enum class form : std::uint8_t { primitive, constructed, any };

    explicit decoder(bytes_view in, decode_options opt = {})
        : decoder(in, opt, 0, 0) {}

    [[nodiscard]] bool at_end() const noexcept {
        return rd_.empty();
    }
    [[nodiscard]] std::size_t offset() const noexcept {
        return rd_.offset();
    }
    [[nodiscard]] bytes_view remaining() const noexcept {
        return rd_.remaining();
    }
    [[nodiscard]] const decode_options & options() const noexcept {
        return opt_;
    }

    [[nodiscard]] result<element> peek() const {
        return rd_.peek();
    }

    result<void> expect_end() {
        if (!at_end())
            return detail::fail(errc::trailing_data, offset());
        return {};
    }

    // Consume one element, requiring an exact tag and an allowed form.
    result<element> read_element(tag t, form f) {
        auto el = rd_.next();
        if (!el)
            return el;
        if (el->tag != t)
            return detail::fail_tag(el->offset, t, el->tag);
        if (f == form::primitive && el->constructed)
            return detail::fail(errc::unexpected_constructed, el->offset);
        if (f == form::constructed && !el->constructed)
            return detail::fail(errc::unexpected_constructed, el->offset);
        return el;
    }

    // --- BOOLEAN (§8.2) --- //
    result<bool> read_bool(tag t = tags::boolean) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        if (el->content.size() != 1)
            return detail::fail(errc::invalid_value, el->offset);
        const auto v = std::to_integer<std::uint8_t>(el->content[0]);
        if constexpr (R::require_canonical) {
            if (v != 0x00 && v != 0xFF) // §11.1
                return detail::fail(errc::non_canonical, el->offset);
        }
        return v != 0;
    }

    // --- INTEGER / ENUMERATED (§8.3, §8.4) --- //
    template<class I>
        requires std::integral<I> && (!std::same_as<I, bool>)
    result<I> read_integer(tag t = tags::integer) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        const auto c = el->content;
        if (c.empty())
            return detail::fail(errc::invalid_value, el->offset);
        if (c.size() >= 2) {
            // §8.3.2: minimal two's complement, mandatory even in BER.
            const auto b0 = std::to_integer<std::uint8_t>(c[0]);
            const auto b1 = std::to_integer<std::uint8_t>(c[1]);
            if (b0 == 0x00 && (b1 & 0x80) == 0)
                return detail::fail(errc::invalid_value, el->offset);
            if (b0 == 0xFF && (b1 & 0x80) != 0)
                return detail::fail(errc::invalid_value, el->offset);
        }
        const bool negative = (std::to_integer<std::uint8_t>(c[0]) & 0x80) != 0;
        if constexpr (std::unsigned_integral<I>) {
            if (negative)
                return detail::fail(errc::value_out_of_range, el->offset);
            // A leading 0x00 octet is significant only as a sign octet.
            auto eff = (std::to_integer<std::uint8_t>(c[0]) == 0 && c.size() > 1) ? c.subspan(1) : c;
            if (eff.size() > sizeof(std::uint64_t))
                return detail::fail(errc::value_out_of_range, el->offset);
            std::uint64_t u = 0;
            for (auto b : eff)
                u = (u << 8) | std::to_integer<std::uint8_t>(b);
            if (u > std::numeric_limits<I>::max())
                return detail::fail(errc::value_out_of_range, el->offset);
            return static_cast<I>(u);
        } else {
            if (c.size() > sizeof(std::int64_t))
                return detail::fail(errc::value_out_of_range, el->offset);
            std::uint64_t u = negative ? ~std::uint64_t{0} : 0;
            for (auto b : c)
                u = (u << 8) | std::to_integer<std::uint8_t>(b);
            const auto v = std::bit_cast<std::int64_t>(u);
            if (v < std::numeric_limits<I>::min() || v > std::numeric_limits<I>::max())
                return detail::fail(errc::value_out_of_range, el->offset);
            return static_cast<I>(v);
        }
    }

    // --- NULL (§8.8) --- //
    result<null_t> read_null(tag t = tags::null) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        if (!el->content.empty())
            return detail::fail(errc::invalid_value, el->offset);
        return null;
    }

    // --- OCTET STRING (§8.7), incl. BER constructed reassembly --- //
    result<bytes> read_octet_string(tag t = tags::octet_string) {
        auto el = read_element(t, string_form());
        if (!el)
            return std::unexpected(el.error());
        if (!el->constructed)
            return bytes::view(el->content);
        std::vector<std::byte> out;
        auto r = collect_octets(el->content, content_offset(*el), depth_ + 1, out);
        if (!r)
            return std::unexpected(r.error());
        return bytes(std::move(out));
    }

    // Restricted character strings: outer tag varies, constructed segments
    // are OCTET STRINGs (§8.23.6; cf. the §8.21 "Jones" example).
    result<std::string> read_character_string(tag t) {
        auto b = read_octet_string(t);
        if (!b)
            return std::unexpected(b.error());
        auto s = b->span();
        return std::string(reinterpret_cast<const char *>(s.data()), s.size());
    }

    // --- BIT STRING (§8.6) --- //
    result<bit_string> read_bit_string(tag t = tags::bit_string) {
        auto el = read_element(t, string_form());
        if (!el)
            return std::unexpected(el.error());
        if (!el->constructed) {
            auto r = parse_primitive_bits(el->content, el->offset);
            if (!r)
                return std::unexpected(r.error());
            if constexpr (R::require_canonical) {
                // §11.2.1: unused padding bits shall be zero.
                if (r->unused_bits != 0) {
                    const auto last = r->data.span().back();
                    const auto mask = static_cast<std::uint8_t>((1u << r->unused_bits) - 1);
                    if ((std::to_integer<std::uint8_t>(last) & mask) != 0)
                        return detail::fail(errc::non_canonical, el->offset);
                }
            }
            return r;
        }
        std::vector<std::byte> out;
        std::uint8_t unused = 0;
        auto r = collect_bits(el->content, content_offset(*el), depth_ + 1, out, unused);
        if (!r)
            return std::unexpected(r.error());
        return bit_string{bytes(std::move(out)), unused};
    }

    // --- OBJECT IDENTIFIER / RELATIVE-OID (§8.19, §8.20) --- //
    result<oid> read_object_identifier(tag t = tags::object_identifier) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        if (el->content.empty())
            return detail::fail(errc::invalid_value, el->offset);
        auto subids = parse_subidentifiers(el->content, el->offset);
        if (!subids)
            return std::unexpected(subids.error());
        std::vector<std::uint64_t> arcs;
        arcs.reserve(subids->size() + 1);
        // §8.19.4: first subidentifier packs the first two arcs as 40·X + Y.
        const auto first = (*subids)[0];
        if (first < 40) {
            arcs.push_back(0);
            arcs.push_back(first);
        } else if (first < 80) {
            arcs.push_back(1);
            arcs.push_back(first - 40);
        } else {
            arcs.push_back(2);
            arcs.push_back(first - 80);
        }
        arcs.insert(arcs.end(), subids->begin() + 1, subids->end());
        return oid(std::move(arcs));
    }

    result<relative_oid> read_relative_oid(tag t = tags::relative_oid) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        // X.680 §33: at least one component.
        if (el->content.empty())
            return detail::fail(errc::invalid_value, el->offset);
        auto subids = parse_subidentifiers(el->content, el->offset);
        if (!subids)
            return std::unexpected(subids.error());
        return relative_oid(std::move(*subids));
    }

    // --- REAL (§8.5) --- //
    result<double> read_real(tag t = tags::real) {
        auto el = read_element(t, form::primitive);
        if (!el)
            return std::unexpected(el.error());
        const auto c = el->content;
        if (c.empty())
            return 0.0; // §8.5.2: zero has no contents octets
        const auto b0 = std::to_integer<std::uint8_t>(c[0]);
        if (b0 & 0x80)
            return decode_binary_real(c, el->offset);
        if ((b0 & 0xC0) == 0x40) { // §8.5.9: SpecialRealValues
            if (c.size() != 1)
                return detail::fail(errc::invalid_value, el->offset);
            switch (b0) {
            case 0x40:
                return std::numeric_limits<double>::infinity();
            case 0x41:
                return -std::numeric_limits<double>::infinity();
            case 0x42:
                return std::numeric_limits<double>::quiet_NaN();
            case 0x43:
                return -0.0;
            default:
                return detail::fail(errc::invalid_value, el->offset);
            }
        }
        return decode_decimal_real(c, el->offset); // §8.5.8: ISO 6093
    }

    // --- ANY / open type --- //
    result<any> read_any() {
        auto el = rd_.next();
        if (!el)
            return std::unexpected(el.error());
        any a;
        a.tag = el->tag;
        a.constructed = el->constructed;
        a.content = bytes::view(el->content);
        a.full = bytes::view(el->full);
        return a;
    }

    // --- constructed scope --- //
    template<class F>
        requires std::invocable<F &, decoder &>
    auto read_constructed(tag t, F && f) -> std::invoke_result_t<F &, decoder &> {
        using ret = std::invoke_result_t<F &, decoder &>;
        auto el = read_element(t, form::constructed);
        if (!el)
            return ret(std::unexpected(el.error()));
        if (depth_ + 1 > opt_.max_depth)
            return ret(detail::fail(errc::depth_exceeded, el->offset));
        decoder sub(el->content, opt_, content_offset(*el), depth_ + 1);
        ret r = f(sub);
        if (r) {
            if (auto e = sub.expect_end(); !e)
                return ret(std::unexpected(e.error()));
        }
        return r;
    }

    // --- codec_traits dispatch --- //
    template<class T>
    result<std::remove_cvref_t<T>> read() {
        return codec_traits<std::remove_cvref_t<T>>::decode(*this);
    }

private:
    decoder(bytes_view in, decode_options opt, std::size_t base, std::uint32_t depth)
        : rd_(in, opt.max_depth, base),
          opt_(opt),
          depth_(depth) {}

    static constexpr form string_form() noexcept {
        return R::allow_constructed_strings ? form::any : form::primitive;
    }

    static std::size_t content_offset(const element & el) noexcept {
        return el.offset + static_cast<std::size_t>(el.content.data() - el.full.data());
    }

    result<void> collect_octets(bytes_view content, std::size_t off, std::uint32_t depth,
                                std::vector<std::byte> & out) {
        if (depth > opt_.max_depth)
            return detail::fail(errc::depth_exceeded, off);
        reader<R> sub(content, opt_.max_depth, off);
        while (!sub.empty()) {
            auto el = sub.next();
            if (!el)
                return std::unexpected(el.error());
            // §8.7.3.1: segments of a constructed OCTET STRING (and of constructed
            // character strings) are OCTET STRINGs.
            if (el->tag != tags::octet_string)
                return detail::fail_tag(el->offset, tags::octet_string, el->tag);
            if (el->constructed) {
                auto r = collect_octets(el->content, content_offset(*el), depth + 1, out);
                if (!r)
                    return r;
            } else {
                out.insert(out.end(), el->content.begin(), el->content.end());
            }
        }
        return {};
    }

    result<bit_string> parse_primitive_bits(bytes_view c, std::size_t off) {
        // §8.6.2.2: initial octet counts unused bits, 0..7.
        if (c.empty())
            return detail::fail(errc::invalid_value, off);
        const auto unused = std::to_integer<std::uint8_t>(c[0]);
        if (unused > 7)
            return detail::fail(errc::invalid_value, off);
        if (unused > 0 && c.size() == 1)
            return detail::fail(errc::invalid_value, off);
        return bit_string{bytes::view(c.subspan(1)), unused};
    }

    result<void> collect_bits(bytes_view content, std::size_t off, std::uint32_t depth, std::vector<std::byte> & out,
                              std::uint8_t & unused) {
        if (depth > opt_.max_depth)
            return detail::fail(errc::depth_exceeded, off);
        reader<R> sub(content, opt_.max_depth, off);
        while (!sub.empty()) {
            auto el = sub.next();
            if (!el)
                return std::unexpected(el.error());
            if (el->tag != tags::bit_string)
                return detail::fail_tag(el->offset, tags::bit_string, el->tag);
            // §8.6.4: every segment except the last must end on an octet boundary.
            if (unused != 0)
                return detail::fail(errc::invalid_value, el->offset);
            if (el->constructed) {
                auto r = collect_bits(el->content, content_offset(*el), depth + 1, out, unused);
                if (!r)
                    return r;
            } else {
                auto seg = parse_primitive_bits(el->content, el->offset);
                if (!seg)
                    return std::unexpected(seg.error());
                auto s = seg->data.span();
                out.insert(out.end(), s.begin(), s.end());
                unused = seg->unused_bits;
            }
        }
        return {};
    }

    result<std::vector<std::uint64_t>> parse_subidentifiers(bytes_view c, std::size_t off) {
        std::vector<std::uint64_t> subids;
        std::size_t i = 0;
        while (i < c.size()) {
            // §8.19.2: leading octet of a subidentifier shall not be 0x80.
            if (std::to_integer<std::uint8_t>(c[i]) == 0x80)
                return detail::fail(errc::invalid_value, off + i);
            std::uint64_t acc = 0;
            while (true) {
                if (i >= c.size()) // continuation bit set on the final octet
                    return detail::fail(errc::invalid_value, off + i - 1);
                const auto b = std::to_integer<std::uint8_t>(c[i]);
                ++i;
                if (acc > (~std::uint64_t{0} >> 7))
                    return detail::fail(errc::value_out_of_range, off + i - 1);
                acc = (acc << 7) | (b & 0x7F);
                if ((b & 0x80) == 0)
                    break;
            }
            subids.push_back(acc);
        }
        return subids;
    }

    result<double> decode_binary_real(bytes_view c, std::size_t off) {
        const auto b0 = std::to_integer<std::uint8_t>(c[0]);
        const bool negative = (b0 & 0x40) != 0;
        const unsigned base_bits = (b0 >> 4) & 0x3;
        if (base_bits == 3)
            return detail::fail(errc::invalid_value, off);
        const int log2_base = base_bits == 0 ? 1 : (base_bits == 1 ? 3 : 4);
        const unsigned scale = (b0 >> 2) & 0x3; // F: 0..3
        const unsigned exp_form = b0 & 0x3;

        std::size_t i = 1;
        std::size_t exp_len = 0;
        if (exp_form < 3) {
            exp_len = exp_form + 1;
        } else {
            if (c.size() < 2)
                return detail::fail(errc::invalid_value, off);
            exp_len = std::to_integer<std::uint8_t>(c[1]);
            i = 2;
            if (exp_len == 0)
                return detail::fail(errc::invalid_value, off);
        }
        if (c.size() - i < exp_len)
            return detail::fail(errc::invalid_value, off);

        // §8.5.7.4 d: with an explicit exponent length, the first nine bits
        // shall not all be zero or all ones.
        if (exp_form == 3 && exp_len >= 2) {
            const auto e0 = std::to_integer<std::uint8_t>(c[i]);
            const auto e1 = std::to_integer<std::uint8_t>(c[i + 1]);
            if ((e0 == 0x00 && (e1 & 0x80) == 0) || (e0 == 0xFF && (e1 & 0x80) != 0))
                return detail::fail(errc::invalid_value, off);
        }

        // Two's-complement exponent, saturated far past double's range. The
        // accumulation cap must dominate the 8*dropped mantissa adjustment
        // below so a saturated exponent cannot be flipped by a huge mantissa.
        constexpr std::int64_t exp_acc_cap = std::int64_t{1} << 40;
        std::int64_t exponent = (std::to_integer<std::uint8_t>(c[i]) & 0x80) ? -1 : 0;
        for (std::size_t k = 0; k < exp_len; ++k) {
            exponent = (exponent << 8) | std::to_integer<std::uint8_t>(c[i + k]);
            if (exponent > exp_acc_cap)
                exponent = exp_acc_cap;
            if (exponent < -exp_acc_cap)
                exponent = -exp_acc_cap;
        }
        i += exp_len;

        if constexpr (R::require_canonical) {
            // §11.3.1: base 2, scale factor 0, minimal octets, mantissa odd
            // (zero must use the empty-contents form, §8.5.2).
            if (base_bits != 0 || scale != 0)
                return detail::fail(errc::non_canonical, off);
            if (i >= c.size() || std::to_integer<std::uint8_t>(c[i]) == 0 ||
                (std::to_integer<std::uint8_t>(c.back()) & 1) == 0)
                return detail::fail(errc::non_canonical, off);
        }

        // Mantissa N is unbounded in BER. Keep the 64 most significant bits
        // (octet-aligned) and fold the dropped low-order octets into the
        // exponent; a sticky bit preserves correct round-to-nearest when the
        // value is later rounded to double.
        while (i < c.size() && std::to_integer<std::uint8_t>(c[i]) == 0)
            ++i;
        std::uint64_t mantissa = 0;
        std::size_t taken = 0;
        for (; i < c.size() && taken < sizeof(std::uint64_t); ++i, ++taken)
            mantissa = (mantissa << 8) | std::to_integer<std::uint8_t>(c[i]);
        const std::uint64_t dropped = c.size() - i;
        bool sticky = false;
        for (std::size_t k = i; k < c.size(); ++k)
            if (std::to_integer<std::uint8_t>(c[k]) != 0)
                sticky = true;
        if (sticky)
            mantissa |= 1;

        constexpr std::int64_t exp_cap = 1 << 24; // clamp into ldexp's int range
        std::int64_t shift =
            static_cast<std::int64_t>(scale) + exponent * log2_base + static_cast<std::int64_t>(8 * dropped);
        if (shift > exp_cap)
            shift = exp_cap;
        if (shift < -exp_cap)
            shift = -exp_cap;
        const long double v = std::ldexp(static_cast<long double>(mantissa), static_cast<int>(shift));
        return static_cast<double>(negative ? -v : v);
    }

    result<double> decode_decimal_real(bytes_view c, std::size_t off) {
        const auto nr = std::to_integer<std::uint8_t>(c[0]);
        if (nr != 0x01 && nr != 0x02 && nr != 0x03)
            return detail::fail(errc::invalid_value, off);
        if constexpr (R::require_canonical) {
            if (nr != 0x03) // §11.3.2: NR3 only
                return detail::fail(errc::non_canonical, off);
        }
        // Normalize the ISO 6093 field: strip leading spaces and '+', map the
        // comma decimal mark to '.'.
        std::string text;
        text.reserve(c.size() - 1);
        bool lead = true;
        for (std::size_t i = 1; i < c.size(); ++i) {
            const char ch = static_cast<char>(std::to_integer<std::uint8_t>(c[i]));
            if (lead && (ch == ' ' || ch == '+')) {
                if (ch == '+')
                    lead = false;
                continue;
            }
            lead = false;
            text.push_back(ch == ',' ? '.' : ch);
        }
        if (text.empty())
            return detail::fail(errc::invalid_value, off);
        // ISO 6093 fields are digits with optional sign, point and exponent;
        // anything else (notably from_chars' "inf"/"nan" forms) is malformed.
        bool has_digit = false;
        for (const char ch : text) {
            if (ch >= '0' && ch <= '9')
                has_digit = true;
            else if (ch != '.' && ch != '+' && ch != '-' && ch != 'e' && ch != 'E')
                return detail::fail(errc::invalid_value, off);
        }
        if (!has_digit)
            return detail::fail(errc::invalid_value, off);
        double v = 0.0;
        auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
        if (ec == std::errc::result_out_of_range && end == text.data() + text.size()) {
            // Saturate like the binary path: overflow to ±inf, underflow to ±0.
            return decimal_saturate(text);
        }
        if (ec != std::errc{} || end != text.data() + text.size())
            return detail::fail(errc::invalid_value, off);
        return v;
    }

    // Decide overflow vs underflow for an out-of-double-range ISO 6093 field
    // from its decimal-exponent estimate.
    static double decimal_saturate(std::string_view text) {
        const bool negative = !text.empty() && text.front() == '-';
        std::int64_t exp10 = 0;
        if (auto e = text.find_first_of("eE"); e != std::string_view::npos) {
            auto es = text.substr(e + 1);
            (void)std::from_chars(es.data(), es.data() + es.size(), exp10);
            text = text.substr(0, e);
        }
        // Position of the first significant digit relative to the point.
        std::int64_t int_digits = 0, lead_zeros = 0;
        bool seen_point = false, seen_sig = false;
        for (const char ch : text) {
            if (ch == '.') {
                seen_point = true;
                continue;
            }
            if (ch < '0' || ch > '9')
                continue;
            if (ch != '0')
                seen_sig = true;
            if (!seen_sig && seen_point)
                ++lead_zeros;
            if (seen_sig && !seen_point)
                ++int_digits;
        }
        const std::int64_t estimate = exp10 + (int_digits > 0 ? int_digits : -lead_zeros);
        const double mag = estimate > 0 ? std::numeric_limits<double>::infinity() : 0.0;
        return negative ? -mag : mag;
    }

    reader<R> rd_;
    decode_options opt_;
    std::uint32_t depth_;
};

} // namespace asn1
