// asn1/types.hpp — ASN.1 value types: bytes, OIDs, BIT STRING, ANY,
// restricted character strings, time types, and tagging wrappers.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "core.hpp"

namespace asn1 {

// --- bytes: a view-or-owned byte container ------------------------------ //
//
// Decoding is zero-copy where possible: primitive string contents come back
// as views into the input buffer (the caller keeps the buffer alive).
// BER constructed-string reassembly necessarily allocates, producing the
// owned alternative. `to_owned()` detaches from the input buffer.
class bytes {
public:
    bytes() = default;
    explicit bytes(std::vector<std::byte> own)
        : data_(std::move(own)) {}

    static bytes view(bytes_view v) {
        return bytes(v);
    }
    static bytes copy(bytes_view v) {
        return bytes(std::vector<std::byte>(v.begin(), v.end()));
    }

    [[nodiscard]] bytes_view span() const noexcept {
        if (auto * v = std::get_if<bytes_view>(&data_))
            return *v;
        return std::get<std::vector<std::byte>>(data_);
    }
    [[nodiscard]] std::size_t size() const noexcept {
        return span().size();
    }
    [[nodiscard]] bool empty() const noexcept {
        return span().empty();
    }
    [[nodiscard]] bool owning() const noexcept {
        return data_.index() == 1;
    }

    bytes & to_owned() {
        if (!owning())
            *this = copy(span());
        return *this;
    }

    friend bool operator==(const bytes & a, const bytes & b) noexcept {
        auto sa = a.span(), sb = b.span();
        return std::equal(sa.begin(), sa.end(), sb.begin(), sb.end());
    }

private:
    explicit bytes(bytes_view v)
        : data_(v) {}
    std::variant<bytes_view, std::vector<std::byte>> data_{bytes_view{}};
};

// --- NULL ---------------------------------------------------------------- //

struct null_t {
    friend constexpr bool operator==(null_t, null_t) noexcept {
        return true;
    }
};
inline constexpr null_t null{};

// --- OBJECT IDENTIFIER / RELATIVE-OID (§8.19, §8.20) --------------------- //

class oid {
public:
    oid() = default;
    oid(std::initializer_list<std::uint64_t> arcs)
        : arcs_(arcs) {}
    explicit oid(std::vector<std::uint64_t> arcs)
        : arcs_(std::move(arcs)) {}

    // Parse dotted notation, e.g. "1.2.840.113549.1.1.11".
    static result<oid> parse(std::string_view dotted);

    [[nodiscard]] std::span<const std::uint64_t> arcs() const noexcept {
        return arcs_;
    }
    [[nodiscard]] std::size_t size() const noexcept {
        return arcs_.size();
    }
    std::uint64_t operator[](std::size_t i) const noexcept {
        return arcs_[i];
    }
    [[nodiscard]] std::string to_string() const;

    // X.660 constraints: at least two arcs; first arc 0-2; second arc < 40
    // unless the first is 2.
    [[nodiscard]] bool valid() const noexcept {
        return arcs_.size() >= 2 && arcs_[0] <= 2 && (arcs_[0] == 2 || arcs_[1] < 40);
    }

    friend bool operator==(const oid &, const oid &) = default;
    friend auto operator<=>(const oid &, const oid &) = default;

private:
    std::vector<std::uint64_t> arcs_;
};

class relative_oid {
public:
    relative_oid() = default;
    relative_oid(std::initializer_list<std::uint64_t> arcs)
        : arcs_(arcs) {}
    explicit relative_oid(std::vector<std::uint64_t> arcs)
        : arcs_(std::move(arcs)) {}

    [[nodiscard]] std::span<const std::uint64_t> arcs() const noexcept {
        return arcs_;
    }
    [[nodiscard]] std::size_t size() const noexcept {
        return arcs_.size();
    }
    [[nodiscard]] std::string to_string() const;

    friend bool operator==(const relative_oid &, const relative_oid &) = default;

private:
    std::vector<std::uint64_t> arcs_;
};

// --- BIT STRING (§8.6) ---------------------------------------------------- //

struct bit_string {
    bytes data{};
    std::uint8_t unused_bits{0}; // 0..7, in the final octet

    [[nodiscard]] std::size_t bit_count() const noexcept {
        auto n = data.size();
        return n == 0 ? 0 : n * 8 - unused_bits;
    }
    // Bit 0 is the most significant bit of the first octet (§8.6.2).
    [[nodiscard]] bool bit(std::size_t i) const noexcept {
        auto b = std::to_integer<std::uint8_t>(data.span()[i / 8]);
        return (b >> (7 - i % 8)) & 1;
    }

    friend bool operator==(const bit_string & a, const bit_string & b) noexcept {
        return a.unused_bits == b.unused_bits && a.data == b.data;
    }
};

// --- ANY / open type ------------------------------------------------------ //
//
// Captures one complete TLV verbatim (`full` keeps identifier + length +
// contents, the Go RawValue lesson: re-emitting must be byte-exact).
struct any {
    asn1::tag tag{};
    bool constructed = false;
    bytes content{};
    bytes full{};

    any & to_owned() {
        content.to_owned();
        full.to_owned();
        return *this;
    }
    friend bool operator==(const any & a, const any & b) noexcept {
        return a.full == b.full;
    }
};

// --- restricted character strings (§8.23) --------------------------------- //

template<std::uint32_t TagNumber>
struct restricted_string {
    static constexpr asn1::tag type_tag{tag_class::universal, TagNumber};
    std::string value;

    restricted_string() = default;
    restricted_string(std::string v)
        : value(std::move(v)) {}
    restricted_string(const char * v)
        : value(v) {}

    friend bool operator==(const restricted_string &, const restricted_string &) = default;
    friend auto operator<=>(const restricted_string &, const restricted_string &) = default;
};

using numeric_string = restricted_string<18>;
using printable_string = restricted_string<19>;
using teletex_string = restricted_string<20>;
using videotex_string = restricted_string<21>;
using ia5_string = restricted_string<22>;
using graphic_string = restricted_string<25>;
using visible_string = restricted_string<26>;
using general_string = restricted_string<27>;
using object_descriptor = restricted_string<7>;

// UniversalString (UCS-4 BE) and BMPString (UCS-2 BE), §8.23.7/8.23.8.
struct bmp_string {
    std::u16string value;
    friend bool operator==(const bmp_string &, const bmp_string &) = default;
};
struct universal_string {
    std::u32string value;
    friend bool operator==(const universal_string &, const universal_string &) = default;
};

// --- time types (§8.25, X.680 §46/§47) ------------------------------------ //
//
// Values are normalized to UTC on decode when a zone is present. A BER
// sender may omit the zone ("local time"); we record that and interpret
// the fields as-if UTC. Encoding always produces the canonical Z form.
struct utc_time {
    std::chrono::sys_seconds value{};
    bool local = false;

    friend bool operator==(const utc_time & a, const utc_time & b) noexcept {
        return a.value == b.value;
    }
};

struct generalized_time {
    std::chrono::sys_time<std::chrono::milliseconds> value{};
    bool local = false;

    friend bool operator==(const generalized_time & a, const generalized_time & b) noexcept {
        return a.value == b.value;
    }
};

// --- tagging wrappers (§8.14) ---------------------------------------------//
//
// IMPLICIT: replaces the identifier octets of the base encoding.
// EXPLICIT: wraps the complete base TLV in a constructed outer TLV.
template<std::uint32_t N, class T, tag_class C = tag_class::context_specific>
struct implicit {
    static constexpr asn1::tag type_tag{C, N};
    T value{};

    friend bool operator==(const implicit &, const implicit &) = default;
};

template<std::uint32_t N, class T, tag_class C = tag_class::context_specific>
struct explicit_ { // NOLINT(readability-identifier-naming) -- 'explicit' is a keyword
    static constexpr asn1::tag type_tag{C, N};
    T value{};

    friend bool operator==(const explicit_ &, const explicit_ &) = default;
};

// --- SET OF ----------------------------------------------------------------//
//
// std::vector<T> maps to SEQUENCE OF; set_of<T> maps to SET OF (tag 17).
// Under DER, elements are emitted in the §11.6 canonical order.
template<class T>
struct set_of {
    std::vector<T> items;

    friend bool operator==(const set_of &, const set_of &) = default;
};

// --- inline implementations ------------------------------------------------//

inline result<oid> oid::parse(std::string_view dotted) {
    std::vector<std::uint64_t> arcs;
    std::uint64_t acc = 0;
    bool have_digit = false;
    for (std::size_t i = 0; i <= dotted.size(); ++i) {
        if (i == dotted.size() || dotted[i] == '.') {
            if (!have_digit)
                return detail::fail(errc::invalid_value, i);
            arcs.push_back(acc);
            acc = 0;
            have_digit = false;
            continue;
        }
        const char c = dotted[i];
        if (c < '0' || c > '9')
            return detail::fail(errc::invalid_value, i);
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (acc > (~std::uint64_t{0} - d) / 10)
            return detail::fail(errc::value_out_of_range, i);
        acc = acc * 10 + d;
        have_digit = true;
    }
    oid o(std::move(arcs));
    if (!o.valid())
        return detail::fail(errc::invalid_value, 0);
    return o;
}

namespace detail {
inline std::string arcs_to_string(std::span<const std::uint64_t> arcs) {
    std::string out;
    for (std::size_t i = 0; i < arcs.size(); ++i) {
        if (i)
            out += '.';
        out += std::to_string(arcs[i]);
    }
    return out;
}
} // namespace detail

inline std::string oid::to_string() const {
    return detail::arcs_to_string(arcs_);
}
inline std::string relative_oid::to_string() const {
    return detail::arcs_to_string(arcs_);
}

} // namespace asn1
