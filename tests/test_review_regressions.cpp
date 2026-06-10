// Regression tests for the confirmed findings of the multi-agent
// compliance review (X.690 references inline).
#include <bit>
#include <cmath>
#include <cstdint>
#include <limits>

#include <doctest/doctest.h>

#include "helpers.hpp"

using asn1::ber_codec;
using asn1::der_codec;
using asn1::errc;

namespace {
struct one_int {
    std::int32_t v = 0;
};
} // namespace

TEST_CASE("BER accepts long-form lengths with leading zero octets") {
    // SEQUENCE, length 3 encoded in 9 long-form octets (valid BER, §8.1.3.5;
    // length minimality is a DER-only restriction, §10.1).
    auto buf = H("30 89 00 00 00 00 00 00 00 00 03 02 01 7F");
    auto r = ber_codec::decode<one_int>(buf);
    REQUIRE(r);
    CHECK_EQ(r->v, 127);
    // DER rejects it as non-minimal (accurate error code).
    CHECK_ERR(der_codec::decode<one_int>(buf), errc::non_minimal_length);

    // Spec-maximum 126 length octets, mostly zeros.
    std::vector<std::byte> big = H("04 FE");
    for (int i = 0; i < 125; ++i)
        big.push_back(std::byte{0x00});
    big.push_back(std::byte{0x01});
    big.push_back(std::byte{0xAB});
    auto rb = ber_codec::decode<std::vector<std::byte>>(big);
    REQUIRE(rb);
    CHECK_EQ(hexstr(*rb), "AB");

    // A genuinely 2^64-overflowing length is still rejected.
    CHECK_ERR(ber_codec::decode<std::vector<std::byte>>(H("04 89 01 00 00 00 00 00 00 00 00")), errc::invalid_length);
}

TEST_CASE("binary REAL: wide mantissas decode exactly (no FP accumulation)") {
    // 2^16792 * 2^-17800 = 2^-1008: mantissa is 0x01 followed by 2099 zero
    // octets, exponent -17800 in two octets. Previously overflowed to +inf.
    std::vector<std::byte> buf = H("09 82 08 37 81 BA 78 01");
    for (int i = 0; i < 2099; ++i)
        buf.push_back(std::byte{0x00});
    auto r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, std::ldexp(1.0, -1008));

    // Correct round-to-nearest across the dropped-octet boundary:
    // N = 2^64 + 2^11 + 1, E = 0 -> nearest double is 2^64 + 2^12.
    auto buf2 = H("09 0B 80 00 01 00 00 00 00 00 00 08 01");
    auto r2 = ber_codec::decode<double>(buf2);
    REQUIRE(r2);
    CHECK_EQ(std::bit_cast<std::uint64_t>(*r2), 0x43F0000000000001ULL);

    // Saturation for truly out-of-range values still works.
    auto huge = H("09 05 81 7F FF FF 01"); // 1 * 2^(2^23-ish)
    auto rh = ber_codec::decode<double>(huge);
    REQUIRE(rh);
    CHECK_EQ(*rh, std::numeric_limits<double>::infinity());
}

TEST_CASE("DER binary REAL canonical checks (§11.3.1)") {
    // Even mantissa: valid BER, non-canonical DER.
    auto even = H("09 03 80 00 0A");
    CHECK_EQ(ber_codec::decode<double>(even), asn1::result<double>(10.0));
    CHECK_ERR(der_codec::decode<double>(even), errc::non_canonical);

    // Odd mantissa passes DER.
    auto odd = H("09 03 80 01 05");
    CHECK_EQ(der_codec::decode<double>(odd), asn1::result<double>(10.0));

    // Binary-form zero (mantissa absent or 0) must use empty contents.
    auto bzero = H("09 03 80 00 00");
    CHECK_EQ(ber_codec::decode<double>(bzero), asn1::result<double>(0.0));
    CHECK_ERR(der_codec::decode<double>(bzero), errc::non_canonical);

    // Leading zero mantissa octet is non-minimal.
    CHECK_ERR(der_codec::decode<double>(H("09 04 80 00 00 05")), errc::non_canonical);
}

TEST_CASE("decimal REAL rejects from_chars special-value text") {
    // "inf" / "nan" / "INFINITY" are not ISO 6093 fields.
    CHECK_ERR(ber_codec::decode<double>(H("09 04 03 69 6E 66")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<double>(H("09 04 03 6E 61 6E")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<double>(H("09 04 01 2D 69 6E")), errc::invalid_value);
}

TEST_CASE("decimal REAL saturates out-of-range like the binary path") {
    // NR3 "1E999999999" -> +inf.
    auto over = H("09 0C 03 31 45 39 39 39 39 39 39 39 39 39");
    auto r = ber_codec::decode<double>(over);
    REQUIRE(r);
    CHECK_EQ(*r, std::numeric_limits<double>::infinity());

    // NR3 "-1E999999999" -> -inf.
    auto nover = H("09 0D 03 2D 31 45 39 39 39 39 39 39 39 39 39");
    r = ber_codec::decode<double>(nover);
    REQUIRE(r);
    CHECK_EQ(*r, -std::numeric_limits<double>::infinity());

    // NR3 "1E-999999999" -> +0.
    auto under = H("09 0D 03 31 45 2D 39 39 39 39 39 39 39 39 39");
    r = ber_codec::decode<double>(under);
    REQUIRE(r);
    CHECK_EQ(*r, 0.0);
    CHECK_FALSE(std::signbit(*r));
}

TEST_CASE("empty RELATIVE-OID rejected both directions (X.680 §33)") {
    CHECK_ERR(ber_codec::decode<asn1::relative_oid>(H("0D 00")), errc::invalid_value);
    CHECK_ERR(ber_codec::encode(asn1::relative_oid{}), errc::invalid_value);
}

TEST_CASE("time zone differentials are range-checked") {
    // "191215190210-0860": offset minutes 60 is invalid.
    CHECK_ERR(ber_codec::decode<asn1::utc_time>(H("17 11 31 39 31 32 31 35 31 39 30 32 31 30 2D 30 38 36 30")),
              errc::invalid_value);
    // "191215190210+2400": offset hours 24 is invalid.
    CHECK_ERR(ber_codec::decode<asn1::utc_time>(H("17 11 31 39 31 32 31 35 31 39 30 32 31 30 2B 32 34 30 30")),
              errc::invalid_value);
    // GeneralizedTime "2019121603+0199".
    CHECK_ERR(ber_codec::decode<asn1::generalized_time>(H("18 0F 32 30 31 39 31 32 31 36 30 33 2B 30 31 39 39")),
              errc::invalid_value);
}

namespace {
// A deliberately broken codec_traits client type whose decode consumes
// nothing — the SEQUENCE OF loop guard must turn this into an error
// instead of an infinite loop.
struct non_consuming {};
} // namespace

template<>
struct asn1::codec_traits<non_consuming> {
    static constexpr asn1::tag type_tag = asn1::tags::integer;
    static constexpr bool accepts(asn1::tag, bool) noexcept {
        return true;
    }
    template<asn1::encoding_rules R>
    static asn1::result<non_consuming> decode(asn1::decoder<R> &, asn1::tag = type_tag) {
        return non_consuming{}; // consumes no input
    }
    template<asn1::encoding_rules R>
    static asn1::result<void> encode(asn1::encoder<R> &, const non_consuming &, asn1::tag = type_tag) {
        return {};
    }
};

TEST_CASE("SEQUENCE OF / SET OF guard against non-consuming element decodes") {
    auto buf = H("30 03 02 01 07");
    CHECK_ERR(ber_codec::decode<std::vector<non_consuming>>(buf), errc::invalid_value);
    auto sbuf = H("31 03 02 01 07");
    CHECK_ERR(ber_codec::decode<asn1::set_of<non_consuming>>(sbuf), errc::invalid_value);
}

TEST_CASE("DER encode of ANY validates captured structure") {
    // Capture an indefinite-length TLV under BER...
    auto buf = H("30 80 05 00 00 00");
    auto a = ber_codec::decode<asn1::any>(buf);
    REQUIRE(a);
    // ...BER re-emits it verbatim; DER refuses to emit invalid DER.
    auto ber_out = ber_codec::encode(*a);
    REQUIRE(ber_out);
    CHECK_EQ(hexstr(*ber_out), hexstr(buf));
    CHECK_ERR(der_codec::encode(*a), errc::indefinite_not_allowed);

    // Non-minimal nested length is also caught.
    auto buf2 = H("30 04 04 81 01 AA");
    auto a2 = ber_codec::decode<asn1::any>(buf2);
    REQUIRE(a2);
    CHECK_ERR(der_codec::encode(*a2), errc::non_minimal_length);

    // Well-formed DER passes through.
    auto buf3 = H("30 03 02 01 07");
    auto a3 = der_codec::decode<asn1::any>(buf3);
    REQUIRE(a3);
    auto out3 = der_codec::encode(*a3);
    REQUIRE(out3);
    CHECK_EQ(hexstr(*out3), hexstr(buf3));
}

TEST_CASE("value::parse reports absolute error offsets when nested") {
    // SEQUENCE(len 5){ INTEGER 7; then a child at index 5 whose length 3
    // overruns } -> length_overflow at the length octet, absolute offset 6.
    auto buf = H("30 05 02 01 07 02 03");
    auto r = asn1::value::parse(buf);
    REQUIRE_FALSE(r.has_value());
    CHECK_EQ(r.error().code, errc::length_overflow);
    CHECK_EQ(r.error().offset, 6);

    // Two levels deep: SEQUENCE{ SEQUENCE{ <bad tag 0x00 0x01> } }.
    auto buf2 = H("30 04 30 02 00 01");
    auto r2 = asn1::value::parse(buf2);
    REQUIRE_FALSE(r2.has_value());
    CHECK_EQ(r2.error().offset, 4);
}
