// Known-answer vectors for primitive types. Sources: X.690 (02/2021)
// normative examples, Microsoft Learn, Let's Encrypt "A Warm Welcome to
// ASN.1 and DER", OSS Nokalva.
#include <cmath>
#include <cstdint>
#include <limits>

#include <doctest/doctest.h>

#include "helpers.hpp"

using asn1::ber_codec;
using asn1::der_codec;
using asn1::errc;

TEST_CASE("BOOLEAN (§8.2)") {
    auto t = H("01 01 FF");
    CHECK_EQ(ber_codec::decode<bool>(t), asn1::result<bool>(true));
    auto f = H("01 01 00");
    CHECK_EQ(ber_codec::decode<bool>(f), asn1::result<bool>(false));
    CHECK_HEX(ber_codec::encode(true), "01 01 FF");
    CHECK_HEX(ber_codec::encode(false), "01 01 00");

    // BER: any nonzero is TRUE; DER: TRUE must be FF (§11.1).
    auto odd = H("01 01 2A");
    CHECK_EQ(ber_codec::decode<bool>(odd), asn1::result<bool>(true));
    CHECK_ERR(der_codec::decode<bool>(odd), errc::non_canonical);

    CHECK_ERR(ber_codec::decode<bool>(H("01 00")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<bool>(H("01 02 00 00")), errc::invalid_value);
}

TEST_CASE("INTEGER known-answer vectors (§8.3)") {
    const std::pair<std::int64_t, const char *> vectors[] = {
        {0, "02 01 00"},      {3, "02 01 03"},    {127, "02 01 7F"},     {128, "02 02 00 80"},
        {256, "02 02 01 00"}, {-128, "02 01 80"}, {-129, "02 02 FF 7F"},
    };
    for (auto [v, hex] : vectors) {
        CAPTURE(hex);
        CHECK_HEX(ber_codec::encode(v), hex);
        auto buf = H(hex);
        auto r = ber_codec::decode<std::int64_t>(buf);
        REQUIRE(r);
        CHECK_EQ(*r, v);
    }

    // 2^63 + 1 needs the unsigned leading-zero form (Let's Encrypt vector).
    const std::uint64_t big = 0x8000000000000001ULL;
    CHECK_HEX(ber_codec::encode(big), "02 09 00 80 00 00 00 00 00 00 01");
    auto buf = H("02 09 00 80 00 00 00 00 00 00 01");
    auto r = ber_codec::decode<std::uint64_t>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, big);
}

TEST_CASE("INTEGER minimality is mandatory even in BER (§8.3.2)") {
    CHECK_ERR(ber_codec::decode<std::int64_t>(H("02 02 00 7F")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<std::int64_t>(H("02 02 FF 80")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<std::int64_t>(H("02 00")), errc::invalid_value);
}

TEST_CASE("INTEGER range checking") {
    CHECK_ERR(ber_codec::decode<std::uint64_t>(H("02 01 FF")),
              errc::value_out_of_range); // negative into unsigned
    CHECK_ERR(ber_codec::decode<std::int8_t>(H("02 02 01 2C")),
              errc::value_out_of_range); // 300 into int8
    CHECK_ERR(ber_codec::decode<std::int64_t>(H("02 09 00 80 00 00 00 00 00 00 01")),
              errc::value_out_of_range); // 2^63+1 into int64
    auto buf = H("02 01 81");            // -127 into int8: fine
    auto r = ber_codec::decode<std::int8_t>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, -127);
}

TEST_CASE("INTEGER round trip across widths") {
    for (std::int64_t const v :
         {std::int64_t{0}, std::int64_t{1}, std::int64_t{-1}, std::int64_t{255}, std::int64_t{-256},
          std::int64_t{65535}, std::numeric_limits<std::int64_t>::min(), std::numeric_limits<std::int64_t>::max()}) {
        auto enc = ber_codec::encode(v);
        REQUIRE(enc);
        auto dec = ber_codec::decode<std::int64_t>(*enc);
        REQUIRE(dec);
        CHECK_EQ(*dec, v);
    }
    for (std::uint64_t const v : {std::uint64_t{0}, std::uint64_t{0x80}, std::numeric_limits<std::uint64_t>::max()}) {
        auto enc = ber_codec::encode(v);
        REQUIRE(enc);
        auto dec = ber_codec::decode<std::uint64_t>(*enc);
        REQUIRE(dec);
        CHECK_EQ(*dec, v);
    }
}

TEST_CASE("NULL (§8.8)") {
    auto buf = H("05 00");
    CHECK(ber_codec::decode<asn1::null_t>(buf).has_value());
    CHECK_HEX(ber_codec::encode(asn1::null), "05 00");
    CHECK_ERR(ber_codec::decode<asn1::null_t>(H("05 01 00")), errc::invalid_value);
}

TEST_CASE("OBJECT IDENTIFIER known-answer vectors (§8.19)") {
    const std::pair<asn1::oid, const char *> vectors[] = {
        {{2, 100, 3}, "06 03 81 34 03"},                                       // X.690 §8.19.5 example
        {{1, 2, 840, 113549, 1, 1, 11}, "06 09 2A 86 48 86 F7 0D 01 01 0B"},   // sha256WithRSAEncryption
        {{2, 5, 4, 3}, "06 03 55 04 03"},                                      // id-at-commonName
        {{1, 3, 6, 1, 4, 1, 311, 21, 20}, "06 09 2B 06 01 04 01 82 37 15 14"}, // MS Learn vector
    };
    for (const auto & [v, hex] : vectors) {
        CAPTURE(hex);
        CHECK_HEX(ber_codec::encode(v), hex);
        auto buf = H(hex);
        auto r = ber_codec::decode<asn1::oid>(buf);
        REQUIRE(r);
        CHECK_EQ(*r, v);
    }
}

TEST_CASE("OBJECT IDENTIFIER validation") {
    CHECK_ERR(ber_codec::decode<asn1::oid>(H("06 00")), errc::invalid_value);
    // Subidentifier with 0x80 padding is non-minimal (§8.19.2).
    CHECK_ERR(ber_codec::decode<asn1::oid>(H("06 02 80 01")), errc::invalid_value);
    // Truncated subidentifier (continuation bit set on last octet).
    CHECK_ERR(ber_codec::decode<asn1::oid>(H("06 01 81")), errc::invalid_value);
    // Arc overflow past 2^64.
    CHECK_ERR(ber_codec::decode<asn1::oid>(H("06 0B 2A FF FF FF FF FF FF FF FF FF 7F")), errc::value_out_of_range);

    // Encoding constraints: X ∈ {0,1,2}; Y < 40 when X < 2.
    CHECK_ERR(ber_codec::encode(asn1::oid{0, 40}), errc::invalid_value);
    CHECK_ERR(ber_codec::encode(asn1::oid{3, 1}), errc::invalid_value);
    CHECK_ERR(ber_codec::encode(asn1::oid{1}), errc::invalid_value);

    auto p = asn1::oid::parse("1.2.840.113549.1.1.11");
    REQUIRE(p);
    CHECK_EQ(*p, (asn1::oid{1, 2, 840, 113549, 1, 1, 11}));
    CHECK_FALSE(asn1::oid::parse("").has_value());
    CHECK_FALSE(asn1::oid::parse("1..2").has_value());
    CHECK_FALSE(asn1::oid::parse("9.9").has_value());
}

TEST_CASE("RELATIVE-OID (§8.20.5 example)") {
    const asn1::relative_oid v{8571, 3, 2};
    CHECK_HEX(ber_codec::encode(v), "0D 04 C2 7B 03 02");
    auto buf = H("0D 04 C2 7B 03 02");
    auto r = ber_codec::decode<asn1::relative_oid>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, v);
}

TEST_CASE("REAL binary form (§8.5.7)") {
    // OSS Nokalva: {mantissa 10, base 2, exponent 0} = 10.0.
    auto buf = H("09 03 80 00 0A");
    auto r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 10.0);

    // 0.15625 = 5 × 2^-5.
    buf = H("09 03 80 FB 05");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 0.15625);
    CHECK_HEX(ber_codec::encode(0.15625), "09 03 80 FB 05");

    // Encoder normalizes to odd mantissa: 10.0 = 5 × 2^1.
    CHECK_HEX(ber_codec::encode(10.0), "09 03 80 01 05");
    CHECK_HEX(ber_codec::encode(-1.0), "09 03 C0 00 01");

    // Base 8 and base 16 with scale factors decode correctly:
    // 0x94 = base 8, F=1: 3 × 2^1 × 8^1 = 48.
    buf = H("09 03 94 01 03");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 48.0);
    // Base 8/16 are non-canonical under DER (§11.3.1).
    CHECK_ERR(der_codec::decode<double>(buf), errc::non_canonical);
}

TEST_CASE("REAL zero and special values (§8.5.2, §8.5.9)") {
    auto buf = H("09 00");
    auto r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 0.0);
    CHECK_FALSE(std::signbit(*r));
    CHECK_HEX(ber_codec::encode(0.0), "09 00");

    buf = H("09 01 40");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, std::numeric_limits<double>::infinity());

    buf = H("09 01 41");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, -std::numeric_limits<double>::infinity());

    buf = H("09 01 42");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK(std::isnan(*r));

    buf = H("09 01 43");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 0.0);
    CHECK(std::signbit(*r));

    CHECK_HEX(ber_codec::encode(std::numeric_limits<double>::infinity()), "09 01 40");
    CHECK_HEX(ber_codec::encode(-std::numeric_limits<double>::infinity()), "09 01 41");
    CHECK_HEX(ber_codec::encode(std::numeric_limits<double>::quiet_NaN()), "09 01 42");
    CHECK_HEX(ber_codec::encode(-0.0), "09 01 43");
}

TEST_CASE("REAL decimal forms, ISO 6093 (§8.5.8)") {
    // NR1: "4902"
    auto buf = H("09 05 01 34 39 30 32");
    auto r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 4902.0);

    // NR2: "3.14"
    buf = H("09 05 02 33 2E 31 34");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, 3.14);

    // NR3: "314.159E-2"
    buf = H("09 0B 03 33 31 34 2E 31 35 39 45 2D 32");
    r = ber_codec::decode<double>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, doctest::Approx(3.14159));

    // NR1/NR2 are non-canonical under DER (§11.3.2: NR3 only).
    buf = H("09 05 01 34 39 30 32");
    CHECK_ERR(der_codec::decode<double>(buf), errc::non_canonical);
}

TEST_CASE("REAL round trip") {
    for (double const v :
         {1.0, -1.0, 0.5, 3.141592653589793, 1e308, -1e-308, 123456789.0, std::numeric_limits<double>::denorm_min()}) {
        auto enc = ber_codec::encode(v);
        REQUIRE(enc);
        auto dec = ber_codec::decode<double>(*enc);
        REQUIRE(dec);
        CHECK_EQ(*dec, v);
    }
}

TEST_CASE("OCTET STRING (§8.7)") {
    auto buf = H("04 04 03 02 06 A0");
    auto r = ber_codec::decode<std::vector<std::byte>>(buf);
    REQUIRE(r);
    CHECK_EQ(hexstr(*r), hexstr(H("03 02 06 A0")));
    CHECK_HEX(ber_codec::encode(H("03 02 06 A0")), "04 04 03 02 06 A0");

    // BER constructed form reassembles; DER rejects it (§10.2).
    buf = H("24 09 04 03 4A 6F 6E 04 02 65 73");
    r = ber_codec::decode<std::vector<std::byte>>(buf);
    REQUIRE(r);
    CHECK_EQ(hexstr(*r), hexstr(H("4A 6F 6E 65 73")));
    CHECK_ERR(der_codec::decode<std::vector<std::byte>>(buf), errc::unexpected_constructed);

    // Segments must be OCTET STRINGs.
    buf = H("24 05 02 01 00 04 00");
    CHECK_ERR(ber_codec::decode<std::vector<std::byte>>(buf), errc::tag_mismatch);
}

TEST_CASE("BIT STRING (§8.6)") {
    // X.690 §8.6.4.2: '0A3B5F291CD'H, 4 unused bits — primitive.
    auto buf = H("03 07 04 0A 3B 5F 29 1C D0");
    auto r = ber_codec::decode<asn1::bit_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->unused_bits, 4);
    CHECK_EQ(hexstr(r->data.span()), hexstr(H("0A 3B 5F 29 1C D0")));
    CHECK_EQ(r->bit_count(), 44);

    // Same value, constructed + indefinite (X.690 §8.6.4.2).
    auto cbuf = H("23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00");
    auto cr = ber_codec::decode<asn1::bit_string>(cbuf);
    REQUIRE(cr);
    CHECK_EQ(*cr, *r);
    CHECK_ERR(der_codec::decode<asn1::bit_string>(cbuf), errc::indefinite_not_allowed);

    // Let's Encrypt: 18 bits, 6 unused.
    buf = H("03 04 06 6E 5D C0");
    r = ber_codec::decode<asn1::bit_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->bit_count(), 18);
    CHECK(r->bit(1));
    CHECK_FALSE(r->bit(0));

    // Empty bit string (§8.6.2.3).
    buf = H("03 01 00");
    r = ber_codec::decode<asn1::bit_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->bit_count(), 0);
    CHECK_HEX(ber_codec::encode(asn1::bit_string{}), "03 01 00");

    // Round trip.
    asn1::bit_string const bs{asn1::bytes::copy(H("6E 5D C0")), 6};
    CHECK_HEX(ber_codec::encode(bs), "03 04 06 6E 5D C0");

    // Malformed: no initial octet / unused > 7 / unused with no data.
    CHECK_ERR(ber_codec::decode<asn1::bit_string>(H("03 00")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<asn1::bit_string>(H("03 02 08 00")), errc::invalid_value);
    CHECK_ERR(ber_codec::decode<asn1::bit_string>(H("03 01 04")), errc::invalid_value);

    // §8.6.4: only the final segment may end mid-octet.
    CHECK_ERR(ber_codec::decode<asn1::bit_string>(H("23 0A 03 03 04 0A 30 03 03 00 0A 3B")), errc::invalid_value);

    // DER: padding bits must be zero (§11.2.1).
    buf = H("03 04 06 6E 5D C1");
    CHECK(ber_codec::decode<asn1::bit_string>(buf).has_value());
    CHECK_ERR(der_codec::decode<asn1::bit_string>(buf), errc::non_canonical);
}

TEST_CASE("ENUMERATED maps C++ enums (§8.4)") {
    enum class version : std::int32_t { v1 = 0, v2 = 1, v3 = 2 };
    CHECK_HEX(ber_codec::encode(version::v3), "0A 01 02");
    auto buf = H("0A 01 02");
    auto r = ber_codec::decode<version>(buf);
    REQUIRE(r);
    CHECK(*r == version::v3);
}
