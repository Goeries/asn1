// Character string and time types, incl. BER constructed reassembly
// (the X.690 §8.21 "Jones" example) and DER canonical time checks.
#include <chrono>

#include <doctest/doctest.h>

#include "helpers.hpp"

using asn1::ber_codec;
using asn1::der_codec;
using asn1::errc;

TEST_CASE("VisibleString primitive and constructed (§8.21 'Jones')") {
    // Primitive.
    auto buf = H("1A 05 4A 6F 6E 65 73");
    auto r = ber_codec::decode<asn1::visible_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->value, "Jones");
    CHECK_HEX(ber_codec::encode(asn1::visible_string{"Jones"}), "1A 05 4A 6F 6E 65 73");

    // Constructed, definite length: segments are OCTET STRINGs.
    buf = H("3A 09 04 03 4A 6F 6E 04 02 65 73");
    r = ber_codec::decode<asn1::visible_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->value, "Jones");
    CHECK_ERR(der_codec::decode<asn1::visible_string>(buf), errc::unexpected_constructed);

    // Constructed, indefinite length.
    buf = H("3A 80 04 03 4A 6F 6E 04 02 65 73 00 00");
    r = ber_codec::decode<asn1::visible_string>(buf);
    REQUIRE(r);
    CHECK_EQ(r->value, "Jones");
}

TEST_CASE("PrintableString / IA5String / NumericString charsets") {
    auto buf = H("13 02 68 69");
    auto p = ber_codec::decode<asn1::printable_string>(buf);
    REQUIRE(p);
    CHECK_EQ(p->value, "hi");

    buf = H("16 02 68 69");
    auto i = ber_codec::decode<asn1::ia5_string>(buf);
    REQUIRE(i);
    CHECK_EQ(i->value, "hi");

    // '*' is not in the PrintableString alphabet.
    CHECK_ERR(ber_codec::decode<asn1::printable_string>(H("13 01 2A")), errc::invalid_value);
    CHECK_ERR(ber_codec::encode(asn1::printable_string{"*"}), errc::invalid_value);

    // IA5 is 7-bit.
    CHECK_ERR(ber_codec::decode<asn1::ia5_string>(H("16 01 80")), errc::invalid_value);

    // NumericString: digits and space only.
    buf = H("12 03 31 32 20");
    auto n = ber_codec::decode<asn1::numeric_string>(buf);
    REQUIRE(n);
    CHECK_ERR(ber_codec::decode<asn1::numeric_string>(H("12 01 41")), errc::invalid_value);
}

TEST_CASE("UTF8String validation (§8.23.10)") {
    auto buf = H("0C 04 F0 9F 98 8E"); // U+1F60E
    auto r = ber_codec::decode<std::string>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, "\xF0\x9F\x98\x8E");
    CHECK_HEX(ber_codec::encode(std::string("\xF0\x9F\x98\x8E")), "0C 04 F0 9F 98 8E");

    CHECK_ERR(ber_codec::decode<std::string>(H("0C 01 FF")), errc::invalid_value);
    // Overlong encoding of NUL.
    CHECK_ERR(ber_codec::decode<std::string>(H("0C 02 C0 80")), errc::invalid_value);
    // CESU-8 surrogate.
    CHECK_ERR(ber_codec::decode<std::string>(H("0C 03 ED A0 80")), errc::invalid_value);
    // Truncated multibyte sequence.
    CHECK_ERR(ber_codec::decode<std::string>(H("0C 01 C3")), errc::invalid_value);
}

TEST_CASE("BMPString and UniversalString") {
    auto buf = H("1E 04 00 68 00 69");
    auto b = ber_codec::decode<asn1::bmp_string>(buf);
    REQUIRE(b);
    CHECK(b->value == u"hi");
    CHECK_HEX(ber_codec::encode(asn1::bmp_string{u"hi"}), "1E 04 00 68 00 69");
    CHECK_ERR(ber_codec::decode<asn1::bmp_string>(H("1E 03 00 68 00")),
              errc::invalid_value); // odd length
    CHECK_ERR(ber_codec::decode<asn1::bmp_string>(H("1E 02 D8 00")),
              errc::invalid_value); // surrogate

    buf = H("1C 08 00 00 00 68 00 01 F6 0E");
    auto u = ber_codec::decode<asn1::universal_string>(buf);
    REQUIRE(u);
    CHECK(u->value == U"h\U0001F60E");
    CHECK_HEX(ber_codec::encode(asn1::universal_string{U"h\U0001F60E"}), "1C 08 00 00 00 68 00 01 F6 0E");
}

TEST_CASE("UTCTime (§11.8, Let's Encrypt vectors)") {
    using namespace std::chrono;
    const auto instant = sys_days{2019y / December / 16} + hours{3} + minutes{2} + seconds{10};

    auto buf = H("17 0D 31 39 31 32 31 36 30 33 30 32 31 30 5A");
    auto r = ber_codec::decode<asn1::utc_time>(buf);
    REQUIRE(r);
    CHECK(r->value == instant);
    CHECK_HEX(ber_codec::encode(asn1::utc_time{instant}), "17 0D 31 39 31 32 31 36 30 33 30 32 31 30 5A");

    // Offset form "191215190210-0800" denotes the same instant.
    buf = H("17 11 31 39 31 32 31 35 31 39 30 32 31 30 2D 30 38 30 30");
    r = ber_codec::decode<asn1::utc_time>(buf);
    REQUIRE(r);
    CHECK(r->value == instant);
    // DER requires seconds + Z (§11.8).
    CHECK_ERR(der_codec::decode<asn1::utc_time>(buf), errc::non_canonical);

    // Missing seconds: BER-legal, seconds default to 0.
    buf = H("17 0B 31 39 31 32 31 36 30 33 30 32 5A");
    r = ber_codec::decode<asn1::utc_time>(buf);
    REQUIRE(r);
    CHECK(r->value == instant - seconds{10});
    CHECK_ERR(der_codec::decode<asn1::utc_time>(buf), errc::non_canonical);

    // 50..99 maps to 19xx (RFC 5280 convention).
    buf = H("17 0D 39 35 30 31 30 31 30 30 30 30 30 30 5A");
    r = ber_codec::decode<asn1::utc_time>(buf);
    REQUIRE(r);
    CHECK(r->value == sys_days{1995y / January / 1});

    CHECK_ERR(ber_codec::decode<asn1::utc_time>(H("17 0D 31 39 31 33 33 32 30 33 30 32 31 30 5A")),
              errc::invalid_value); // month 13
}

TEST_CASE("GeneralizedTime (§11.7)") {
    using namespace std::chrono;
    const auto instant = sys_days{2019y / December / 16} + hours{3} + minutes{2} + seconds{10};

    auto buf = H("18 0F 32 30 31 39 31 32 31 36 30 33 30 32 31 30 5A");
    auto r = ber_codec::decode<asn1::generalized_time>(buf);
    REQUIRE(r);
    CHECK(r->value == instant);
    CHECK_HEX(ber_codec::encode(asn1::generalized_time{instant}), "18 0F 32 30 31 39 31 32 31 36 30 33 30 32 31 30 5A");

    // Fractional seconds: "...10.5Z" = +500 ms.
    buf = H("18 11 32 30 31 39 31 32 31 36 30 33 30 32 31 30 2E 35 5A");
    r = ber_codec::decode<asn1::generalized_time>(buf);
    REQUIRE(r);
    CHECK(r->value == instant + milliseconds{500});
    // Trailing zero in the fraction is non-canonical (§11.7.3).
    buf = H("18 12 32 30 31 39 31 32 31 36 30 33 30 32 31 30 2E 35 30 5A");
    CHECK(ber_codec::decode<asn1::generalized_time>(buf).has_value());
    CHECK_ERR(der_codec::decode<asn1::generalized_time>(buf), errc::non_canonical);

    // Local time (no zone): BER-legal, flagged; DER requires Z.
    buf = H("18 0E 32 30 31 39 31 32 31 36 30 33 30 32 31 30");
    r = ber_codec::decode<asn1::generalized_time>(buf);
    REQUIRE(r);
    CHECK(r->local);
    CHECK_ERR(der_codec::decode<asn1::generalized_time>(buf), errc::non_canonical);

    // Hours-only with offset zone.
    buf = H("18 0D 32 30 31 39 31 32 31 36 30 33 2B 30 31");
    r = ber_codec::decode<asn1::generalized_time>(buf);
    REQUIRE(r);
    CHECK(r->value == sys_days{2019y / December / 16} + hours{2});

    CHECK_ERR(ber_codec::decode<asn1::generalized_time>(H("18 0E 32 30 31 39 31 33 31 36 30 33 30 32 31 30")),
              errc::invalid_value); // month 13
}

TEST_CASE("fixed encode round trip for times") {
    using namespace std::chrono;
    const asn1::generalized_time g{sys_days{2026y / June / 9} + hours{21} + minutes{58} + seconds{1} +
                                   milliseconds{250}};
    auto enc = ber_codec::encode(g);
    REQUIRE(enc);
    auto dec = ber_codec::decode<asn1::generalized_time>(*enc);
    REQUIRE(dec);
    CHECK(dec->value == g.value);

    const asn1::utc_time u{time_point_cast<seconds>(sys_days{1999y / January / 31} + hours{12})};
    auto enc2 = ber_codec::encode(u);
    REQUIRE(enc2);
    auto dec2 = ber_codec::decode<asn1::utc_time>(*enc2);
    REQUIRE(dec2);
    CHECK(dec2->value == u.value);
}
