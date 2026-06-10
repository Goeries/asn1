// L0 reader: identifier/length/EOC corner cases (X.690 §8.1).
#include <doctest/doctest.h>

#include "helpers.hpp"

using asn1::errc;

namespace {
template<class R = asn1::ber>
asn1::result<asn1::element> read_one(const std::vector<std::byte> & buf, std::uint32_t max_depth = 64) {
    asn1::reader<R> rd(buf, max_depth);
    return rd.next();
}
} // namespace

TEST_CASE("low tag form parses class, P/C bit and number") {
    auto buf = H("30 00");
    auto el = read_one(buf);
    REQUIRE(el);
    CHECK(el->tag == asn1::tags::sequence);
    CHECK(el->constructed);
    CHECK(el->content.empty());

    buf = H("02 01 00");
    el = read_one(buf);
    REQUIRE(el);
    CHECK(el->tag == asn1::tags::integer);
    CHECK_FALSE(el->constructed);
    CHECK_EQ(el->content.size(), 1);
}

TEST_CASE("high tag number form (§8.1.2.4)") {
    // Universal primitive tag 31 (DATE): 1F 1F.
    auto buf = H("1F 1F 00");
    auto el = read_one(buf);
    REQUIRE(el);
    CHECK(el->tag == asn1::tags::date);

    // Context-specific constructed tag 201: BF 81 49.
    buf = H("BF 81 49 00");
    el = read_one(buf);
    REQUIRE(el);
    CHECK(el->tag == asn1::tags::context(201));
    CHECK(el->constructed);

    // 0x80 padding octet is forbidden (§8.1.2.4.2 c).
    buf = H("9F 80 1F 00");
    CHECK_ERR(read_one(buf), errc::invalid_tag);

    // Tag numbers 0-30 must use the low form (§8.1.2.2).
    buf = H("9F 1E 00");
    CHECK_ERR(read_one(buf), errc::invalid_tag);

    // Tag number overflow past 2^32.
    buf = H("9F 90 80 80 80 80 00 00");
    CHECK_ERR(read_one(buf), errc::invalid_tag);
}

TEST_CASE("length forms (§8.1.3)") {
    // Long form, non-minimal: valid BER, rejected by DER.
    auto buf = H("04 81 05 01 02 03 04 05");
    auto el = read_one<asn1::ber>(buf);
    REQUIRE(el);
    CHECK_EQ(el->content.size(), 5);
    CHECK_ERR(read_one<asn1::der>(buf), errc::non_minimal_length);

    // 0x81 0x00: long-form zero length, BER-legal.
    buf = H("04 81 00");
    el = read_one<asn1::ber>(buf);
    REQUIRE(el);
    CHECK(el->content.empty());
    CHECK_ERR(read_one<asn1::der>(buf), errc::non_minimal_length);

    // Initial length octet 0xFF is reserved (§8.1.3.5 c).
    buf = H("04 FF 00");
    CHECK_ERR(read_one(buf), errc::invalid_length);

    // Declared length exceeding the remaining input.
    buf = H("04 05 01 02");
    CHECK_ERR(read_one(buf), errc::length_overflow);

    // Truncated multi-byte length.
    buf = H("04 82 01");
    CHECK_ERR(read_one(buf), errc::truncated);

    // A 2^64-overflowing length (9 length octets).
    buf = H("04 89 01 00 00 00 00 00 00 00 00");
    CHECK_ERR(read_one(buf), errc::invalid_length);
}

TEST_CASE("indefinite length (§8.1.3.6, §8.1.5)") {
    // Constructed + indefinite, terminated by EOC.
    auto buf = H("30 80 02 01 07 00 00");
    auto el = read_one<asn1::ber>(buf);
    REQUIRE(el);
    CHECK(el->indefinite);
    CHECK_EQ(hexstr(el->content), hexstr(H("02 01 07")));
    CHECK_EQ(el->full.size(), buf.size());

    // Forbidden under DER.
    CHECK_ERR(read_one<asn1::der>(buf), errc::indefinite_not_allowed);

    // Indefinite on a primitive encoding is malformed BER (§8.1.3.2 a).
    buf = H("04 80 00 00");
    CHECK_ERR(read_one<asn1::ber>(buf), errc::indefinite_not_allowed);

    // Missing EOC.
    buf = H("30 80 02 01 07");
    CHECK_ERR(read_one<asn1::ber>(buf), errc::truncated);

    // EOC with nonzero length is malformed.
    buf = H("30 80 00 01 00 00 00");
    CHECK_ERR(read_one<asn1::ber>(buf), errc::invalid_tag);

    // Stray EOC at the top level.
    buf = H("00 00");
    CHECK_ERR(read_one<asn1::ber>(buf), errc::unbalanced_eoc);

    // Nested indefinite forms resolve correctly.
    buf = H("30 80 30 80 02 01 07 00 00 00 00");
    el = read_one<asn1::ber>(buf);
    REQUIRE(el);
    CHECK_EQ(hexstr(el->content), hexstr(H("30 80 02 01 07 00 00")));
}

TEST_CASE("indefinite nesting bomb hits the depth limit") {
    std::vector<std::byte> buf;
    for (int i = 0; i < 100; ++i) {
        buf.push_back(std::byte{0x30});
        buf.push_back(std::byte{0x80});
    }
    buf.push_back(std::byte{0x05});
    buf.push_back(std::byte{0x00});
    for (int i = 0; i < 100; ++i) {
        buf.push_back(std::byte{0x00});
        buf.push_back(std::byte{0x00});
    }
    CHECK_ERR(read_one<asn1::ber>(buf, 64), errc::depth_exceeded);
}

TEST_CASE("truncation inside identifier octets") {
    auto buf = H("");
    CHECK_ERR(read_one(buf), errc::truncated);
    buf = H("02");
    CHECK_ERR(read_one(buf), errc::truncated);
    buf = H("9F 81"); // unterminated high tag number
    CHECK_ERR(read_one(buf), errc::truncated);
    buf = H("00"); // half an EOC
    CHECK_ERR(read_one(buf), errc::truncated);
}
