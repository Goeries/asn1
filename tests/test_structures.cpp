// Constructed types: SEQUENCE via aggregates (the PFR auto-codec),
// tagging (the X.690 §8.14 worked example), OPTIONAL, CHOICE, SET OF,
// ANY, the DOM, and round-trip property tests.
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <doctest/doctest.h>

#include "helpers.hpp"

using asn1::ber_codec;
using asn1::der_codec;
using asn1::errc;

namespace {

// X.690 §8.9.3 example: SEQUENCE {name IA5String, ok BOOLEAN}.
struct name_and_ok {
    asn1::ia5_string name;
    bool ok = false;
    friend bool operator==(const name_and_ok &, const name_and_ok &) = default;
};

// RFC 5280 AlgorithmIdentifier.
struct algorithm_identifier {
    asn1::oid algorithm;
    asn1::any parameters;
};

struct empty_seq {
    [[maybe_unused]] friend bool operator==(const empty_seq &, const empty_seq &) = default;
};

struct rt {
    std::uint32_t a = 0;
    bool b = false;
    std::string s;
    std::vector<std::int64_t> v;
    std::optional<double> d;
    friend bool operator==(const rt &, const rt &) = default;
};

} // namespace

TEST_CASE("SEQUENCE via aggregate auto-codec (§8.9.3 example)") {
    const name_and_ok v{asn1::ia5_string{"Smith"}, true};
    CHECK_HEX(ber_codec::encode(v), "30 0A 16 05 53 6D 69 74 68 01 01 FF");
    auto buf = H("30 0A 16 05 53 6D 69 74 68 01 01 FF");
    auto r = ber_codec::decode<name_and_ok>(buf);
    REQUIRE(r);
    CHECK(*r == v);

    // Missing component.
    CHECK_ERR(ber_codec::decode<name_and_ok>(H("30 07 16 05 53 6D 69 74 68")), errc::truncated);
    // Extra component inside the SEQUENCE.
    CHECK_ERR(ber_codec::decode<name_and_ok>(H("30 0C 16 05 53 6D 69 74 68 01 01 FF 05 00")), errc::trailing_data);
}

TEST_CASE("AlgorithmIdentifier with ANY (Let's Encrypt vector)") {
    auto buf = H("30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00");
    auto r = ber_codec::decode<algorithm_identifier>(buf);
    REQUIRE(r);
    CHECK_EQ(r->algorithm, (asn1::oid{1, 2, 840, 113549, 1, 1, 11}));
    CHECK_EQ(hexstr(r->parameters.full.span()), hexstr(H("05 00")));
    CHECK(r->parameters.tag == asn1::tags::null);

    // Re-encoding is byte-exact (ANY passthrough).
    auto enc = ber_codec::encode(*r);
    REQUIRE(enc);
    CHECK_EQ(hexstr(*enc), hexstr(buf));
}

TEST_CASE("SEQUENCE OF (Let's Encrypt vector)") {
    const std::vector<std::int32_t> v{7, 8, 9};
    CHECK_HEX(ber_codec::encode(v), "30 09 02 01 07 02 01 08 02 01 09");
    auto buf = H("30 09 02 01 07 02 01 08 02 01 09");
    auto r = ber_codec::decode<std::vector<std::int32_t>>(buf);
    REQUIRE(r);
    CHECK_EQ(*r, v);

    // Empty SEQUENCE OF.
    buf = H("30 00");
    r = ber_codec::decode<std::vector<std::int32_t>>(buf);
    REQUIRE(r);
    CHECK(r->empty());
}

TEST_CASE("empty SEQUENCE maps to an empty aggregate") {
    CHECK_HEX(ber_codec::encode(empty_seq{}), "30 00");
    auto buf = H("30 00");
    CHECK(ber_codec::decode<empty_seq>(buf).has_value());
}

TEST_CASE("tagging: the X.690 §8.14 worked example") {
    // Type1 ::= VisibleString
    using type1 = asn1::visible_string;
    // Type2 ::= [APPLICATION 3] IMPLICIT Type1
    using type2 = asn1::implicit<3, type1, asn1::tag_class::application>;
    // Type3 ::= [2] Type2 (explicit)
    using type3 = asn1::explicit_<2, type2>;
    // Type4 ::= [APPLICATION 7] IMPLICIT Type3
    using type4 = asn1::implicit<7, type3, asn1::tag_class::application>;
    // Type5 ::= [2] IMPLICIT Type2
    using type5 = asn1::implicit<2, type2>;

    const type1 v1{"Jones"};
    CHECK_HEX(ber_codec::encode(v1), "1A 05 4A 6F 6E 65 73");

    const type2 v2{v1};
    CHECK_HEX(ber_codec::encode(v2), "43 05 4A 6F 6E 65 73");

    const type3 v3{v2};
    CHECK_HEX(ber_codec::encode(v3), "A2 07 43 05 4A 6F 6E 65 73");

    const type4 v4{v3};
    CHECK_HEX(ber_codec::encode(v4), "67 07 43 05 4A 6F 6E 65 73");

    const type5 v5{v2};
    CHECK_HEX(ber_codec::encode(v5), "82 05 4A 6F 6E 65 73");

    // And all decode back.
    auto b2 = H("43 05 4A 6F 6E 65 73");
    auto r2 = ber_codec::decode<type2>(b2);
    REQUIRE(r2);
    CHECK_EQ(r2->value.value, "Jones");

    auto b4 = H("67 07 43 05 4A 6F 6E 65 73");
    auto r4 = ber_codec::decode<type4>(b4);
    REQUIRE(r4);
    CHECK_EQ(r4->value.value.value.value, "Jones");

    auto b5 = H("82 05 4A 6F 6E 65 73");
    auto r5 = ber_codec::decode<type5>(b5);
    REQUIRE(r5);
    CHECK_EQ(r5->value.value.value, "Jones");
}

TEST_CASE("X.690 Annex A.3: [APPLICATION 2] IMPLICIT INTEGER = 51") {
    using employee_number = asn1::implicit<2, std::int64_t, asn1::tag_class::application>;
    CHECK_HEX(ber_codec::encode(employee_number{51}), "42 01 33");
    auto buf = H("42 01 33");
    auto r = ber_codec::decode<employee_number>(buf);
    REQUIRE(r);
    CHECK_EQ(r->value, 51);
}

TEST_CASE("indefinite-length SEQUENCE decodes under BER only") {
    struct one_int {
        std::int32_t v = 0;
    };
    auto buf = H("30 80 02 01 07 00 00");
    auto r = ber_codec::decode<one_int>(buf);
    REQUIRE(r);
    CHECK_EQ(r->v, 7);
    CHECK_ERR(der_codec::decode<one_int>(buf), errc::indefinite_not_allowed);
}

TEST_CASE("trailing data is rejected; decode_partial reports the rest") {
    auto buf = H("02 01 07 02 01 08");
    CHECK_ERR(ber_codec::decode<std::int32_t>(buf), errc::trailing_data);

    auto r = ber_codec::decode_partial<std::int32_t>(buf);
    REQUIRE(r);
    CHECK_EQ(r->first, 7);
    CHECK_EQ(hexstr(r->second), hexstr(H("02 01 08")));
}

TEST_CASE("OPTIONAL components") {
    struct with_opt {
        std::int32_t a = 0;
        std::optional<bool> b;
    };
    auto buf = H("30 03 02 01 07");
    auto r = ber_codec::decode<with_opt>(buf);
    REQUIRE(r);
    CHECK_EQ(r->a, 7);
    CHECK_FALSE(r->b.has_value());

    buf = H("30 06 02 01 07 01 01 FF");
    r = ber_codec::decode<with_opt>(buf);
    REQUIRE(r);
    CHECK(r->b == true);

    // Absent optional is omitted on encode.
    CHECK_HEX(ber_codec::encode(with_opt{7, std::nullopt}), "30 03 02 01 07");
    CHECK_HEX(ber_codec::encode(with_opt{7, true}), "30 06 02 01 07 01 01 FF");
}

TEST_CASE("CHOICE via std::variant") {
    using choice = std::variant<std::int32_t, asn1::printable_string>;

    auto buf = H("02 01 2A");
    auto r = ber_codec::decode<choice>(buf);
    REQUIRE(r);
    CHECK_EQ(std::get<std::int32_t>(*r), 42);

    buf = H("13 02 68 69");
    r = ber_codec::decode<choice>(buf);
    REQUIRE(r);
    CHECK_EQ(std::get<asn1::printable_string>(*r).value, "hi");

    CHECK_ERR(ber_codec::decode<choice>(H("04 01 00")), errc::tag_mismatch);

    CHECK_HEX(ber_codec::encode(choice{std::int32_t{42}}), "02 01 2A");
    CHECK_HEX(ber_codec::encode(choice{asn1::printable_string{"hi"}}), "13 02 68 69");

    // Distinct-tag alternatives via implicit tags.
    using tagged_choice = std::variant<asn1::implicit<0, std::int32_t>, asn1::implicit<1, std::int32_t>>;
    buf = H("81 01 05");
    auto tr = ber_codec::decode<tagged_choice>(buf);
    REQUIRE(tr);
    CHECK_EQ(tr->index(), 1);
    CHECK_EQ(std::get<1>(*tr).value, 5);
}

TEST_CASE("SET OF: BER order-free, DER canonically sorted (§11.6)") {
    asn1::set_of<std::int32_t> const v{{3, 1, 2}};

    // BER preserves the given order.
    CHECK_HEX(ber_codec::encode(v), "31 09 02 01 03 02 01 01 02 01 02");
    // DER sorts element encodings.
    CHECK_HEX(der_codec::encode(v), "31 09 02 01 01 02 01 02 02 01 03");

    // BER decodes any order; DER rejects unsorted input.
    auto unsorted = H("31 09 02 01 03 02 01 01 02 01 02");
    auto r = ber_codec::decode<asn1::set_of<std::int32_t>>(unsorted);
    REQUIRE(r);
    CHECK_EQ(r->items, std::vector<std::int32_t>{3, 1, 2});
    CHECK_ERR(der_codec::decode<asn1::set_of<std::int32_t>>(unsorted), errc::non_canonical);

    auto sorted = H("31 09 02 01 01 02 01 02 02 01 03");
    auto rd = der_codec::decode<asn1::set_of<std::int32_t>>(sorted);
    REQUIRE(rd);
    CHECK_EQ(rd->items, std::vector<std::int32_t>{1, 2, 3});
}

TEST_CASE("std::tuple and std::pair map to SEQUENCE") {
    const std::pair<std::int32_t, bool> p{7, true};
    CHECK_HEX(ber_codec::encode(p), "30 06 02 01 07 01 01 FF");
    auto buf = H("30 06 02 01 07 01 01 FF");
    auto r = ber_codec::decode<std::pair<std::int32_t, bool>>(buf);
    REQUIRE(r);
    CHECK(*r == p);
}

TEST_CASE("structural depth limit on nested SEQUENCEs") {
    // 80 nested definite-length SEQUENCEs around a NULL.
    std::vector<std::byte> inner = H("05 00");
    for (int i = 0; i < 80; ++i) {
        std::vector<std::byte> wrapped;
        wrapped.push_back(std::byte{0x30});
        REQUIRE(inner.size() < 0x100);
        if (inner.size() < 0x80) {
            wrapped.push_back(static_cast<std::byte>(inner.size()));
        } else {
            wrapped.push_back(std::byte{0x81});
            wrapped.push_back(static_cast<std::byte>(inner.size()));
        }
        wrapped.insert(wrapped.end(), inner.begin(), inner.end());
        inner = std::move(wrapped);
    }
    auto r = asn1::value::parse(inner, {.max_depth = 64});
    REQUIRE_FALSE(r.has_value());
    CHECK_EQ(r.error().code, errc::depth_exceeded);
}

TEST_CASE("DOM parse, dump and re-encode") {
    auto buf = H("30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00");
    auto v = asn1::value::parse(buf);
    REQUIRE(v);
    CHECK(v->tag == asn1::tags::sequence);
    REQUIRE_EQ(v->children.size(), 2);
    CHECK(v->children[0].tag == asn1::tags::object_identifier);
    CHECK(v->children[1].tag == asn1::tags::null);

    auto o = v->children[0].as_oid();
    REQUIRE(o);
    CHECK_EQ(o->to_string(), "1.2.840.113549.1.1.11");

    CHECK_EQ(hexstr(v->to_bytes()), hexstr(buf));

    auto text = asn1::dump(*v);
    CHECK(text.find("SEQUENCE") != std::string::npos);
    CHECK(text.find("OBJECT IDENTIFIER") != std::string::npos);
}

TEST_CASE("error formatting") {
    auto r = ber_codec::decode<std::int32_t>(H("04 01 00"));
    REQUIRE_FALSE(r.has_value());
    auto s = std::format("{}", r.error());
    CHECK(s.find("tag mismatch") != std::string::npos);
    CHECK(s.find("offset") != std::string::npos);
    CHECK(s.find("INTEGER") != std::string::npos);
    CHECK(s.find("OCTET STRING") != std::string::npos);
}

TEST_CASE("round-trip property test over generated aggregates") {
    std::uint64_t seed = 0x243F6A8885A308D3ULL; // deterministic LCG
    auto next = [&seed] {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        return seed >> 11;
    };

    for (int i = 0; i < 200; ++i) {
        rt in;
        in.a = static_cast<std::uint32_t>(next());
        in.b = next() & 1;
        const auto slen = next() % 40;
        for (std::uint64_t k = 0; k < slen; ++k)
            in.s.push_back(static_cast<char>('a' + next() % 26));
        const auto vlen = next() % 8;
        for (std::uint64_t k = 0; k < vlen; ++k)
            in.v.push_back(static_cast<std::int64_t>(next()) - static_cast<std::int64_t>(next()));
        if (next() & 1)
            in.d = std::ldexp(static_cast<double>(next() % 100000), static_cast<int>(next() % 64) - 32);

        auto enc = ber_codec::encode(in);
        REQUIRE(enc);
        auto dec = ber_codec::decode<rt>(*enc);
        REQUIRE(dec);
        CHECK(*dec == in);

        // BER output here is also canonical: DER must accept it.
        auto dec2 = der_codec::decode<rt>(*enc);
        REQUIRE(dec2);
        CHECK(*dec2 == in);
    }
}
