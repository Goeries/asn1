// libFuzzer entry point: DOM parse + typed decode of a representative
// nested type under both BER and DER. Build with -DASN1_BUILD_FUZZERS=ON
// and a clang toolchain.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <asn1/asn1.hpp>

namespace {
struct fuzzed {
    std::int64_t a = 0;
    std::optional<std::string> s;
    std::vector<asn1::oid> oids;
    asn1::bit_string bits;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t * data, std::size_t size) {
    const auto in = std::as_bytes(std::span(data, size));

    if (auto v = asn1::value::parse(in)) {
        (void)v->to_bytes(); // parse -> serialize must not crash either
    }
    (void)asn1::ber_codec::decode<fuzzed>(in);
    (void)asn1::der_codec::decode<fuzzed>(in);
    (void)asn1::ber_codec::decode<asn1::any>(in);
    return 0;
}
