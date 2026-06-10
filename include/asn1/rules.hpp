// asn1/rules.hpp — encoding rules as policy types.
//
// X.690 defines BER (clause 8) plus two canonical subsets, CER (§9) and
// DER (§10/§11). A conforming BER receiver must accept every sender's
// option (§7.3); DER forbids them all. The codec is parameterized on a
// rules type so asn1::codec<ber> and asn1::codec<der> are distinct,
// fully inlined instantiations sharing one X.690 engine.
#pragma once

#include <concepts>

namespace asn1 {

template<class R>
concept encoding_rules = requires {
    { R::allow_indefinite_length } -> std::convertible_to<bool>;
    { R::allow_constructed_strings } -> std::convertible_to<bool>;
    { R::require_minimal_length } -> std::convertible_to<bool>;
    { R::require_canonical } -> std::convertible_to<bool>;
};

// Basic Encoding Rules. Decoder accepts every X.690 §8 sender's option.
struct ber {
    static constexpr bool allow_indefinite_length = true;
    static constexpr bool allow_constructed_strings = true;
    static constexpr bool require_minimal_length = false;
    static constexpr bool require_canonical = false;
};

// Distinguished Encoding Rules: definite minimal lengths only, primitive
// strings only, canonical value forms (§10, §11).
struct der {
    static constexpr bool allow_indefinite_length = false;
    static constexpr bool allow_constructed_strings = false;
    static constexpr bool require_minimal_length = true;
    static constexpr bool require_canonical = true;
};

static_assert(encoding_rules<ber> && encoding_rules<der>);

} // namespace asn1
