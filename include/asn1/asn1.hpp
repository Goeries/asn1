// asn1/asn1.hpp — umbrella header.
//
// A modern C++23 ASN.1 codec parameterized on X.690 encoding rules:
//
//   asn1::ber_codec::decode<T>(bytes)  /  asn1::der_codec::encode(value)
//
// Aggregate structs map to SEQUENCE automatically (see reflect.hpp);
// everything else goes through asn1::codec_traits.
#pragma once

#include "codec.hpp"   // IWYU pragma: export
#include "core.hpp"    // IWYU pragma: export
#include "decoder.hpp" // IWYU pragma: export
#include "encoder.hpp" // IWYU pragma: export
#include "format.hpp"  // IWYU pragma: export
#include "reader.hpp"  // IWYU pragma: export
#include "reflect.hpp" // IWYU pragma: export
#include "rules.hpp"   // IWYU pragma: export
#include "traits.hpp"  // IWYU pragma: export
#include "types.hpp"   // IWYU pragma: export
#include "value.hpp"   // IWYU pragma: export
