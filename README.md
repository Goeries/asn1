# asn1 — a modern C++23 ASN.1 codec

[![CI](https://github.com/Goeries/asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/Goeries/asn1/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C.svg)](https://en.cppreference.com/w/cpp/23)

Header-only ASN.1 codec parameterized on X.690 encoding rules. BER (Basic
Encoding Rules) is fully supported for decode; the encoder emits
definite-length, canonical-leaning output that is valid BER and (for types
without sender's options) DER-identical. DER decode/encode strictness ships
today as `asn1::der`; CER is a future rules type away.

```cpp
#include <asn1/asn1.hpp>

struct AlgorithmIdentifier {
    asn1::oid algorithm;
    asn1::any parameters;
};

// No macros, no codegen, no codec_traits specialization:
std::expected<AlgorithmIdentifier, asn1::error> ai =
    asn1::ber_codec::decode<AlgorithmIdentifier>(bytes);

if (!ai) std::println("decode failed: {}", ai.error());
// "tag mismatch at offset 0x2f: expected INTEGER, got [0]"

auto der = asn1::der_codec::encode(*ai);   // expected<vector<byte>, error>
```

## Design

| Layer | Header | What it does |
|---|---|---|
| L0 | `reader.hpp` | Bounds-checked TLV parsing over `span<const byte>`, zero-alloc, indefinite-length resolution, depth limits |
| L1 | `decoder.hpp` / `encoder.hpp` / `traits.hpp` | Typed codec: `codec_traits<T>` written once per type, shared by all rules |
| L2 | `value.hpp` | Generic DOM (`asn1::value`) for schema-less inspection + `asn1::dump()` |
| Facade | `codec.hpp` | `asn1::codec<Rules>` → `ber_codec`, `der_codec` |

- **Encoding rules as policy types** (`asn1::ber`, `asn1::der`): one X.690
  engine, `constexpr` strictness flags, distinct fully-inlined instantiations.
- **`std::expected` everywhere** — malformed input is normal control flow;
  every `asn1::error` carries an `errc` and the absolute byte offset.
- **Zero-copy by default** — primitive strings decode as views into the
  input buffer (`asn1::bytes`); BER constructed-string reassembly allocates
  only when it must. Keep the input buffer alive, or `.to_owned()`.
- **Closure-scoped nesting** — `read_sequence`-style scopes verify full
  consumption on exit; unbalanced or trailing content is a structural error.

## Automatic struct mapping

ASN.1 SEQUENCE is positional, so plain aggregates map automatically — fields
are encoded/decoded in declaration order (a C++23 structured-bindings
technique; see `reflect.hpp`):

```cpp
enum class Version : int { v1, v2, v3 };          // → ENUMERATED

struct Certificate {
    asn1::explicit_<0, Version> version;          // [0] EXPLICIT
    std::uint64_t serial;                         // → INTEGER
    std::optional<asn1::ia5_string> comment;      // → OPTIONAL
    std::vector<asn1::oid> extensions;            // → SEQUENCE OF
    std::variant<asn1::implicit<1, std::int32_t>,
                 asn1::printable_string> extra;   // → CHOICE
};
```

Type mapping: `bool`→BOOLEAN, integers→INTEGER, enums→ENUMERATED,
`double/float`→REAL, `asn1::null_t`→NULL, `std::string`→UTF8String
(validated), `asn1::printable_string`/`ia5_string`/…→the restricted string
types (charset-validated), `asn1::bytes`/`vector<byte>`→OCTET STRING,
`asn1::bit_string`, `asn1::oid`/`relative_oid`, `asn1::utc_time`/
`generalized_time`, `std::optional`→OPTIONAL, `std::variant`→CHOICE (with
compile-time distinct-tag checking), `std::vector<T>`→SEQUENCE OF,
`asn1::set_of<T>`→SET OF (DER §11.6 ordering enforced both directions),
`asn1::implicit<N,T>`/`asn1::explicit_<N,T>`→tagging, `asn1::any`→open type
(verbatim TLV capture, byte-exact re-emit under BER; `der_codec` validates
the captured structure — definite minimal lengths, recursively — before
re-emitting, though value-level canonicality of ANY contents is the
producer's responsibility).

Schema mistakes that X.680 forbids are compile errors here: CHOICE
alternatives must all carry statically known, pairwise-distinct tags
(§29.2 — `asn1::any` or a nested `variant` as an alternative is rejected;
wrap in `explicit_`), an OPTIONAL member followed by a same-tag member is
rejected (§25.7), and `std::optional` cannot be a SEQUENCE OF / SET OF
element.

Aggregate limits (use a `codec_traits` specialization to go beyond): no base
classes, no bit-fields, no raw C-array members, ≤ 64 members. When C++26
reflection (P2996) is production-ready, the reflect.hpp internals can be
swapped without any public API change.

## Compliance notes (X.690 02/2021)

- BER decoder accepts every §7.3 sender's option: indefinite lengths,
  non-minimal long-form lengths (up to the §8.1.3.5 maximum of 126 length
  octets), constructed strings (recursively, per §8.6.4/§8.7.3 with OCTET
  STRING segments per the §8.21 example), any nonzero BOOLEAN, REAL in
  binary base 2/8/16 with scale factors and arbitrary-width mantissas
  (correctly rounded to double via a 64-bit + sticky-bit reduction),
  decimal ISO 6093 NR1-3 and 2021-edition specials (NaN, −0), UTCTime/
  GeneralizedTime offsets, fractions and local time.
- INTEGER minimality (§8.3.2) and OID subidentifier minimality (§8.19.2)
  are enforced even under BER — the spec mandates both.
- `asn1::der` decode additionally rejects: indefinite/non-minimal lengths,
  constructed strings, non-FF TRUE, nonzero BIT STRING padding, non-base-2
  / non-odd-mantissa / binary-zero REAL (§11.3.1), NR1/NR2 decimals,
  unsorted SET OF, non-canonical times (§11.x).
- Hardened against the classic decoder CVEs: 64-bit length overflow checks,
  reserved 0xFF length octet, depth limits on definite, indefinite and
  string-segment nesting (default 64, configurable via `decode_options`),
  OID/tag-number arc overflow checks, EOC matching.
- DEFAULT component elision and BIT STRING named-bit trimming are schema
  knowledge the codec does not have; both are out of scope for now.

## Using the library

Header-only; every integration style reduces to getting `include/` onto the
include path and compiling with C++23 (GCC ≥ 14.2, Clang ≥ 19, or
MSVC 19.40+; Clang 18 with libstdc++ lacks `std::expected` because it
reports `__cpp_concepts` as 201907).

**Include path / vendoring** — copy the `include/asn1/` directory into your
tree (or point `-I` at this repo's `include/`) and `#include
<asn1/asn1.hpp>`. Nothing to build, no dependencies.

**Git submodule**

```sh
git submodule add https://github.com/Goeries/asn1.git external/asn1
```

```cmake
add_subdirectory(external/asn1)
target_link_libraries(app PRIVATE asn1::asn1)
```

Tests and fuzzers are gated behind `PROJECT_IS_TOP_LEVEL`, so a parent
project pulls in only the `asn1::asn1` INTERFACE target — no doctest
download, no extra build targets.

**CMake FetchContent**

```cmake
include(FetchContent)
FetchContent_Declare(asn1
  GIT_REPOSITORY https://github.com/Goeries/asn1.git
  GIT_TAG v0.1.0-alpha)
FetchContent_MakeAvailable(asn1)
target_link_libraries(app PRIVATE asn1::asn1)
```

`install()` rules and `find_package()` config files are not provided yet.

## Building & testing

To work on the library itself:

```sh
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=g++-14
cmake --build build && ctest --test-dir build
```

The suite (doctest, fetched via CMake) covers all X.690 normative examples,
RFC/vendor known-answer vectors, error-path corner cases and deterministic
round-trip property tests. A libFuzzer harness lives in `fuzz/`
(`-DASN1_BUILD_FUZZERS=ON` with clang).

## License

[MIT](LICENSE)
